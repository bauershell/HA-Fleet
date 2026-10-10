//! Storage abstraction (`04-data-model.md`).
//!
//! Each control-plane store is an **async trait** with two implementations:
//!   * the in-memory structs in `crates/relay/src/{registry,queue,audit,…}.rs`
//!     — the default, so the walking skeleton runs with zero external deps;
//!   * sqlx/Postgres impls in [`pg`] behind the `postgres` cargo feature —
//!     wired against the migrations (0001–0005) with no model change.
//!
//! `AppState` holds `Arc<dyn …>` trait objects, so swapping the backend is a
//! single construction-time choice ([`build_stores`]) rather than a rewrite.
//! The traits are intentionally the *exact* method surface the operator HTTP
//! layer already calls, so neither handlers nor the tunnel code change.

use async_trait::async_trait;
use hafm_proto::{Capability, InstallType};
use uuid::Uuid;

use crate::audit::AuditRecord;
use crate::collector::LogEvent;
use crate::proxy::{ProxyAuthError, ProxyToken};
use crate::queue::QueuedCommand;
use crate::registry::{ClaimError, EnrollState, Instance, TunnelTx};
use crate::templates::{JobState, PushJob, Template, TemplateKind};

#[cfg(feature = "postgres")]
pub mod pg;

/// Which backend the relay runs against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreBackend {
    Memory,
    #[cfg(feature = "postgres")]
    Postgres,
}

impl std::str::FromStr for StoreBackend {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "memory" | "mem" | "in-memory" => Ok(StoreBackend::Memory),
            #[cfg(feature = "postgres")]
            "postgres" | "pg" | "sql" => Ok(StoreBackend::Postgres),
            #[cfg(not(feature = "postgres"))]
            "postgres" | "pg" | "sql" => Err(
                "store=postgres requires building with --features postgres".into(),
            ),
            other => Err(format!("unknown store backend '{other}'")),
        }
    }
}

// --- Registry (04 §1) + routing table (02 §1.2) -----------------------------

#[async_trait]
pub trait RegistryStore: Send + Sync {
    async fn seed_claim(&self, code: &str, display_name: &str);
    /// Seed a claim code with an explicit TTL in ms (SECURITY-TODO #9).
    async fn seed_claim_with_ttl(&self, code: &str, display_name: &str, ttl_ms: u64);
    /// Revoke an unspent claim code (`05 §2`). Returns false if unknown.
    async fn revoke_claim(&self, code: &str) -> bool;
    async fn consume_claim(&self, code: &str) -> Result<String, ClaimError>;
    #[allow(clippy::too_many_arguments)]
    async fn create_instance(
        &self,
        display_name: String,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
        cert_fp: String,
    ) -> Uuid;
    async fn get(&self, id: Uuid) -> Option<Instance>;
    async fn list(&self) -> Vec<Instance>;
    async fn on_hello(
        &self,
        id: Uuid,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
    ) -> bool;
    async fn touch_heartbeat(&self, id: Uuid);
    async fn rotate_cert_fp(&self, id: Uuid, new_fp: String) -> bool;
    async fn set_enroll_state(&self, id: Uuid, state: EnrollState) -> bool;

    // The live routing table (tunnel senders) is process-local even with a
    // Postgres metadata store — a socket cannot be serialized to a row. Both
    // backends keep it in memory; in a multi-relay deploy this is Redis pub/sub
    // (02 §1.2), tracked as a scale-out item, not part of the SQL swap.
    fn bind_tunnel(&self, id: Uuid, tx: TunnelTx);
    fn unbind_tunnel(&self, id: Uuid);
    fn tunnel(&self, id: Uuid) -> Option<TunnelTx>;
}

// --- Offline write queue (04 §4) --------------------------------------------

#[async_trait]
pub trait QueueStore: Send + Sync {
    async fn enqueue(
        &self,
        instance_id: Uuid,
        op: &str,
        args: serde_json::Value,
        idempotency_key: String,
    ) -> Option<Uuid>;
    async fn drain(&self, instance_id: Uuid) -> Vec<QueuedCommand>;
    async fn depth(&self, instance_id: Uuid) -> usize;
}

// --- Append-only audit log (04 §7) ------------------------------------------

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn record(
        &self,
        actor: Option<String>,
        instance_id: Option<Uuid>,
        action: &str,
        target: serde_json::Value,
        result: &str,
        detail: serde_json::Value,
    ) -> u64;
    async fn query(&self, instance_id: Option<Uuid>, limit: usize) -> Vec<AuditRecord>;
}

// --- Templater + push jobs (04 §3/§4) ---------------------------------------

#[async_trait]
pub trait TemplateStore: Send + Sync {
    async fn create(&self, kind: TemplateKind, name: &str, body: serde_json::Value) -> Uuid;
    async fn add_version(&self, template_id: Uuid, body: serde_json::Value) -> Option<i32>;
    async fn get(&self, template_id: Uuid) -> Option<Template>;
    async fn list(&self) -> Vec<Template>;
    async fn latest(
        &self,
        template_id: Uuid,
    ) -> Option<(i32, serde_json::Value, TemplateKind, &'static str)>;
    async fn record_job(
        &self,
        template_id: Uuid,
        version: i32,
        instance_id: Uuid,
        state: JobState,
        detail: serde_json::Value,
    ) -> Uuid;
    async fn jobs_for(&self, template_id: Uuid) -> Vec<PushJob>;
}

// --- Central log collector (04 §6) ------------------------------------------

#[async_trait]
pub trait CollectorStore: Send + Sync {
    async fn ingest_lines(&self, instance_id: Uuid, lines: &[String]) -> usize;
    async fn query(
        &self,
        instance_id: Option<Uuid>,
        contains: Option<&str>,
        limit: usize,
    ) -> Vec<LogEvent>;
}

// --- Proxy authz: grants + single-consume tokens (04 §2/§8) ------------------

#[async_trait]
pub trait ProxyStore: Send + Sync {
    async fn grant(&self, principal: &str, instance_id: Uuid, scope: serde_json::Value);
    async fn mint(&self, principal: &str, instance_id: Uuid) -> Result<ProxyToken, ProxyAuthError>;
    async fn consume(&self, token: &str, instance_id: Uuid)
        -> Result<ProxyToken, ProxyAuthError>;
}

// --- The bundle AppState holds ----------------------------------------------

use std::sync::Arc;

#[derive(Clone)]
pub struct Stores {
    pub registry: Arc<dyn RegistryStore>,
    pub queue: Arc<dyn QueueStore>,
    pub audit: Arc<dyn AuditStore>,
    pub templater: Arc<dyn TemplateStore>,
    pub collector: Arc<dyn CollectorStore>,
    pub proxy_authz: Arc<dyn ProxyStore>,
}

impl Stores {
    /// All-in-memory bundle (default; zero external deps).
    pub fn in_memory() -> Self {
        use crate::audit::AuditLog;
        use crate::collector::LogCollector;
        use crate::proxy::ProxyAuthz;
        use crate::queue::CommandQueue;
        use crate::registry::Registry;
        use crate::templates::Templater;
        Self {
            registry: Arc::new(Registry::new()),
            queue: Arc::new(CommandQueue::new()),
            audit: Arc::new(AuditLog::new()),
            templater: Arc::new(Templater::new()),
            collector: Arc::new(LogCollector::new()),
            proxy_authz: Arc::new(ProxyAuthz::new()),
        }
    }
}

/// Build the store bundle for the chosen backend. The Postgres backend connects
/// the pool and runs migrations before returning (`sqlx::migrate!`).
pub async fn build_stores(
    backend: StoreBackend,
    #[allow(unused_variables)] database_url: Option<&str>,
) -> anyhow::Result<Stores> {
    match backend {
        StoreBackend::Memory => Ok(Stores::in_memory()),
        #[cfg(feature = "postgres")]
        StoreBackend::Postgres => {
            let url = database_url
                .ok_or_else(|| anyhow::anyhow!("store=postgres requires DATABASE_URL"))?;
            pg::build(url).await
        }
    }
}
