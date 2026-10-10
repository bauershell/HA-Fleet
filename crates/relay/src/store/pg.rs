//! sqlx/Postgres implementations of the storage traits (`04-data-model.md`).
//!
//! Compiled only with `--features postgres`. Uses the **runtime** sqlx query API
//! (`sqlx::query`/`query_as` with bind params) rather than the compile-time
//! `query!` macros, so the crate builds without a live database or a checked-in
//! `.sqlx` cache — the DB is needed only to *run*, not to *compile*.
//!
//! Each store maps 1:1 to the migration tables:
//!   * [`PgRegistry`]  → `instances` + `capabilities` + `claim_codes` (0001)
//!   * [`PgQueue`]     → `command_queue` (0002)
//!   * [`PgAudit`]     → `audit_log` (0002)
//!   * [`PgTemplater`] → `templates` + `template_versions` + `push_jobs` (0004)
//!   * [`PgCollector`] → `log_events` (0004)
//!   * [`PgProxy`]     → `cp_instance_grants` + `proxy_tokens` (0005)
//!
//! The live tunnel routing table has no SQL representation (a socket is not a
//! row); [`PgRegistry`] keeps it in a process-local map, matching the in-memory
//! backend. Multi-relay routing is Redis pub/sub (`02 §1.2`), a scale-out item.

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

use crate::audit::AuditRecord;
use crate::collector::LogEvent;
use crate::proxy::{ProxyAuthError, ProxyToken, PROXY_TOKEN_TTL_MS};
use crate::queue::{CmdState, QueuedCommand};
use crate::registry::{now_ms, ClaimError, EnrollState, Instance, TunnelTx};
use crate::store::{
    AuditStore, CollectorStore, ProxyStore, QueueStore, RegistryStore, Stores, TemplateStore,
};
use crate::templates::{JobState, PushJob, Template, TemplateKind, TemplateVersion};
use hafm_proto::{Capability, InstallType};

/// Connect the pool and run migrations 0001–0005, then build the store bundle.
pub async fn build(database_url: &str) -> anyhow::Result<Stores> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    tracing::info!("postgres store: connected + migrations applied");

    let registry = std::sync::Arc::new(PgRegistry::new(pool.clone()));
    Ok(Stores {
        registry,
        queue: std::sync::Arc::new(PgQueue { pool: pool.clone() }),
        audit: std::sync::Arc::new(PgAudit { pool: pool.clone() }),
        templater: std::sync::Arc::new(PgTemplater { pool: pool.clone() }),
        collector: std::sync::Arc::new(PgCollector { pool: pool.clone() }),
        proxy_authz: std::sync::Arc::new(PgProxy { pool }),
    })
}

// --- shared enum <-> text mappers (match the CHECK constraints in migrations) -

fn install_type_str(t: InstallType) -> &'static str {
    match t {
        InstallType::Core => "core",
        InstallType::Container => "container",
        InstallType::Supervised => "supervised",
        InstallType::Haos => "haos",
    }
}
fn install_type_from(s: &str) -> InstallType {
    match s {
        "core" => InstallType::Core,
        "supervised" => InstallType::Supervised,
        "haos" => InstallType::Haos,
        _ => InstallType::Container,
    }
}
fn enroll_state_str(s: EnrollState) -> &'static str {
    match s {
        EnrollState::Pending => "pending",
        EnrollState::Active => "active",
        EnrollState::Revoked => "revoked",
    }
}
fn enroll_state_from(s: &str) -> EnrollState {
    match s {
        "pending" => EnrollState::Pending,
        "revoked" => EnrollState::Revoked,
        _ => EnrollState::Active,
    }
}

// ===========================================================================
// Registry → instances + capabilities + claim_codes
// ===========================================================================

pub struct PgRegistry {
    pool: PgPool,
    /// Process-local routing table (sockets aren't rows). See module docs.
    tunnels: Mutex<HashMap<Uuid, TunnelTx>>,
}

impl PgRegistry {
    fn new(pool: PgPool) -> Self {
        Self { pool, tunnels: Mutex::new(HashMap::new()) }
    }

    async fn load_caps(&self, id: Uuid) -> Vec<Capability> {
        let rows = sqlx::query("SELECT capability FROM capabilities WHERE instance_id = $1")
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| {
                let s: String = r.get("capability");
                // Capability deserializes from the dotted wire string.
                serde_json::from_value(serde_json::Value::String(s)).ok()
            })
            .collect()
    }

    fn row_to_instance(row: &sqlx::postgres::PgRow, caps: Vec<Capability>) -> Instance {
        let hb: Option<sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>> = row.get("last_heartbeat");
        Instance {
            instance_id: row.get("instance_id"),
            display_name: row.get("display_name"),
            install_type: install_type_from(row.get::<String, _>("install_type").as_str()),
            ha_version: row.get("ha_version"),
            agent_version: row.get("agent_version"),
            enroll_state: enroll_state_from(row.get::<String, _>("enroll_state").as_str()),
            agent_cert_fp: row.get("agent_cert_fp"),
            capabilities: caps,
            last_heartbeat_ms: hb.map(|t| t.timestamp_millis() as u64),
        }
    }
}

#[async_trait]
impl RegistryStore for PgRegistry {
    async fn seed_claim(&self, code: &str, display_name: &str) {
        self.seed_claim_with_ttl(code, display_name, crate::registry::CLAIM_CODE_TTL_MS)
            .await
    }

    async fn seed_claim_with_ttl(&self, code: &str, display_name: &str, ttl_ms: u64) {
        // Idempotent seed (ON CONFLICT) so repeated dev starts are harmless.
        let _ = sqlx::query(
            "INSERT INTO claim_codes (code, display_name, expires_at)
             VALUES ($1, $2, now() + make_interval(secs => $3))
             ON CONFLICT (code) DO NOTHING",
        )
        .bind(code)
        .bind(display_name)
        .bind((ttl_ms as f64) / 1000.0)
        .execute(&self.pool)
        .await;
    }

    async fn revoke_claim(&self, code: &str) -> bool {
        let res = sqlx::query("UPDATE claim_codes SET revoked = true WHERE code = $1")
            .bind(code)
            .execute(&self.pool)
            .await;
        matches!(res, Ok(r) if r.rows_affected() > 0)
    }

    async fn consume_claim(&self, code: &str) -> Result<String, ClaimError> {
        // Atomic spend: flip spent=true only if currently valid (unspent,
        // unrevoked, unexpired), returning the display name (#9).
        let row = sqlx::query(
            "UPDATE claim_codes SET spent = true, spent_at = now()
             WHERE code = $1 AND spent = false AND revoked = false AND expires_at > now()
             RETURNING display_name",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClaimError::Unknown)?;
        match row {
            Some(r) => Ok(r.get("display_name")),
            None => {
                // Disambiguate the rejection reason.
                let st = sqlx::query(
                    "SELECT spent, revoked, (expires_at <= now()) AS expired
                     FROM claim_codes WHERE code = $1",
                )
                .bind(code)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
                Err(match st {
                    None => ClaimError::Unknown,
                    Some(r) if r.get::<bool, _>("revoked") => ClaimError::Revoked,
                    Some(r) if r.get::<bool, _>("spent") => ClaimError::Spent,
                    Some(r) if r.get::<bool, _>("expired") => ClaimError::Expired,
                    Some(_) => ClaimError::Unknown,
                })
            }
        }
    }

    async fn create_instance(
        &self,
        display_name: String,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
        cert_fp: String,
    ) -> Uuid {
        let row = sqlx::query(
            "INSERT INTO instances
               (display_name, install_type, ha_version, agent_version,
                enroll_state, agent_cert_fp)
             VALUES ($1, $2, $3, $4, 'active', $5)
             RETURNING instance_id",
        )
        .bind(&display_name)
        .bind(install_type_str(install_type))
        .bind(&ha_version)
        .bind(&agent_version)
        .bind(&cert_fp)
        .fetch_one(&self.pool)
        .await
        .expect("insert instance");
        let id: Uuid = row.get("instance_id");

        for cap in &capabilities {
            let _ = sqlx::query(
                "INSERT INTO capabilities (instance_id, capability) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(cap.as_str())
            .execute(&self.pool)
            .await;
        }
        id
    }

    async fn get(&self, id: Uuid) -> Option<Instance> {
        let row = sqlx::query("SELECT * FROM instances WHERE instance_id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .ok()??;
        let caps = self.load_caps(id).await;
        Some(Self::row_to_instance(&row, caps))
    }

    async fn list(&self) -> Vec<Instance> {
        let rows = sqlx::query("SELECT * FROM instances ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: Uuid = row.get("instance_id");
            let caps = self.load_caps(id).await;
            out.push(Self::row_to_instance(row, caps));
        }
        out
    }

    async fn on_hello(
        &self,
        id: Uuid,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
    ) -> bool {
        let res = sqlx::query(
            "UPDATE instances
             SET install_type = $2, ha_version = $3, agent_version = $4,
                 last_heartbeat = now()
             WHERE instance_id = $1",
        )
        .bind(id)
        .bind(install_type_str(install_type))
        .bind(&ha_version)
        .bind(&agent_version)
        .execute(&self.pool)
        .await;
        let updated = matches!(res, Ok(r) if r.rows_affected() > 0);
        if !updated {
            return false;
        }
        // Refresh advertised capabilities (replace set).
        let _ = sqlx::query("DELETE FROM capabilities WHERE instance_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await;
        for cap in &capabilities {
            let _ = sqlx::query(
                "INSERT INTO capabilities (instance_id, capability) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(cap.as_str())
            .execute(&self.pool)
            .await;
        }
        true
    }

    async fn touch_heartbeat(&self, id: Uuid) {
        let _ = sqlx::query("UPDATE instances SET last_heartbeat = now() WHERE instance_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await;
    }

    async fn rotate_cert_fp(&self, id: Uuid, new_fp: String) -> bool {
        let res =
            sqlx::query("UPDATE instances SET agent_cert_fp = $2 WHERE instance_id = $1")
                .bind(id)
                .bind(&new_fp)
                .execute(&self.pool)
                .await;
        matches!(res, Ok(r) if r.rows_affected() > 0)
    }

    async fn set_enroll_state(&self, id: Uuid, state: EnrollState) -> bool {
        let res =
            sqlx::query("UPDATE instances SET enroll_state = $2 WHERE instance_id = $1")
                .bind(id)
                .bind(enroll_state_str(state))
                .execute(&self.pool)
                .await;
        matches!(res, Ok(r) if r.rows_affected() > 0)
    }

    fn bind_tunnel(&self, id: Uuid, tx: TunnelTx) {
        self.tunnels.lock().unwrap().insert(id, tx);
    }
    fn unbind_tunnel(&self, id: Uuid) {
        self.tunnels.lock().unwrap().remove(&id);
    }
    fn tunnel(&self, id: Uuid) -> Option<TunnelTx> {
        self.tunnels.lock().unwrap().get(&id).cloned()
    }
}

// ===========================================================================
// Queue → command_queue
// ===========================================================================

pub struct PgQueue {
    pool: PgPool,
}

#[async_trait]
impl QueueStore for PgQueue {
    async fn enqueue(
        &self,
        instance_id: Uuid,
        op: &str,
        args: serde_json::Value,
        idempotency_key: String,
    ) -> Option<Uuid> {
        // ON CONFLICT on the UNIQUE idempotency_key → no-op (safe replay).
        let row = sqlx::query(
            "INSERT INTO command_queue (instance_id, op, args, idempotency_key, state)
             VALUES ($1, $2, $3, $4, 'queued')
             ON CONFLICT (idempotency_key) DO NOTHING
             RETURNING cmd_id",
        )
        .bind(instance_id)
        .bind(op)
        .bind(&args)
        .bind(&idempotency_key)
        .fetch_optional(&self.pool)
        .await
        .ok()?;
        row.map(|r| r.get("cmd_id"))
    }

    async fn drain(&self, instance_id: Uuid) -> Vec<QueuedCommand> {
        // Fetch in FIFO order, then delete them (delivered on reconnect).
        let rows = sqlx::query(
            "SELECT cmd_id, instance_id, op, args, idempotency_key, state
             FROM command_queue
             WHERE instance_id = $1 AND state = 'queued'
             ORDER BY created_at",
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let out: Vec<QueuedCommand> = rows
            .iter()
            .map(|r| QueuedCommand {
                cmd_id: r.get("cmd_id"),
                instance_id: r.get("instance_id"),
                op: r.get("op"),
                args: r.get("args"),
                idempotency_key: r.get("idempotency_key"),
                state: CmdState::Queued,
            })
            .collect();

        if !out.is_empty() {
            let _ = sqlx::query(
                "UPDATE command_queue SET state = 'sent'
                 WHERE instance_id = $1 AND state = 'queued'",
            )
            .bind(instance_id)
            .execute(&self.pool)
            .await;
        }
        out
    }

    async fn depth(&self, instance_id: Uuid) -> usize {
        let row = sqlx::query(
            "SELECT count(*) AS n FROM command_queue
             WHERE instance_id = $1 AND state = 'queued'",
        )
        .bind(instance_id)
        .fetch_one(&self.pool)
        .await;
        row.map(|r| r.get::<i64, _>("n") as usize).unwrap_or(0)
    }
}

// ===========================================================================
// Audit → audit_log
// ===========================================================================

pub struct PgAudit {
    pool: PgPool,
}

#[async_trait]
impl AuditStore for PgAudit {
    async fn record(
        &self,
        actor: Option<String>,
        instance_id: Option<Uuid>,
        action: &str,
        target: serde_json::Value,
        result: &str,
        detail: serde_json::Value,
    ) -> u64 {
        let row = sqlx::query(
            "INSERT INTO audit_log (actor, instance_id, action, target, result, detail)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING audit_id",
        )
        .bind(&actor)
        .bind(instance_id)
        .bind(action)
        .bind(&target)
        .bind(result)
        .bind(&detail)
        .fetch_one(&self.pool)
        .await;
        row.map(|r| r.get::<i64, _>("audit_id") as u64).unwrap_or(0)
    }

    async fn query(&self, instance_id: Option<Uuid>, limit: usize) -> Vec<AuditRecord> {
        let rows = sqlx::query(
            "SELECT audit_id, (extract(epoch from ts)*1000)::float8 AS ts_ms, actor,
                    instance_id, action, target, result, detail
             FROM audit_log
             WHERE ($1::uuid IS NULL OR instance_id = $1)
             ORDER BY audit_id DESC
             LIMIT $2",
        )
        .bind(instance_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|r| AuditRecord {
                audit_id: r.get::<i64, _>("audit_id") as u64,
                ts_ms: r.get::<f64, _>("ts_ms") as u64,
                actor: r.get("actor"),
                instance_id: r.get("instance_id"),
                action: r.get("action"),
                target: r.get("target"),
                result: r.get("result"),
                detail: r.get("detail"),
            })
            .collect()
    }
}

// ===========================================================================
// Templater → templates + template_versions + push_jobs
// ===========================================================================

pub struct PgTemplater {
    pool: PgPool,
}

fn kind_str(k: TemplateKind) -> &'static str {
    match k {
        TemplateKind::Automation => "automation",
        TemplateKind::Dashboard => "dashboard",
    }
}
fn kind_from(s: &str) -> TemplateKind {
    match s {
        "dashboard" => TemplateKind::Dashboard,
        _ => TemplateKind::Automation,
    }
}
fn job_state_str(s: JobState) -> &'static str {
    match s {
        JobState::Queued => "queued",
        JobState::Sent => "sent",
        JobState::Reconciled => "reconciled",
        JobState::Drift => "drift",
        JobState::Failed => "failed",
    }
}
fn job_state_from(s: &str) -> JobState {
    match s {
        "sent" => JobState::Sent,
        "reconciled" => JobState::Reconciled,
        "drift" => JobState::Drift,
        "failed" => JobState::Failed,
        _ => JobState::Queued,
    }
}

#[async_trait]
impl TemplateStore for PgTemplater {
    async fn create(&self, kind: TemplateKind, name: &str, body: serde_json::Value) -> Uuid {
        let row = sqlx::query(
            "INSERT INTO templates (kind, name) VALUES ($1, $2) RETURNING template_id",
        )
        .bind(kind_str(kind))
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .expect("insert template");
        let id: Uuid = row.get("template_id");
        let _ = sqlx::query(
            "INSERT INTO template_versions (template_id, version, body)
             VALUES ($1, 1, $2)",
        )
        .bind(id)
        .bind(&body)
        .execute(&self.pool)
        .await;
        id
    }

    async fn add_version(&self, template_id: Uuid, body: serde_json::Value) -> Option<i32> {
        // next = max(version)+1 for this template.
        let next_row = sqlx::query(
            "SELECT coalesce(max(version), 0) + 1 AS next
             FROM template_versions WHERE template_id = $1",
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??;
        // Confirm the template exists (add_version returns None for unknown id).
        let exists = sqlx::query("SELECT 1 AS one FROM templates WHERE template_id = $1")
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
            .is_some();
        if !exists {
            return None;
        }
        let next: i32 = next_row.get("next");
        sqlx::query(
            "INSERT INTO template_versions (template_id, version, body) VALUES ($1, $2, $3)",
        )
        .bind(template_id)
        .bind(next)
        .bind(&body)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(next)
    }

    async fn get(&self, template_id: Uuid) -> Option<Template> {
        let t = sqlx::query("SELECT template_id, kind, name FROM templates WHERE template_id = $1")
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .ok()??;
        let vers = sqlx::query(
            "SELECT version, body FROM template_versions
             WHERE template_id = $1 ORDER BY version",
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        Some(Template {
            template_id,
            kind: kind_from(t.get::<String, _>("kind").as_str()),
            name: t.get("name"),
            versions: vers
                .into_iter()
                .map(|r| TemplateVersion { version: r.get("version"), body: r.get("body") })
                .collect(),
        })
    }

    async fn list(&self) -> Vec<Template> {
        let ids = sqlx::query("SELECT template_id FROM templates ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        let mut out = Vec::new();
        for r in &ids {
            let id: Uuid = r.get("template_id");
            if let Some(t) = self.get(id).await {
                out.push(t);
            }
        }
        out
    }

    async fn latest(
        &self,
        template_id: Uuid,
    ) -> Option<(i32, serde_json::Value, TemplateKind, &'static str)> {
        let t = sqlx::query("SELECT kind FROM templates WHERE template_id = $1")
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .ok()??;
        let kind = kind_from(t.get::<String, _>("kind").as_str());
        let v = sqlx::query(
            "SELECT version, body FROM template_versions
             WHERE template_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await
        .ok()??;
        Some((v.get("version"), v.get("body"), kind, kind.save_op()))
    }

    async fn record_job(
        &self,
        template_id: Uuid,
        version: i32,
        instance_id: Uuid,
        state: JobState,
        detail: serde_json::Value,
    ) -> Uuid {
        let idem = crate::templates::Templater::idem_key(template_id, version, instance_id);
        // Upsert on the deterministic idempotency key: a re-push of the same
        // (version, instance) updates the job row rather than duplicating it.
        let row = sqlx::query(
            "INSERT INTO push_jobs
               (template_id, version, instance_id, idempotency_key, state, detail)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (idempotency_key) DO UPDATE
               SET state = EXCLUDED.state, detail = EXCLUDED.detail, updated_at = now()
             RETURNING job_id",
        )
        .bind(template_id)
        .bind(version)
        .bind(instance_id)
        .bind(&idem)
        .bind(job_state_str(state))
        .bind(&detail)
        .fetch_one(&self.pool)
        .await
        .expect("upsert push job");
        row.get("job_id")
    }

    async fn jobs_for(&self, template_id: Uuid) -> Vec<PushJob> {
        let rows = sqlx::query(
            "SELECT job_id, template_id, version, instance_id, idempotency_key, state, detail
             FROM push_jobs WHERE template_id = $1 ORDER BY updated_at",
        )
        .bind(template_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|r| PushJob {
                job_id: r.get("job_id"),
                template_id: r.get("template_id"),
                version: r.get("version"),
                instance_id: r.get("instance_id"),
                idempotency_key: r.get("idempotency_key"),
                state: job_state_from(r.get::<String, _>("state").as_str()),
                detail: r.get::<Option<serde_json::Value>, _>("detail").unwrap_or(serde_json::json!({})),
            })
            .collect()
    }
}

// ===========================================================================
// Collector → log_events
// ===========================================================================

pub struct PgCollector {
    pool: PgPool,
}

/// Parse an HA error-log line (mirrors collector::parse_line).
fn parse_line(line: &str) -> (String, String, String) {
    let level = ["ERROR", "WARNING", "CRITICAL", "INFO", "DEBUG"]
        .iter()
        .find(|lvl| line.contains(**lvl))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());
    let source = line
        .split('[')
        .nth(1)
        .and_then(|s| s.split(']').next())
        .unwrap_or("")
        .to_string();
    (level, source, line.to_string())
}

#[async_trait]
impl CollectorStore for PgCollector {
    async fn ingest_lines(&self, instance_id: Uuid, lines: &[String]) -> usize {
        let mut n = 0;
        for line in lines {
            let (level, source, message) = parse_line(line);
            let res = sqlx::query(
                "INSERT INTO log_events (instance_id, ts, level, source, message)
                 VALUES ($1, now(), $2, $3, $4)",
            )
            .bind(instance_id)
            .bind(&level)
            .bind(&source)
            .bind(&message)
            .execute(&self.pool)
            .await;
            if res.is_ok() {
                n += 1;
            }
        }
        n
    }

    async fn query(
        &self,
        instance_id: Option<Uuid>,
        contains: Option<&str>,
        limit: usize,
    ) -> Vec<LogEvent> {
        let rows = sqlx::query(
            "SELECT instance_id, (extract(epoch from ts)*1000)::float8 AS ts_ms, level, source, message
             FROM log_events
             WHERE ($1::uuid IS NULL OR instance_id = $1)
               AND ($2::text IS NULL OR message LIKE '%' || $2 || '%')
             ORDER BY id DESC
             LIMIT $3",
        )
        .bind(instance_id)
        .bind(contains)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|r| LogEvent {
                instance_id: r.get("instance_id"),
                ts_ms: r.get::<f64, _>("ts_ms") as u64,
                level: r.get("level"),
                source: r.get("source"),
                message: r.get("message"),
            })
            .collect()
    }
}

// ===========================================================================
// Proxy authz → cp_instance_grants + proxy_tokens
// ===========================================================================

pub struct PgProxy {
    pool: PgPool,
}

#[async_trait]
impl ProxyStore for PgProxy {
    async fn grant(&self, principal: &str, instance_id: Uuid, scope: serde_json::Value) {
        let _ = sqlx::query(
            "INSERT INTO cp_instance_grants (subject_type, subject_id, instance_id, scope)
             VALUES ('user', $1, $2, $3)",
        )
        .bind(principal)
        .bind(instance_id)
        .bind(&scope)
        .execute(&self.pool)
        .await;
    }

    async fn mint(&self, principal: &str, instance_id: Uuid) -> Result<ProxyToken, ProxyAuthError> {
        // Find a grant with scope->>'proxy' = true (default deny otherwise).
        let grant = sqlx::query(
            "SELECT scope FROM cp_instance_grants
             WHERE subject_id = $1 AND instance_id = $2
               AND (scope->>'proxy')::boolean IS TRUE
             LIMIT 1",
        )
        .bind(principal)
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ProxyAuthError::Denied)?;
        let Some(grant) = grant else {
            return Err(ProxyAuthError::Denied);
        };
        let scope: serde_json::Value = grant.get("scope");

        let token = Uuid::new_v4().to_string();
        let expires_at_ms = now_ms() + PROXY_TOKEN_TTL_MS;
        // Store the token hash, never the plaintext (05 §4).
        let token_hash = crate::ca::fingerprint_sha256(token.as_bytes());
        let expires_at = sqlx::types::chrono::DateTime::<sqlx::types::chrono::Utc>::from_timestamp_millis(
            expires_at_ms as i64,
        )
        .unwrap_or_else(sqlx::types::chrono::Utc::now);
        let _ = sqlx::query(
            "INSERT INTO proxy_tokens
               (token_hash, principal, instance_id, scope, expires_at, consumed)
             VALUES ($1, $2, $3, $4, $5, false)",
        )
        .bind(&token_hash)
        .bind(principal)
        .bind(instance_id)
        .bind(&scope)
        .bind(expires_at)
        .execute(&self.pool)
        .await;

        Ok(ProxyToken {
            token,
            principal: principal.to_string(),
            instance_id,
            scope,
            expires_at_ms,
            consumed: false,
        })
    }

    async fn consume(
        &self,
        token: &str,
        instance_id: Uuid,
    ) -> Result<ProxyToken, ProxyAuthError> {
        let token_hash = crate::ca::fingerprint_sha256(token.as_bytes());
        let row = sqlx::query(
            "SELECT principal, instance_id, scope,
                    (extract(epoch from expires_at)*1000)::float8 AS expires_ms, consumed
             FROM proxy_tokens WHERE token_hash = $1",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ProxyAuthError::TokenUnknown)?
        .ok_or(ProxyAuthError::TokenUnknown)?;

        let consumed: bool = row.get("consumed");
        if consumed {
            return Err(ProxyAuthError::TokenConsumed);
        }
        let expires_ms = row.get::<f64, _>("expires_ms") as u64;
        if now_ms() > expires_ms {
            return Err(ProxyAuthError::TokenExpired);
        }
        let tok_instance: Uuid = row.get("instance_id");
        if tok_instance != instance_id {
            return Err(ProxyAuthError::TokenInstanceMismatch);
        }
        // Single-consume: flip only if still unconsumed (guards a race).
        let upd = sqlx::query(
            "UPDATE proxy_tokens SET consumed = true
             WHERE token_hash = $1 AND consumed = false",
        )
        .bind(&token_hash)
        .execute(&self.pool)
        .await
        .map_err(|_| ProxyAuthError::TokenConsumed)?;
        if upd.rows_affected() == 0 {
            return Err(ProxyAuthError::TokenConsumed);
        }
        Ok(ProxyToken {
            token: token.to_string(),
            principal: row.get("principal"),
            instance_id,
            scope: row.get("scope"),
            expires_at_ms: expires_ms,
            consumed: true,
        })
    }
}
