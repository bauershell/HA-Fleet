//! In-memory stand-ins for the Phase 1 Postgres registry (`04 §1`) and the
//! Redis tunnel routing table (`02 §1.2`). Phase 0 keeps everything in one
//! process so the walking skeleton needs no external services.
//!
//! The shapes mirror `04-data-model.md` so swapping in `sqlx` later is a
//! data-access change, not a model change.

use hafm_proto::{Capability, InstallType};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Mirror of `instances` + `capabilities` (`04 §1`).
#[derive(Debug, Clone)]
pub struct Instance {
    pub instance_id: Uuid,
    pub display_name: String,
    pub install_type: InstallType,
    pub ha_version: Option<String>,
    pub agent_version: Option<String>,
    pub enroll_state: EnrollState,
    pub agent_cert_fp: Option<String>,
    pub capabilities: Vec<Capability>,
    pub last_heartbeat_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollState {
    Pending,
    Active,
    Revoked,
}

impl Instance {
    /// Derived online/offline (`04 §1` status: heartbeat within 90s). A revoked
    /// instance is never online — its tunnel is refused (`05 §5.1`).
    pub fn is_online(&self) -> bool {
        if self.enroll_state == EnrollState::Revoked {
            return false;
        }
        match self.last_heartbeat_ms {
            Some(hb) => now_ms().saturating_sub(hb) < hafm_proto::HEARTBEAT_DEAD_AFTER_SECS * 1000,
            None => false,
        }
    }
}

/// A single-use claim code the operator hands to an agent (`05 §2`). Carries a
/// TTL and a revocation flag (SECURITY-TODO #9): a code is valid only if unspent,
/// unrevoked, and not past `expires_at_ms`.
#[derive(Debug, Clone)]
pub struct ClaimCode {
    /// Kept for parity with the `claim_codes` row (migrations/0001); the map key
    /// is the code itself, so this field is not read back directly.
    #[allow(dead_code)]
    pub code: String,
    pub spent: bool,
    pub revoked: bool,
    /// Unix ms after which the code is rejected (`05 §2` short-TTL).
    pub expires_at_ms: u64,
    pub display_name: String,
}

/// Default claim-code TTL (`05 §2`): short — a code is a one-shot bootstrap
/// secret, not a standing credential.
pub const CLAIM_CODE_TTL_MS: u64 = 3_600_000; // 1h, mirrors migrations/0001

/// A live tunnel's send handle — the relay pushes outbound frames here; the
/// per-connection task owns the socket. Keyed by `instance_id` in the table.
pub type TunnelTx = mpsc::Sender<String>;

#[derive(Default)]
pub struct Registry {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    instances: HashMap<Uuid, Instance>,
    claims: HashMap<String, ClaimCode>,
    /// Routing table stand-in (`02 §1.2`): instance_id → live tunnel sender.
    tunnels: HashMap<Uuid, TunnelTx>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a dev claim code with the default TTL so the walk needs no operator UI.
    pub fn seed_claim(&self, code: &str, display_name: &str) {
        self.seed_claim_with_ttl(code, display_name, CLAIM_CODE_TTL_MS)
    }

    /// Seed a claim code with an explicit TTL (ms from now). Used by tests to
    /// exercise expiry.
    pub fn seed_claim_with_ttl(&self, code: &str, display_name: &str, ttl_ms: u64) {
        let mut g = self.inner.lock().unwrap();
        g.claims.insert(
            code.to_string(),
            ClaimCode {
                code: code.to_string(),
                spent: false,
                revoked: false,
                expires_at_ms: now_ms().saturating_add(ttl_ms),
                display_name: display_name.to_string(),
            },
        );
    }

    /// Operator action: revoke an unspent claim code (`05 §2`), e.g. if it leaked.
    pub fn revoke_claim(&self, code: &str) -> bool {
        match self.inner.lock().unwrap().claims.get_mut(code) {
            Some(c) => {
                c.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Validate + spend a claim code; returns the display name to seed the
    /// instance. Rejects unknown, already-spent, revoked, and expired codes.
    pub fn consume_claim(&self, code: &str) -> Result<String, ClaimError> {
        let mut g = self.inner.lock().unwrap();
        match g.claims.get_mut(code) {
            None => Err(ClaimError::Unknown),
            Some(c) if c.spent => Err(ClaimError::Spent),
            Some(c) if c.revoked => Err(ClaimError::Revoked),
            Some(c) if now_ms() >= c.expires_at_ms => Err(ClaimError::Expired),
            Some(c) => {
                c.spent = true;
                Ok(c.display_name.clone())
            }
        }
    }

    /// Register a freshly enrolled instance (`04 §1`, enroll_state=active).
    pub fn create_instance(
        &self,
        display_name: String,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
        cert_fp: String,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let mut g = self.inner.lock().unwrap();
        g.instances.insert(
            id,
            Instance {
                instance_id: id,
                display_name,
                install_type,
                ha_version,
                agent_version: Some(agent_version),
                enroll_state: EnrollState::Active,
                agent_cert_fp: Some(cert_fp),
                capabilities,
                last_heartbeat_ms: None,
            },
        );
        id
    }

    pub fn get(&self, id: Uuid) -> Option<Instance> {
        self.inner.lock().unwrap().instances.get(&id).cloned()
    }

    pub fn list(&self) -> Vec<Instance> {
        self.inner.lock().unwrap().instances.values().cloned().collect()
    }

    /// Record a HELLO on reconnect: refresh capabilities/version + heartbeat.
    pub fn on_hello(
        &self,
        id: Uuid,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
    ) -> bool {
        let mut g = self.inner.lock().unwrap();
        if let Some(i) = g.instances.get_mut(&id) {
            i.install_type = install_type;
            i.ha_version = ha_version;
            i.agent_version = Some(agent_version);
            i.capabilities = capabilities;
            i.last_heartbeat_ms = Some(now_ms());
            true
        } else {
            false
        }
    }

    pub fn touch_heartbeat(&self, id: Uuid) {
        if let Some(i) = self.inner.lock().unwrap().instances.get_mut(&id) {
            i.last_heartbeat_ms = Some(now_ms());
        }
    }

    /// Rotate the pinned mTLS cert fingerprint (`05 §5.1`); no claim code needed.
    pub fn rotate_cert_fp(&self, id: Uuid, new_fp: String) -> bool {
        match self.inner.lock().unwrap().instances.get_mut(&id) {
            Some(i) => {
                i.agent_cert_fp = Some(new_fp);
                true
            }
            None => false,
        }
    }

    /// Set enroll_state (used by revoke: `05 §5.1` compromise path).
    pub fn set_enroll_state(&self, id: Uuid, state: EnrollState) -> bool {
        match self.inner.lock().unwrap().instances.get_mut(&id) {
            Some(i) => {
                i.enroll_state = state;
                true
            }
            None => false,
        }
    }

    pub fn bind_tunnel(&self, id: Uuid, tx: TunnelTx) {
        self.inner.lock().unwrap().tunnels.insert(id, tx);
    }

    pub fn unbind_tunnel(&self, id: Uuid) {
        self.inner.lock().unwrap().tunnels.remove(&id);
    }

    pub fn tunnel(&self, id: Uuid) -> Option<TunnelTx> {
        self.inner.lock().unwrap().tunnels.get(&id).cloned()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    Unknown,
    Spent,
    Revoked,
    Expired,
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

// --- RegistryStore impl (in-memory default) ---------------------------------
// Thin async wrappers over the sync methods above; the trait is async so the
// Postgres backend (store::pg) can await the DB. See store::RegistryStore.

#[async_trait::async_trait]
impl crate::store::RegistryStore for Registry {
    async fn seed_claim(&self, code: &str, display_name: &str) {
        Registry::seed_claim(self, code, display_name)
    }
    async fn seed_claim_with_ttl(&self, code: &str, display_name: &str, ttl_ms: u64) {
        Registry::seed_claim_with_ttl(self, code, display_name, ttl_ms)
    }
    async fn revoke_claim(&self, code: &str) -> bool {
        Registry::revoke_claim(self, code)
    }
    async fn consume_claim(&self, code: &str) -> Result<String, ClaimError> {
        Registry::consume_claim(self, code)
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
        Registry::create_instance(
            self, display_name, install_type, ha_version, agent_version, capabilities, cert_fp,
        )
    }
    async fn get(&self, id: Uuid) -> Option<Instance> {
        Registry::get(self, id)
    }
    async fn list(&self) -> Vec<Instance> {
        Registry::list(self)
    }
    async fn on_hello(
        &self,
        id: Uuid,
        install_type: InstallType,
        ha_version: Option<String>,
        agent_version: String,
        capabilities: Vec<Capability>,
    ) -> bool {
        Registry::on_hello(self, id, install_type, ha_version, agent_version, capabilities)
    }
    async fn touch_heartbeat(&self, id: Uuid) {
        Registry::touch_heartbeat(self, id)
    }
    async fn rotate_cert_fp(&self, id: Uuid, new_fp: String) -> bool {
        Registry::rotate_cert_fp(self, id, new_fp)
    }
    async fn set_enroll_state(&self, id: Uuid, state: EnrollState) -> bool {
        Registry::set_enroll_state(self, id, state)
    }
    fn bind_tunnel(&self, id: Uuid, tx: TunnelTx) {
        Registry::bind_tunnel(self, id, tx)
    }
    fn unbind_tunnel(&self, id: Uuid) {
        Registry::unbind_tunnel(self, id)
    }
    fn tunnel(&self, id: Uuid) -> Option<TunnelTx> {
        Registry::tunnel(self, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_code_is_single_use() {
        let r = Registry::new();
        r.seed_claim("DEV-1", "Home");
        assert_eq!(r.consume_claim("DEV-1"), Ok("Home".to_string()));
        assert_eq!(r.consume_claim("DEV-1"), Err(ClaimError::Spent));
        assert_eq!(r.consume_claim("NOPE"), Err(ClaimError::Unknown));
    }

    #[test]
    fn claim_code_expiry_rejected() {
        let r = Registry::new();
        r.seed_claim_with_ttl("OLD", "Home", 0); // already expired
        assert_eq!(r.consume_claim("OLD"), Err(ClaimError::Expired));
    }

    #[test]
    fn claim_code_revocation_rejected() {
        let r = Registry::new();
        r.seed_claim("LEAKED", "Home");
        assert!(r.revoke_claim("LEAKED"));
        assert_eq!(r.consume_claim("LEAKED"), Err(ClaimError::Revoked));
        assert!(!r.revoke_claim("MISSING"));
    }

    #[test]
    fn instance_offline_without_heartbeat() {
        let r = Registry::new();
        let id = r.create_instance(
            "Home".into(),
            InstallType::Container,
            Some("2026.9.0".into()),
            "0.0.0".into(),
            vec![Capability::CoreStates],
            "fp".into(),
        );
        let inst = r.get(id).unwrap();
        assert!(!inst.is_online());
        assert_eq!(inst.enroll_state, EnrollState::Active);
    }
}
