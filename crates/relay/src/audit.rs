//! Append-only audit log (`04 §7`, `NFR-SEC-5`). Every control-plane op writes
//! one record: who/what/when/instance/result. Phase 1 keeps it in memory; the
//! `audit_log` table (migrations/0002) is the Phase 1→Postgres target.

use std::sync::Mutex;
use uuid::Uuid;

use crate::registry::now_ms;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord {
    pub audit_id: u64,
    pub ts_ms: u64,
    /// Operator principal (OIDC sub). `None` for system/agent-originated actions.
    pub actor: Option<String>,
    pub instance_id: Option<Uuid>,
    pub action: String,
    pub target: serde_json::Value,
    /// `ok` | `error`.
    pub result: String,
    pub detail: serde_json::Value,
}

#[derive(Default)]
pub struct AuditLog {
    inner: Mutex<Vec<AuditRecord>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a record (returns the assigned id). Append-only: never updates.
    pub fn record(
        &self,
        actor: Option<String>,
        instance_id: Option<Uuid>,
        action: &str,
        target: serde_json::Value,
        result: &str,
        detail: serde_json::Value,
    ) -> u64 {
        let mut g = self.inner.lock().unwrap();
        let audit_id = g.len() as u64 + 1;
        g.push(AuditRecord {
            audit_id,
            ts_ms: now_ms(),
            actor,
            instance_id,
            action: action.to_string(),
            target,
            result: result.to_string(),
            detail,
        });
        audit_id
    }

    /// Query, newest first, optionally filtered by instance (`NFR-OBS-1`).
    pub fn query(&self, instance_id: Option<Uuid>, limit: usize) -> Vec<AuditRecord> {
        let g = self.inner.lock().unwrap();
        g.iter()
            .rev()
            .filter(|r| instance_id.is_none() || r.instance_id == instance_id)
            .take(limit)
            .cloned()
            .collect()
    }
}

// --- AuditStore impl (in-memory default) ------------------------------------

#[async_trait::async_trait]
impl crate::store::AuditStore for AuditLog {
    async fn record(
        &self,
        actor: Option<String>,
        instance_id: Option<Uuid>,
        action: &str,
        target: serde_json::Value,
        result: &str,
        detail: serde_json::Value,
    ) -> u64 {
        AuditLog::record(self, actor, instance_id, action, target, result, detail)
    }
    async fn query(&self, instance_id: Option<Uuid>, limit: usize) -> Vec<AuditRecord> {
        AuditLog::query(self, instance_id, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_appended_and_queryable_newest_first() {
        let log = AuditLog::new();
        let inst = Uuid::new_v4();
        log.record(Some("op@x".into()), Some(inst), "states.get", serde_json::json!({}), "ok", serde_json::json!({}));
        log.record(Some("op@x".into()), Some(inst), "core.restart", serde_json::json!({}), "ok", serde_json::json!({}));
        let rows = log.query(Some(inst), 10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "core.restart"); // newest first
        assert_eq!(rows[0].audit_id, 2);
    }

    #[test]
    fn instance_filter_excludes_others() {
        let log = AuditLog::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        log.record(None, Some(a), "x", serde_json::json!({}), "ok", serde_json::json!({}));
        log.record(None, Some(b), "y", serde_json::json!({}), "ok", serde_json::json!({}));
        assert_eq!(log.query(Some(a), 10).len(), 1);
        assert_eq!(log.query(None, 10).len(), 2);
    }
}
