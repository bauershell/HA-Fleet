//! RPC envelope (`03 §4`). Phase 0 exercises the read ops only: `states.get`,
//! `dashboard.list`, `dashboard.get`. The full op set lives in `03 §5`; ops not
//! yet brokered return `RpcErrorCode::BadRequest` from the agent dispatcher.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `chan=rpc, type=req` (`03 §4`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Operation name, e.g. `"dashboard.get"` (`03 §5`).
    pub op: String,
    /// Dedup across reconnects (`NFR-OFF-2`). Absent for pure reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<Uuid>,
    pub deadline_ms: u64,
    /// Op-specific arguments.
    #[serde(default)]
    pub args: serde_json::Value,
}

/// `chan=rpc, type=resp` (`03 §4`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(result: serde_json::Value) -> Self {
        Self { ok: true, result: Some(result), error: None }
    }
    pub fn err(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(RpcError { code, message: message.into(), retriable: code.retriable() }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
    pub retriable: bool,
}

/// Standard error codes (`03 §4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    InstanceOffline,
    CapabilityMissing,
    HaError,
    Timeout,
    /// Reconcile drift (`03 §7`). phase: 3
    Conflict,
    Unauthorized,
    BadRequest,
}

impl RpcErrorCode {
    /// Whether a client may safely retry (feeds `RpcError.retriable`).
    pub fn retriable(self) -> bool {
        matches!(self, RpcErrorCode::InstanceOffline | RpcErrorCode::Timeout | RpcErrorCode::HaError)
    }
}

/// Canonical op names (`03 §5`). Kept as `&str` constants so the relay,
/// agent broker, and audit log all reference the same spelling.
pub mod op {
    // Phase 0 (reads)
    pub const STATES_GET: &str = "states.get";
    pub const DASHBOARD_LIST: &str = "dashboard.list";
    pub const DASHBOARD_GET: &str = "dashboard.get";
    // Inventory reads (fleet visibility): notifications, installed services/
    // add-ons, device registry, and available updates.
    pub const NOTIFICATION_LIST: &str = "notification.list";
    pub const SERVICE_LIST: &str = "service.list";
    pub const DEVICE_LIST: &str = "device.list";
    pub const UPDATE_LIST: &str = "update.list";
    // Phase 1 (core management)
    pub const DASHBOARD_SAVE: &str = "dashboard.save";
    pub const AUTOMATION_LIST: &str = "automation.list";
    pub const AUTOMATION_GET: &str = "automation.get";
    pub const AUTOMATION_SAVE: &str = "automation.save";
    pub const AUTOMATION_RELOAD: &str = "automation.reload";
    pub const CONFIG_CHECK: &str = "config.check";
    pub const CORE_RESTART: &str = "core.restart";
    pub const LOG_STREAM: &str = "log.stream";
    pub const HEALTH_GET: &str = "health.get";
    pub const SERVICE_CALL: &str = "service.call";
    // Phase 2 (Supervisor)
    pub const BACKUP_CREATE: &str = "backup.create";
    pub const BACKUP_LIST: &str = "backup.list";
    pub const BACKUP_DOWNLOAD: &str = "backup.download";
    pub const BACKUP_RESTORE: &str = "backup.restore";
    pub const UPDATE_CHECK: &str = "update.check";
    pub const UPDATE_APPLY: &str = "update.apply";
    pub const USER_LIST: &str = "user.list";
    pub const USER_CREATE: &str = "user.create";
    pub const USER_UPDATE: &str = "user.update";
    pub const USER_DELETE: &str = "user.delete";
    // Phase 4 (proxy) / Phase 5 (self-update)
    pub const PROXY_OPEN: &str = "proxy.open";
    pub const AGENT_UPDATE: &str = "agent.update";

    /// Destructive ops needing elevated role / step-up auth (`05 §6`).
    pub const DESTRUCTIVE: &[&str] = &[
        BACKUP_RESTORE, UPDATE_APPLY, USER_DELETE, CORE_RESTART, AGENT_UPDATE,
    ];

    /// Whether an op mutates HA state (gates offline queueing, `NFR-OFF-2`).
    pub fn is_write(op: &str) -> bool {
        matches!(
            op,
            DASHBOARD_SAVE | AUTOMATION_SAVE | AUTOMATION_RELOAD | CORE_RESTART
                | SERVICE_CALL | BACKUP_CREATE | BACKUP_RESTORE | UPDATE_APPLY
                | USER_CREATE | USER_UPDATE | USER_DELETE | AGENT_UPDATE
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_serialize_snake_case() {
        let s = serde_json::to_string(&RpcErrorCode::InstanceOffline).unwrap();
        assert_eq!(s, "\"instance_offline\"");
    }

    #[test]
    fn ok_helper_sets_fields() {
        let r = RpcResponse::ok(serde_json::json!({"a": 1}));
        assert!(r.ok);
        assert!(r.error.is_none());
        assert!(r.result.is_some());
    }

    #[test]
    fn err_helper_marks_retriable() {
        let r = RpcResponse::err(RpcErrorCode::Timeout, "slow");
        assert!(!r.ok);
        let e = r.error.unwrap();
        assert!(e.retriable);
        assert_eq!(e.code, RpcErrorCode::Timeout);
    }
}
