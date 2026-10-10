//! Capability strings advertised in the handshake (`03 §3`). The control plane
//! stores these (`04` `capabilities`) and gates features per instance (`FR-8`).
//!
//! Phase 0 only *detects and advertises* them; only `core.*` matter for the
//! status + dashboard read slice. Supervisor variants are defined so capability
//! detection can report them, but no op behind them is wired until Phase 2.

use serde::{Deserialize, Serialize};

/// Flat capability tokens. Serialized as the dotted strings from `03 §3`
/// (e.g. `supervisor.backup`) so they match the wire + DB verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    #[serde(rename = "core.states")]
    CoreStates,
    #[serde(rename = "core.services")]
    CoreServices,
    #[serde(rename = "core.lovelace")]
    CoreLovelace,
    #[serde(rename = "core.automation")]
    CoreAutomation,
    #[serde(rename = "core.users")]
    CoreUsers,
    #[serde(rename = "core.errorlog")]
    CoreErrorlog,
    #[serde(rename = "core.health")]
    CoreHealth,
    #[serde(rename = "supervisor.backup")]
    SupervisorBackup,
    #[serde(rename = "supervisor.update")]
    SupervisorUpdate,
    #[serde(rename = "supervisor.addons")]
    SupervisorAddons,
    #[serde(rename = "supervisor.host")]
    SupervisorHost,
    #[serde(rename = "supervisor.logs")]
    SupervisorLogs,
    #[serde(rename = "proxy.http")]
    ProxyHttp,
}

impl Capability {
    /// True for the Supervisor-gated capabilities (`03 §3`, only on haos/supervised).
    pub fn is_supervisor(self) -> bool {
        matches!(
            self,
            Capability::SupervisorBackup
                | Capability::SupervisorUpdate
                | Capability::SupervisorAddons
                | Capability::SupervisorHost
                | Capability::SupervisorLogs
        )
    }

    /// The dotted wire string, e.g. `"core.states"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::CoreStates => "core.states",
            Capability::CoreServices => "core.services",
            Capability::CoreLovelace => "core.lovelace",
            Capability::CoreAutomation => "core.automation",
            Capability::CoreUsers => "core.users",
            Capability::CoreErrorlog => "core.errorlog",
            Capability::CoreHealth => "core.health",
            Capability::SupervisorBackup => "supervisor.backup",
            Capability::SupervisorUpdate => "supervisor.update",
            Capability::SupervisorAddons => "supervisor.addons",
            Capability::SupervisorHost => "supervisor.host",
            Capability::SupervisorLogs => "supervisor.logs",
            Capability::ProxyHttp => "proxy.http",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_dotted_string() {
        let s = serde_json::to_string(&Capability::SupervisorBackup).unwrap();
        assert_eq!(s, "\"supervisor.backup\"");
    }

    #[test]
    fn supervisor_classification() {
        assert!(Capability::SupervisorBackup.is_supervisor());
        assert!(!Capability::CoreStates.is_supervisor());
        assert!(!Capability::ProxyHttp.is_supervisor());
    }
}
