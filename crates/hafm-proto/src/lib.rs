//! Shared agent↔relay wire protocol — spec `03-agent-protocol.md`.
//!
//! Phase 0 implements the JSON control frames only. The binary `proxy` channel
//! and chunked blob transfer (`03 §6`, `backup.download`) are defined as enum
//! variants but not exercised until later phases — they are marked `// phase: N`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod capability;
pub mod rpc;

pub use capability::Capability;
pub use rpc::{op, RpcError, RpcErrorCode, RpcRequest, RpcResponse};

/// Protocol version negotiated in the handshake (`03 §9`). Additive ops are
/// backward compatible; a breaking change bumps this major.
pub const PROTOCOL_VERSION: u16 = 0;

/// Agent build version advertised in `ENROLL`/`HELLO`. Phase 0 placeholder.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// HA install type (`04-data-model.md` `instances.install_type`). Drives which
/// capabilities are even possible (`02 §2.3`, Supervisor only on haos/supervised).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallType {
    Core,
    Container,
    Supervised,
    Haos,
}

impl InstallType {
    /// Whether the Supervisor API is reachable for this install type (`02 §2.3`).
    pub fn has_supervisor(self) -> bool {
        matches!(self, InstallType::Supervised | InstallType::Haos)
    }
}

// ---------------------------------------------------------------------------
// Frame header / mux (03 §2)
// ---------------------------------------------------------------------------

/// Logical channel multiplexed on the one tunnel (`03 §2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Control-op request/response.
    Rpc,
    /// Reverse-proxy byte stream. phase: 4
    Proxy,
    /// Tunnel control (HELLO/WELCOME/HEARTBEAT).
    Ctrl,
}

/// Every tunnel frame begins with this header (`03 §2`). The `payload` carries
/// the channel-specific body; in Phase 0 all payloads are JSON values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub chan: Channel,
    /// Correlates request/response or a proxy stream.
    pub stream_id: u32,
    /// Monotonic per-direction, for ack/resume (`03 §1b resume_from`).
    pub seq: u64,
    /// Channel-specific message type tag + body, flattened below.
    #[serde(flatten)]
    pub body: FrameBody,
}

/// The body dispatched by `chan` + inner `type`. Phase 0 handles `Ctrl` and the
/// `Rpc` request/response variants; streaming + proxy variants are reserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FrameBody {
    // --- ctrl ---
    Hello(Hello),
    Welcome(Welcome),
    Heartbeat,
    // --- rpc ---
    Req(RpcRequest),
    Resp(RpcResponse),
    /// Streaming chunk (logs, blobs). phase: 1+
    Chunk { data: serde_json::Value },
    /// Terminal frame of a stream. phase: 1+
    End,
}

// ---------------------------------------------------------------------------
// Enrollment / first contact — runs ONCE, no cert yet (03 §1a, 05 §2)
// ---------------------------------------------------------------------------

/// `ENROLL` — sent by a freshly installed agent over a server-auth-only TLS
/// connection. The agent already self-provisioned its local HA identity
/// (`05 §2.1`) before this point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enroll {
    /// Single-use, short-TTL claim code issued when the operator registered the
    /// instance (`05 §2`).
    pub claim_code: String,
    pub install_type: InstallType,
    pub ha_version: Option<String>,
    pub agent_version: String,
    pub capabilities: Vec<Capability>,
    /// PEM-encoded PKCS#10 CSR. The private key never leaves the box (`03 §1a`).
    pub csr_pem: String,
}

/// `ENROLLED` — relay signs the CSR, pins the cert fingerprint to a freshly
/// minted `instance_id`, flips enroll_state→active (`04 §1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrolled {
    pub instance_id: Uuid,
    /// PEM-encoded signed mTLS client cert.
    pub client_cert_pem: String,
    /// PEM-encoded relay CA, so the agent can verify the relay server cert.
    pub relay_ca_pem: String,
    pub session_id: Uuid,
    pub min_agent_ver: String,
}

/// Enrollment can be refused: spent/expired/revoked claim code, or a bad CSR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRejected {
    pub reason: EnrollRejectReason,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollRejectReason {
    ClaimCodeUnknown,
    ClaimCodeSpent,
    ClaimCodeExpired,
    BadCsr,
    AgentTooOld,
}

/// What the agent POSTs/sends on the `/enroll` endpoint, and what it gets back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum EnrollExchange {
    Enroll(Enroll),
    Enrolled(Enrolled),
    Rejected(EnrollRejected),
}

// ---------------------------------------------------------------------------
// Steady-state handshake (03 §1b)
// ---------------------------------------------------------------------------

/// `HELLO` — first frame on `/tunnel` after mTLS. The cert binding is the auth;
/// no token is presented (`03 §1b`, `05 §2`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub instance_id: Uuid,
    pub install_type: InstallType,
    pub ha_version: Option<String>,
    pub agent_version: String,
    pub capabilities: Vec<Capability>,
    pub protocol_version: u16,
}

/// `WELCOME` — relay accepts, assigns a session, tells the agent where to resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    pub session_id: Uuid,
    /// Last server-acked RPC seq; agent replays only unacked idempotent ops.
    pub resume_from: u64,
    /// Relay wall clock (ms since epoch) for skew detection.
    pub server_time_ms: u64,
    pub min_agent_ver: String,
}

/// Heartbeat cadence (`03 §1b`): send every 30s, dead after 90s → mark offline.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;
pub const HEARTBEAT_DEAD_AFTER_SECS: u64 = 90;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_ctrl_hello_round_trips() {
        let f = Frame {
            chan: Channel::Ctrl,
            stream_id: 0,
            seq: 1,
            body: FrameBody::Hello(Hello {
                instance_id: Uuid::nil(),
                install_type: InstallType::Haos,
                ha_version: Some("2026.9.0".into()),
                agent_version: AGENT_VERSION.into(),
                capabilities: vec![Capability::CoreStates, Capability::CoreLovelace],
                protocol_version: PROTOCOL_VERSION,
            }),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.body, FrameBody::Hello(_)));
        assert_eq!(back.chan, Channel::Ctrl);
    }

    #[test]
    fn rpc_req_round_trips() {
        let f = Frame {
            chan: Channel::Rpc,
            stream_id: 1337,
            seq: 2,
            body: FrameBody::Req(RpcRequest {
                op: "dashboard.get".into(),
                idempotency_key: Some(Uuid::new_v4()),
                deadline_ms: 15_000,
                args: serde_json::json!({ "dashboard_id": "lovelace" }),
            }),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&s).unwrap();
        match back.body {
            FrameBody::Req(r) => assert_eq!(r.op, "dashboard.get"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn install_type_supervisor_gating() {
        assert!(InstallType::Haos.has_supervisor());
        assert!(InstallType::Supervised.has_supervisor());
        assert!(!InstallType::Container.has_supervisor());
        assert!(!InstallType::Core.has_supervisor());
    }

    #[test]
    fn enroll_exchange_tagged() {
        let e = EnrollExchange::Rejected(EnrollRejected {
            reason: EnrollRejectReason::ClaimCodeSpent,
            message: "already used".into(),
        });
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"msg\":\"rejected\""));
    }
}
