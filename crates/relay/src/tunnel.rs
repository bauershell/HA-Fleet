//! Tunnel-side handlers + the RPC correlation `Hub`.
//!
//! * [`handle_enroll`] runs the one-time enrollment exchange (`03 §1a`).
//! * [`handle_tunnel`] runs a steady-state connection: HELLO/WELCOME, heartbeat
//!   liveness, and the RPC request/response pump (`03 §1b`, §4).
//! * [`Hub`] lets the operator HTTP side issue an RPC by `instance_id` and await
//!   the correlated response, matching on `stream_id`.

use crate::AppState;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use hafm_proto::{
    Channel, Enroll, EnrollExchange, EnrollRejectReason, EnrollRejected, Enrolled, Frame,
    FrameBody, Hello, RpcRequest, RpcResponse, Welcome, HEARTBEAT_DEAD_AFTER_SECS,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::registry::{now_ms, ClaimError};

// ---------------------------------------------------------------------------
// WsConn — a tiny WebSocket abstraction so one copy of the enroll/tunnel logic
// serves BOTH the axum socket (operator/testing path) and the raw mTLS stream
// (tokio-tungstenite over a verified-client-cert TLS session). Text frames,
// close, and split-free sequential I/O are all the handlers need.
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait WsConn: Send {
    /// Receive the next text frame, or None on close/non-text/error.
    async fn recv_text(&mut self) -> Option<String>;
    /// Send a text frame; Err on a dead socket.
    async fn send_text(&mut self, txt: String) -> Result<(), ()>;
    /// Best-effort close.
    async fn close(&mut self);
}

#[async_trait::async_trait]
impl WsConn for WebSocket {
    async fn recv_text(&mut self) -> Option<String> {
        loop {
            match self.recv().await {
                Some(Ok(Message::Text(t))) => return Some(t),
                Some(Ok(Message::Close(_))) | None => return None,
                Some(Ok(_)) => continue, // skip ping/pong/binary
                Some(Err(_)) => return None,
            }
        }
    }
    async fn send_text(&mut self, txt: String) -> Result<(), ()> {
        SinkExt::send(self, Message::Text(txt)).await.map_err(|_| ())
    }
    async fn close(&mut self) {
        let _ = SinkExt::close(self).await;
    }
}

/// A tokio-tungstenite stream over the mTLS session (any AsyncRead+AsyncWrite).
#[async_trait::async_trait]
impl<S> WsConn for tokio_tungstenite::WebSocketStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    async fn recv_text(&mut self) -> Option<String> {
        use tokio_tungstenite::tungstenite::Message as T;
        loop {
            match self.next().await {
                Some(Ok(T::Text(t))) => return Some(t),
                Some(Ok(T::Close(_))) | None => return None,
                Some(Ok(_)) => continue,
                Some(Err(_)) => return None,
            }
        }
    }
    async fn send_text(&mut self, txt: String) -> Result<(), ()> {
        use tokio_tungstenite::tungstenite::Message as T;
        SinkExt::send(self, T::Text(txt)).await.map_err(|_| ())
    }
    async fn close(&mut self) {
        let _ = SinkExt::close(self).await;
    }
}

/// Correlates outstanding RPCs across the whole relay. Keyed by `(instance, stream_id)`.
#[derive(Default)]
pub struct Hub {
    pending: Mutex<HashMap<(Uuid, u32), oneshot::Sender<RpcResponse>>>,
    stream_ctr: AtomicU32,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_stream(&self) -> u32 {
        // Start at 1 (0 is reserved for ctrl frames); wrap is fine for Phase 0.
        self.stream_ctr.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    /// Register a pending RPC and return the receiver to await.
    fn register(&self, key: (Uuid, u32)) -> oneshot::Receiver<RpcResponse> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(key, tx);
        rx
    }

    /// Deliver a response to whoever is awaiting `(instance, stream_id)`.
    fn deliver(&self, key: (Uuid, u32), resp: RpcResponse) {
        if let Some(tx) = self.pending.lock().unwrap().remove(&key) {
            let _ = tx.send(resp);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("instance offline (no live tunnel)")]
    InstanceOffline,
    #[error("rpc timed out")]
    Timeout,
    #[error("hub not wired")]
    NotWired,
}

impl Hub {
    /// The RPC entry: look up the live tunnel sender in the registry, send a
    /// `req` frame, and await the matching `resp`.
    pub async fn call_via(
        self: &Arc<Self>,
        st: &AppState,
        instance: Uuid,
        op: &str,
        args: serde_json::Value,
    ) -> Result<RpcResponse, HubError> {
        let tx = st.registry.tunnel(instance).ok_or(HubError::InstanceOffline)?;
        let stream_id = self.next_stream();
        let rx = self.register((instance, stream_id));

        let frame = Frame {
            chan: Channel::Rpc,
            stream_id,
            seq: 0,
            body: FrameBody::Req(RpcRequest {
                op: op.to_string(),
                idempotency_key: None,
                deadline_ms: 15_000,
                args,
            }),
        };
        let txt = serde_json::to_string(&frame).map_err(|_| HubError::NotWired)?;
        tx.send(txt).await.map_err(|_| HubError::InstanceOffline)?;

        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(HubError::InstanceOffline),
            Err(_) => {
                self.pending.lock().unwrap().remove(&(instance, stream_id));
                Err(HubError::Timeout)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment handler (03 §1a)
// ---------------------------------------------------------------------------

/// mTLS entry point (SECURITY-TODO #1): the agent connects with NO CA-signed
/// cert yet (it is here to get one), so `peer_fp` is the fp of whatever bootstrap
/// cert it presented — informational only; enrollment is gated by the single-use
/// claim code, not the cert.
pub async fn handle_enroll_tls<C: WsConn>(socket: C, st: AppState, _peer_fp: String) {
    handle_enroll(socket, st).await
}

pub async fn handle_enroll<C: WsConn>(mut socket: C, st: AppState) {
    let Some(txt) = socket.recv_text().await else {
        tracing::warn!("enroll: no initial message");
        return;
    };
    let exchange: EnrollExchange = match serde_json::from_str(&txt) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "enroll: bad payload");
            return;
        }
    };
    let EnrollExchange::Enroll(enroll) = exchange else {
        tracing::warn!("enroll: first message was not Enroll");
        return;
    };

    let reply = process_enroll(&st, enroll).await;
    let _ = socket.send_text(serde_json::to_string(&reply).unwrap()).await;
    socket.close().await;
}

async fn process_enroll(st: &AppState, enroll: Enroll) -> EnrollExchange {
    // 1. validate + spend the single-use claim code (05 §2, #9 TTL+revoke).
    let display_name = match st.registry.consume_claim(&enroll.claim_code).await {
        Ok(name) => name,
        Err(ClaimError::Unknown) => {
            return reject(EnrollRejectReason::ClaimCodeUnknown, "unknown claim code")
        }
        Err(ClaimError::Spent) => {
            return reject(EnrollRejectReason::ClaimCodeSpent, "claim code already used")
        }
        Err(ClaimError::Revoked) => {
            return reject(EnrollRejectReason::ClaimCodeSpent, "claim code revoked")
        }
        Err(ClaimError::Expired) => {
            return reject(EnrollRejectReason::ClaimCodeExpired, "claim code expired")
        }
    };

    // 2. sign the agent's CSR → client cert bound to its key (03 §1a, #3/#4);
    //    compute the fingerprint to pin (04 §1 agent_cert_fp).
    let cn = format!("agent-{}", enroll.claim_code);
    let issued = match st.ca.sign_csr(&enroll.csr_pem, &cn) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "enroll: CSR signing failed");
            return reject(EnrollRejectReason::BadCsr, "could not sign CSR");
        }
    };

    // 3. mint instance_id, pin cert fp, enroll_state=active (04 §1).
    let instance_id = st.registry.create_instance(
        display_name,
        enroll.install_type,
        enroll.ha_version,
        enroll.agent_version,
        enroll.capabilities,
        issued.fingerprint.clone(),
    ).await;
    tracing::info!(%instance_id, cert_fp = %issued.fingerprint, "instance enrolled");

    EnrollExchange::Enrolled(Enrolled {
        instance_id,
        client_cert_pem: issued.cert_pem,
        relay_ca_pem: st.ca.ca_cert_pem().to_string(),
        session_id: Uuid::new_v4(),
        min_agent_ver: "0.0.0".into(),
    })
}

fn reject(reason: EnrollRejectReason, msg: &str) -> EnrollExchange {
    EnrollExchange::Rejected(EnrollRejected { reason, message: msg.to_string() })
}

// ---------------------------------------------------------------------------
// Steady-state tunnel handler (03 §1b, §4)
// ---------------------------------------------------------------------------

/// mTLS entry point (SECURITY-TODO #2): `peer_fp` is the SHA-256 of the agent's
/// VERIFIED client cert (rustls already chained it to the CA). The handler
/// additionally requires it to equal the fingerprint pinned at enrollment, so a
/// valid-but-different cert cannot impersonate another instance.
pub async fn handle_tunnel_tls<C: WsConn>(socket: C, st: AppState, peer_fp: String) {
    handle_tunnel_inner(socket, st, Some(peer_fp)).await
}

/// Non-TLS entry (used only by in-process tests / the plain-WS fallback). No
/// verified fingerprint is available, so the pin check is skipped — this path
/// must never be exposed on a public listener.
#[allow(dead_code)]
pub async fn handle_tunnel<C: WsConn>(socket: C, st: AppState) {
    handle_tunnel_inner(socket, st, None).await
}

async fn handle_tunnel_inner<C: WsConn>(mut socket: C, st: AppState, peer_fp: Option<String>) {
    // 1. expect HELLO.
    let hello: Hello = match socket.recv_text().await {
        Some(t) => match serde_json::from_str::<Frame>(&t) {
            Ok(Frame { body: FrameBody::Hello(h), .. }) => h,
            _ => {
                tracing::warn!("tunnel: first frame not HELLO");
                return;
            }
        },
        None => return,
    };

    let instance_id = hello.instance_id;

    let Some(inst) = st.registry.get(instance_id).await else {
        tracing::warn!(%instance_id, "tunnel: HELLO for unknown instance — refusing");
        return;
    };

    // Revoked instances are refused (`05 §5.1`): a revoked cert cannot
    // re-establish the tunnel even if the agent still holds it.
    if inst.enroll_state == crate::registry::EnrollState::Revoked {
        tracing::warn!(%instance_id, "tunnel: HELLO from REVOKED instance — refusing");
        return;
    }

    // mTLS identity binding (SECURITY-TODO #2): the VERIFIED client-cert
    // fingerprint must equal the one pinned at enrollment. This replaces the old
    // "trust HELLO.instance_id" stub — the HELLO's instance_id is now only a
    // lookup key; authentication is the cert.
    if let Some(fp) = &peer_fp {
        match &inst.agent_cert_fp {
            Some(pinned) if pinned == fp => {}
            Some(pinned) => {
                tracing::warn!(%instance_id, presented = %fp, %pinned,
                    "tunnel: client-cert fingerprint does NOT match pin — refusing");
                return;
            }
            None => {
                tracing::warn!(%instance_id, "tunnel: instance has no pinned cert — refusing");
                return;
            }
        }
    }

    if !st.registry.on_hello(
        instance_id,
        hello.install_type,
        hello.ha_version.clone(),
        hello.agent_version.clone(),
        hello.capabilities.clone(),
    ).await {
        tracing::warn!(%instance_id, "tunnel: HELLO for unknown instance — refusing");
        return;
    }

    // 2. send WELCOME.
    let welcome = Frame {
        chan: Channel::Ctrl,
        stream_id: 0,
        seq: 0,
        body: FrameBody::Welcome(Welcome {
            session_id: Uuid::new_v4(),
            resume_from: 0,
            server_time_ms: now_ms(),
            min_agent_ver: "0.0.0".into(),
        }),
    };
    if socket.send_text(serde_json::to_string(&welcome).unwrap()).await.is_err() {
        return;
    }
    tracing::info!(%instance_id, mtls = peer_fp.is_some(), caps = ?hello.capabilities, "tunnel up");

    // 3. bind an outbound channel so the operator HTTP side can push RPCs.
    let (out_tx, mut out_rx) = mpsc::channel::<String>(64);
    st.registry.bind_tunnel(instance_id, out_tx);
    // Register tunnel ownership in the presence router (#15) so a scaled-out
    // fleet knows which node holds this agent's socket.
    st.router.register(instance_id).await;

    // 3b. deliver any writes queued while this instance was offline, in order
    //     (`NFR-OFF-2`).
    let queued = st.queue.drain(instance_id).await;
    if !queued.is_empty() {
        tracing::info!(%instance_id, n = queued.len(), "delivering queued offline writes");
        for cmd in queued {
            let frame = Frame {
                chan: Channel::Rpc,
                stream_id: 0, // fire-and-forget; no awaiter
                seq: 0,
                body: FrameBody::Req(RpcRequest {
                    op: cmd.op.clone(),
                    idempotency_key: Uuid::parse_str(&cmd.idempotency_key).ok(),
                    deadline_ms: 15_000,
                    args: cmd.args,
                }),
            };
            if let Ok(txt) = serde_json::to_string(&frame) {
                let _ = st.registry.tunnel(instance_id).map(|tx| tx.try_send(txt));
            }
            st.audit.record(
                None,
                Some(instance_id),
                &cmd.op,
                serde_json::json!({"idempotency_key": cmd.idempotency_key}),
                "ok",
                serde_json::json!({"delivery": "replayed_on_reconnect"}),
            ).await;
        }
    }

    let hub = st.hub.clone();
    let registry = st.registry.clone();
    let mut last_seen = now_ms();

    // 4. pump: forward operator RPC frames out; route agent frames back in.
    loop {
        tokio::select! {
            maybe = out_rx.recv() => {
                match maybe {
                    Some(txt) => {
                        if socket.send_text(txt).await.is_err() { break; }
                    }
                    None => break,
                }
            }
            maybe = socket.recv_text() => {
                match maybe {
                    Some(t) => {
                        last_seen = now_ms();
                        if let Ok(frame) = serde_json::from_str::<Frame>(&t) {
                            match frame.body {
                                FrameBody::Resp(resp) => {
                                    hub.deliver((instance_id, frame.stream_id), resp);
                                }
                                FrameBody::Heartbeat => {
                                    registry.touch_heartbeat(instance_id).await;
                                    st.router.heartbeat(instance_id).await;
                                }
                                other => tracing::debug!(?other, "tunnel: unexpected inbound frame"),
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if now_ms().saturating_sub(last_seen) > HEARTBEAT_DEAD_AFTER_SECS * 1000 {
                    tracing::warn!(%instance_id, "tunnel: heartbeat dead → closing");
                    break;
                }
            }
        }
    }

    st.registry.unbind_tunnel(instance_id);
    st.router.unregister(instance_id).await;
    tracing::info!(%instance_id, "tunnel down");
    let _ = hub; // keep clone alive for the loop lifetime
}
