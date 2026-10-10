//! `agent` — the edge agent (`02 §2`). Two modes:
//!
//!   agent enroll --relay <wss-url> --claim-code <code>   (one-time, 03 §1a)
//!   agent                                                (steady state, 03 §1b)
//!
//! Transport is **real mTLS** (SECURITY-TODO #1–#6). At enrollment the agent
//! generates a keypair + CSR locally (private key never leaves the box), sends
//! only the CSR, and stores the CA-signed client cert it gets back. Steady-state
//! `/tunnel` connections present that client cert, and the relay authenticates
//! the agent by its verified cert fingerprint matching the enrollment pin.

mod broker;
mod detect;
mod tls;
mod update;

use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use hafm_proto::{
    Channel, Enroll, EnrollExchange, Frame, FrameBody, Hello, AGENT_VERSION,
    HEARTBEAT_INTERVAL_SECS, PROTOCOL_VERSION,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message as WsMsg;

use broker::Broker;
use detect::Identity;

#[derive(Parser, Debug)]
#[command(name = "agent", about = "ha-fleet edge agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Relay base URL. mTLS uses wss://; ws:// is accepted for the loopback
    /// test harness only.
    #[arg(long, env = "AGENT_RELAY", default_value = "wss://127.0.0.1:8443", global = true)]
    relay: String,
    /// Local HA Core base URL.
    #[arg(long, env = "AGENT_HA_BASE", default_value = "http://127.0.0.1:8123", global = true)]
    ha_base: String,
    /// HA long-lived access token (self-provisioned, `05 §2.1`). Mock ignores it.
    #[arg(long, env = "AGENT_HA_TOKEN", default_value = "dev-token", global = true)]
    ha_token: String,
    /// Supervisor REST base (supervised/haos only). Real HA uses `http://supervisor`;
    /// the mock exposes it under the Core base at `/supervisor`.
    #[arg(long, env = "AGENT_SUPERVISOR_BASE", global = true)]
    supervisor_base: Option<String>,
    /// Where the enrollment identity is stored.
    #[arg(long, env = "AGENT_STATE_DIR", global = true)]
    state_dir: Option<PathBuf>,
    /// Path to the relay CA cert (PEM) to trust during ENROLLMENT. If omitted,
    /// the agent trusts-on-first-use (TOFU) with a loud warning — acceptable for
    /// a loopback dev relay, NOT for production where the CA (or its fingerprint)
    /// must be delivered out-of-band with the claim code.
    #[arg(long, env = "AGENT_RELAY_CA", global = true)]
    relay_ca: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// One-time enrollment: generate keypair + CSR, claim a code, store the cert.
    Enroll {
        #[arg(long)]
        claim_code: String,
        /// Owner credential used ONCE to self-provision a dedicated least-privilege
        /// HA account (`05 §2.1`, SECURITY-TODO #8). Never stored; discarded after
        /// the dedicated token is minted. Omit to keep the --ha-token dev default.
        #[arg(long)]
        owner_token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,agent=debug".into()))
        .init();

    let cli = Cli::parse();
    // Install the ring-backed rustls crypto provider (required by rustls 0.23).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let state_dir = cli
        .state_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("hafm-agent"));

    match &cli.cmd {
        Some(Cmd::Enroll { claim_code, owner_token }) => {
            enroll(&cli, &state_dir, claim_code, owner_token.as_deref()).await
        }
        None => run_steady_state(&cli, &state_dir).await,
    }
}

/// Self-provision a dedicated least-privilege HA token (`05 §2.1`, #8). Presents
/// the owner credential ONCE to HA's provisioning endpoint, returns the minted
/// dedicated token. The owner credential is dropped by the caller immediately.
async fn self_provision(ha_base: &str, owner_token: &str) -> anyhow::Result<String> {
    let url = format!("{ha_base}/auth/provision");
    let body = serde_json::json!({ "owner_token": owner_token }).to_string();
    let resp = detect::http_post_text(&url, &body).await?;
    let v: serde_json::Value = serde_json::from_str(&resp)?;
    v.get("long_lived_token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("provision response had no long_lived_token: {resp}"))
}

/// Open a WSS connection to `url` with the given TLS connector, returning the
/// WebSocket stream. Falls back to plain ws:// only when `url` is ws:// (test
/// harness) — a wss:// url always goes through TLS.
async fn ws_connect(
    url: &str,
    connector: Option<&tokio_rustls::TlsConnector>,
) -> anyhow::Result<WsStream> {
    if url.starts_with("ws://") {
        // Plain-WS test path (loopback harness only).
        let (ws, _) = tokio_tungstenite::connect_async(url).await?;
        return Ok(WsStream::Plain(Box::new(ws)));
    }
    let connector = connector.ok_or_else(|| anyhow::anyhow!("wss requires a TLS connector"))?;
    let (server_name, authority) = tls::parse_wss(url)?;
    let tcp = tokio::net::TcpStream::connect(&authority).await?;
    let tls = connector.connect(server_name, tcp).await?;
    let (ws, _) = tokio_tungstenite::client_async(url, tls).await?;
    Ok(WsStream::Tls(Box::new(ws)))
}

/// A WS stream that is either plain TCP (test) or over a rustls client session.
/// Both variants are boxed to keep the enum small (the TLS stream is large).
enum WsStream {
    Plain(Box<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>),
    Tls(Box<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>),
}

impl WsStream {
    async fn send(&mut self, m: WsMsg) -> anyhow::Result<()> {
        match self {
            WsStream::Plain(s) => s.send(m).await?,
            WsStream::Tls(s) => s.send(m).await?,
        }
        Ok(())
    }
    async fn next(&mut self) -> Option<Result<WsMsg, tokio_tungstenite::tungstenite::Error>> {
        match self {
            WsStream::Plain(s) => s.next().await,
            WsStream::Tls(s) => s.next().await,
        }
    }
}

/// Enrollment handshake (`03 §1a`). Generates a keypair + CSR locally, sends the
/// CSR, stores the CA-signed cert + private key (SECURITY-TODO #3). If an owner
/// token is given, first self-provisions a dedicated least-privilege HA token
/// (SECURITY-TODO #8) and stores THAT, discarding the owner credential.
async fn enroll(
    cli: &Cli,
    state_dir: &std::path::Path,
    claim_code: &str,
    owner_token: Option<&str>,
) -> anyhow::Result<()> {
    let detected = detect::detect(&cli.ha_base).await?;
    tracing::info!(
        install = ?detected.install_type,
        ha = ?detected.ha_version,
        caps = ?detected.capabilities,
        "capability detection complete"
    );

    // Self-provision the dedicated least-privilege HA token (#8) if an owner
    // credential was supplied. The owner token is used here and then dropped —
    // it is never written to the identity file.
    let ha_token = match owner_token {
        Some(owner) => {
            let dedicated = self_provision(&cli.ha_base, owner).await?;
            tracing::info!("self-provisioned dedicated least-privilege HA token (owner cred discarded)");
            Some(dedicated)
        }
        None => None,
    };

    // Generate the keypair + CSR up front; the private key stays local.
    let cn = format!("agent-{claim_code}");
    let (client_key_pem, csr_pem) = tls::generate_keypair_and_csr(&cn)?;

    // Trust the relay CA for the enroll TLS connection: from --relay-ca if given,
    // else TOFU (dev loopback only).
    let connector = match &cli.relay_ca {
        Some(path) => {
            let ca_pem = std::fs::read_to_string(path)?;
            Some(tls::connector_enroll(&ca_pem)?)
        }
        None if cli.relay.starts_with("wss://") => {
            anyhow::bail!(
                "enrolling over wss:// requires --relay-ca <relay CA pem> (TOFU not implemented for the dev build); point it at the relay's ca/ca-cert.pem"
            )
        }
        None => None, // ws:// test path
    };

    let enroll_url = format!("{}/enroll", cli.relay);
    let mut ws = ws_connect(&enroll_url, connector.as_ref()).await?;

    let msg = EnrollExchange::Enroll(Enroll {
        claim_code: claim_code.to_string(),
        install_type: detected.install_type,
        ha_version: detected.ha_version.clone(),
        agent_version: AGENT_VERSION.to_string(),
        capabilities: detected.capabilities.clone(),
        csr_pem,
    });
    ws.send(WsMsg::Text(serde_json::to_string(&msg)?)).await?;

    let reply = ws
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("relay closed during enroll"))??;
    let WsMsg::Text(txt) = reply else {
        anyhow::bail!("unexpected non-text enroll reply")
    };

    match serde_json::from_str::<EnrollExchange>(&txt)? {
        EnrollExchange::Enrolled(e) => {
            let id = Identity {
                instance_id: e.instance_id,
                client_key_pem,
                client_cert_pem: e.client_cert_pem,
                relay_ca_pem: e.relay_ca_pem,
                ha_token: ha_token.clone(),
            };
            id.save(state_dir)?;
            tracing::info!(
                instance_id = %e.instance_id,
                store = %Identity::store_path(state_dir).display(),
                "ENROLLED — identity (key+cert+CA) stored; run `agent` for steady state"
            );
            Ok(())
        }
        EnrollExchange::Rejected(r) => {
            anyhow::bail!("enrollment rejected: {:?} — {}", r.reason, r.message)
        }
        EnrollExchange::Enroll(_) => anyhow::bail!("relay echoed Enroll — protocol error"),
    }
}

/// Steady-state connection (`03 §1b`): HELLO → WELCOME, then serve RPCs + beat.
async fn run_steady_state(cli: &Cli, state_dir: &std::path::Path) -> anyhow::Result<()> {
    let identity = Identity::load(state_dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no enrollment identity at {} — run `agent enroll --claim-code <code>` first",
            Identity::store_path(state_dir).display()
        )
    })?;

    let detected = detect::detect(&cli.ha_base).await?;
    // Prefer the self-provisioned dedicated token (#8); fall back to the dev
    // --ha-token only when the agent was enrolled without self-provisioning.
    let ha_token = identity.ha_token.clone().unwrap_or_else(|| cli.ha_token.clone());
    let mut broker = Broker::new(cli.ha_base.clone(), ha_token);
    if detected.install_type.has_supervisor() {
        let base = cli
            .supervisor_base
            .clone()
            .unwrap_or_else(|| format!("{}/supervisor", cli.ha_base));
        tracing::info!(%base, "Supervisor broker enabled");
        broker = broker.with_supervisor(base);
    }

    // Build the mTLS tunnel connector once from the stored identity (#6): trust
    // the pinned relay CA, present our CA-signed client cert.
    let connector = if cli.relay.starts_with("wss://") {
        Some(tls::connector_tunnel(
            &identity.relay_ca_pem,
            &identity.client_cert_pem,
            &identity.client_key_pem,
        )?)
    } else {
        None // ws:// test path
    };

    // Reconnect loop with fixed backoff.
    loop {
        match connect_once(cli, &identity, &detected, &broker, connector.as_ref(), state_dir).await {
            Ok(()) => tracing::warn!("tunnel closed cleanly; reconnecting in 3s"),
            Err(e) => tracing::warn!(error = %e, "tunnel error; reconnecting in 3s"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn connect_once(
    cli: &Cli,
    identity: &Identity,
    detected: &detect::Detected,
    broker: &Broker,
    connector: Option<&tokio_rustls::TlsConnector>,
    state_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let tunnel_url = format!("{}/tunnel", cli.relay);
    // Present the mTLS client cert via the connector (#6); the relay verifies it
    // chains to the CA and matches the enrollment pin before accepting HELLO.
    let mut ws = ws_connect(&tunnel_url, connector).await?;

    // 1. HELLO
    let hello = Frame {
        chan: Channel::Ctrl,
        stream_id: 0,
        seq: 0,
        body: FrameBody::Hello(Hello {
            instance_id: identity.instance_id,
            install_type: detected.install_type,
            ha_version: detected.ha_version.clone(),
            agent_version: AGENT_VERSION.to_string(),
            capabilities: detected.capabilities.clone(),
            protocol_version: PROTOCOL_VERSION,
        }),
    };
    ws.send(WsMsg::Text(serde_json::to_string(&hello)?)).await?;

    // 2. WELCOME
    let welcome = ws.next().await.ok_or_else(|| anyhow::anyhow!("no WELCOME"))??;
    let WsMsg::Text(wtxt) = welcome else {
        anyhow::bail!("WELCOME was not text")
    };
    match serde_json::from_str::<Frame>(&wtxt)?.body {
        FrameBody::Welcome(w) => tracing::info!(session = %w.session_id, "tunnel up (WELCOME)"),
        other => anyhow::bail!("expected WELCOME, got {other:?}"),
    }

    // 3. serve: heartbeat ticker + inbound RPC request dispatch.
    // Real on-disk A/B slot layout under the state dir (#12): the agent.update
    // RPC performs an actual slot write + symlink flip + rollback.
    let slot_root = state_dir.join("slots-root");
    let mut slots = update::SlotLayout::init(&slot_root, AGENT_VERSION.as_bytes(), AGENT_VERSION)
        .unwrap_or_else(|e| {
            tracing::warn!(error=%e, "slot layout init failed; updates will error");
            // Re-init under a temp dir so the agent still serves other ops.
            update::SlotLayout::init(std::env::temp_dir().join("hafm-slots"), AGENT_VERSION.as_bytes(), AGENT_VERSION)
                .expect("temp slot init")
        });
    let mut beat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    loop {
        tokio::select! {
            _ = beat.tick() => {
                let hb = Frame { chan: Channel::Ctrl, stream_id: 0, seq: 0, body: FrameBody::Heartbeat };
                if ws.send(WsMsg::Text(serde_json::to_string(&hb)?)).await.is_err() { break; }
            }
            maybe = ws.next() => {
                let Some(msg) = maybe else { break };
                let WsMsg::Text(t) = msg? else { continue };
                let Ok(frame) = serde_json::from_str::<Frame>(&t) else { continue };
                if let FrameBody::Req(req) = frame.body {
                    tracing::debug!(op = %req.op, stream = frame.stream_id, "RPC req");
                    let resp = if req.op == hafm_proto::op::AGENT_UPDATE {
                        handle_agent_update(&mut slots, &req.args)
                    } else {
                        broker.dispatch(&req.op, &req.args).await
                    };
                    let out = Frame {
                        chan: Channel::Rpc,
                        stream_id: frame.stream_id,
                        seq: frame.seq,
                        body: FrameBody::Resp(resp),
                    };
                    if ws.send(WsMsg::Text(serde_json::to_string(&out)?)).await.is_err() { break; }
                }
            }
        }
    }
    Ok(())
}

/// Run the self-update state machine for an `agent.update` RPC (`05 §5.2`), now
/// backed by a REAL on-disk A/B slot swap (#12). The new-binary payload in the
/// skeleton is a version marker (no real artifact ships over the mock); the
/// slot write + symlink flip + rollback are performed for real. A rollback is
/// reported as a successful RPC whose `outcome` says the update did NOT take —
/// the control plane halts the rollout rather than treating it as an error.
fn handle_agent_update(
    slots: &mut update::SlotLayout,
    args: &serde_json::Value,
) -> hafm_proto::RpcResponse {
    let version = args.get("version").and_then(|v| v.as_str()).unwrap_or("");
    let signer = args.get("sig").and_then(|v| v.as_str()).unwrap_or("");
    let health_ok = args.get("health_ok").and_then(|v| v.as_bool()).unwrap_or(true);
    if version.is_empty() {
        return hafm_proto::RpcResponse::err(hafm_proto::RpcErrorCode::BadRequest, "missing version");
    }
    // Skeleton payload: the version string stands in for the downloaded binary.
    let payload = format!("agent-binary-{version}").into_bytes();
    match slots.apply(
        update::UpdateRequest { version, signer, health_ok_after_flip: health_ok },
        &payload,
    ) {
        Ok(outcome) => hafm_proto::RpcResponse::ok(serde_json::json!({
            "outcome": outcome,
            "active_slot": slots.active(),
            "running_version": slots.version(),
            "current_symlink": format!("{:?}", slots.current_slot()),
        })),
        Err(e) => hafm_proto::RpcResponse::err(
            hafm_proto::RpcErrorCode::HaError,
            format!("slot swap io error: {e}"),
        ),
    }
}
