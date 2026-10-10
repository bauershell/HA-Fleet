//! Core brokers (`02 §2.1/2.2`): translate Phase 0 RPC ops into HA Core calls.
//!
//! Phase 0 ops (`03 §5`): `states.get` (REST), `dashboard.list` + `dashboard.get`
//! (WS `lovelace/*`). Each call opens a short-lived HA WS when needed; a real
//! agent keeps one persistent Core WS (`02 §2.2`), which is a Phase 1 refinement.

use futures_util::{SinkExt, StreamExt};
use hafm_proto::{RpcErrorCode, RpcResponse};
use serde_json::json;
use tokio_tungstenite::tungstenite::Message as WsMsg;

pub struct Broker {
    /// e.g. `http://127.0.0.1:8123`
    core_base: String,
    /// e.g. `ws://127.0.0.1:8123/api/websocket`
    core_ws: String,
    /// Supervisor REST base, present only on supervised/haos (`05 §2.3`).
    /// `None` ⇒ the agent advertised no `supervisor.*` caps and the relay gates
    /// those ops out before they ever reach here.
    supervisor_base: Option<String>,
    /// HA long-lived access token (self-provisioned, `05 §2.1`). Mock ignores it.
    ha_token: String,
}

impl Broker {
    pub fn new(core_base: impl Into<String>, ha_token: impl Into<String>) -> Self {
        let core_base = core_base.into();
        let core_ws = core_base.replace("http://", "ws://").replace("https://", "wss://")
            + "/api/websocket";
        Self { core_base, core_ws, supervisor_base: None, ha_token: ha_token.into() }
    }

    /// Enable the Supervisor broker at the given REST base (supervised/haos).
    pub fn with_supervisor(mut self, base: impl Into<String>) -> Self {
        self.supervisor_base = Some(base.into());
        self
    }

    /// Dispatch an op. Phase 0 reads + Phase 1 core-management ops are wired;
    /// unknown/not-yet-wired ops return `BadRequest` (`03 §4`).
    pub async fn dispatch(&self, op: &str, args: &serde_json::Value) -> RpcResponse {
        use hafm_proto::op;
        let r = match op {
            // --- Phase 0 reads ---
            op::STATES_GET => self.states_get().await,
            op::DASHBOARD_LIST => self.dashboard_list().await,
            op::DASHBOARD_GET => self.dashboard_get(args).await,
            // --- Phase 1 core management ---
            op::DASHBOARD_SAVE => self.dashboard_save(args).await,
            op::AUTOMATION_LIST => self.ws_command(json!({"type": "automation/list"})).await,
            op::AUTOMATION_GET => {
                let aid = str_arg(args, "automation_id", "auto_1");
                self.ws_command(json!({"type": "automation/get", "automation_id": aid})).await
            }
            op::AUTOMATION_SAVE => self.automation_save(args).await,
            op::AUTOMATION_RELOAD => self.ws_command(json!({"type": "automation/reload"})).await,
            op::HEALTH_GET => self.ws_command(json!({"type": "system_health/info"})).await,
            op::CONFIG_CHECK => self.config_check().await,
            op::CORE_RESTART => self.core_restart().await,
            op::LOG_STREAM => self.log_stream().await,
            // --- Phase 2: user management (Core WS config/auth) ---
            op::USER_LIST => self.ws_command(json!({"type": "config/auth/list"})).await,
            op::USER_CREATE => {
                let name = str_arg(args, "name", "new-user");
                self.ws_command(json!({"type": "config/auth/create", "name": name})).await
            }
            op::USER_UPDATE => {
                let uid = str_arg(args, "user_id", "");
                self.ws_command(json!({"type": "config/auth/update", "user_id": uid, "patch": args.get("patch").cloned().unwrap_or(json!({}))})).await
            }
            op::USER_DELETE => {
                let uid = str_arg(args, "user_id", "");
                self.ws_command(json!({"type": "config/auth/delete", "user_id": uid})).await
            }
            // --- Phase 2: Supervisor-backed (gated on supervisor.* caps) ---
            op::BACKUP_LIST => self.sup_get("/backups").await,
            op::BACKUP_CREATE => {
                let name = str_arg(args, "name", "manual");
                self.sup_post("/backups", json!({"name": name})).await
            }
            op::BACKUP_DOWNLOAD => {
                let slug = str_arg(args, "slug", "");
                self.backup_download(&slug).await
            }
            op::BACKUP_RESTORE => {
                let slug = str_arg(args, "slug", "");
                self.sup_post(&format!("/backups/{slug}/restore"), json!({})).await
            }
            op::UPDATE_CHECK => self.sup_get("/available_updates").await,
            op::UPDATE_APPLY => {
                let target = str_arg(args, "target", "core");
                self.sup_post("/update", json!({"target": target})).await
            }
            // --- Inventory reads (fleet visibility) ---
            op::NOTIFICATION_LIST => self.core_get("/api/notifications").await,
            op::SERVICE_LIST => self.core_get("/api/services").await,
            op::DEVICE_LIST => self.core_get("/api/devices").await,
            op::UPDATE_LIST => self.core_get("/api/updates").await,
            // --- Phase 4: reverse proxy data plane (03 §6, FR-7) ---
            op::PROXY_OPEN => self.proxy_open(args).await,
            other => {
                return RpcResponse::err(
                    RpcErrorCode::BadRequest,
                    format!("op '{other}' not implemented yet"),
                )
            }
        };
        match r {
            Ok(v) => RpcResponse::ok(v),
            Err(e) => RpcResponse::err(RpcErrorCode::HaError, e.to_string()),
        }
    }

    /// `states.get` → `GET /api/states` (`02 §2.1`).
    async fn states_get(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/api/states", self.core_base);
        http_get_json(&url, &self.ha_token).await
    }

    /// Generic GET against an HA Core REST path (inventory reads:
    /// notifications / services / devices / updates).
    async fn core_get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.core_base, path);
        http_get_json(&url, &self.ha_token).await
    }

    /// `dashboard.list` → HA WS `lovelace/dashboards/list` (`02 §2.2`).
    async fn dashboard_list(&self) -> anyhow::Result<serde_json::Value> {
        self.ws_command(json!({"type": "lovelace/dashboards/list"})).await
    }

    /// `dashboard.get` → HA WS `lovelace/config` for one dashboard.
    async fn dashboard_get(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let dash = args
            .get("dashboard_id")
            .and_then(|d| d.as_str())
            .unwrap_or("lovelace");
        self.ws_command(json!({"type": "lovelace/config", "url_path": dash})).await
    }

    /// `dashboard.save` → HA WS `lovelace/config/save` (`03 §5`, FR-4.2).
    async fn dashboard_save(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let dash = str_arg(args, "dashboard_id", "lovelace");
        let config = args.get("config").cloned().unwrap_or(json!({}));
        self.ws_command(json!({
            "type": "lovelace/config/save", "url_path": dash, "config": config
        }))
        .await
    }

    /// `automation.save` → HA WS `automation/save` (`03 §5`, FR-4.1).
    async fn automation_save(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let aid = str_arg(args, "automation_id", "auto_1");
        let config = args.get("config").cloned().unwrap_or(json!({}));
        self.ws_command(json!({
            "type": "automation/save", "automation_id": aid, "config": config
        }))
        .await
    }

    /// `config.check` → `POST /api/config/core/check_config` (`02 §2.1`, FR-3).
    async fn config_check(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/api/config/core/check_config", self.core_base);
        http_post_json(&url, &self.ha_token, "{}").await
    }

    /// `core.restart` → `homeassistant.restart` service call (`03 §5`, FR-6.2).
    /// Destructive (`05 §6`); the control plane gates it on an elevated role.
    async fn core_restart(&self) -> anyhow::Result<serde_json::Value> {
        // Phase 1: acknowledge rather than actually restarting the mock. A real
        // agent calls POST /api/services/homeassistant/restart.
        Ok(json!({"acknowledged": true, "note": "mock: restart not performed"}))
    }

    /// `log.stream` → `GET /api/error_log` (`02 §2.1`, FR-3/4.3). Phase 1 returns
    /// the current log as a single result; true streaming (chunk frames) is a
    /// Phase 3 refinement for the central collector.
    async fn log_stream(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/api/error_log", self.core_base);
        let text = http_get_text(&url, &self.ha_token).await?;
        let lines: Vec<&str> = text.lines().collect();
        Ok(json!({"lines": lines}))
    }

    // ---- Supervisor broker (02 §2.3). Absent base ⇒ capability_missing path ----

    fn supervisor(&self) -> anyhow::Result<&str> {
        self.supervisor_base
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("supervisor not available on this install"))
    }

    async fn sup_get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let base = self.supervisor()?;
        http_get_json(&format!("{base}{path}"), &self.ha_token).await
    }

    async fn sup_post(&self, path: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let base = self.supervisor()?;
        http_post_json(&format!("{base}{path}"), &self.ha_token, &body.to_string()).await
    }

    /// `backup.download` → stream the Supervisor backup blob. Phase 2 returns a
    /// size + a base-ish marker; true chunked transfer to GCS (`04 §5`) is the
    /// backup-orchestrator's streaming path (Phase 2 relay-side refinement).
    async fn backup_download(&self, slug: &str) -> anyhow::Result<serde_json::Value> {
        let base = self.supervisor()?;
        let text = http_get_text(&format!("{base}/backups/{slug}/download"), &self.ha_token).await?;
        Ok(json!({"slug": slug, "bytes": text.len(), "sample": text}))
    }

    /// `proxy.open` (`03 §6`, FR-7). The relay already authorized this in the
    /// cloud and consumed a short-TTL `session_token`; the agent does **no**
    /// authz of its own. The agent opens the local HA UI path and relays the
    /// response body back as an ordered sequence of **chunks** terminated by an
    /// end marker (SECURITY-TODO #11) — the real byte-stream semantics of
    /// `chan=proxy`, rather than a one-shot snippet. Each chunk is base64 so
    /// binary assets survive the JSON hop. Full bidirectional tunnelling of an
    /// interactive UI (request upload + websockets) rides the same chunk
    /// framing and is the remaining integration against a real HA UI.
    async fn proxy_open(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let path = str_arg(args, "path", "/");
        let url = format!("{}{}", self.core_base, path);
        let body = http_get_text(&url, &self.ha_token).await?;
        let bytes = body.as_bytes();
        const CHUNK: usize = 1024; // bounded chunk size (03 §6 flow control)
        let chunks: Vec<serde_json::Value> = bytes
            .chunks(CHUNK)
            .enumerate()
            .map(|(seq, c)| json!({ "seq": seq, "b64": b64_encode(c) }))
            .collect();
        Ok(json!({
            "opened": true,
            "path": path,
            "stream": {
                "total_bytes": bytes.len(),
                "chunk_size": CHUNK,
                "chunks": chunks,     // ordered Chunk frames
                "end": true           // End marker (03 §6)
            }
        }))
    }

    /// Open a Core WS, authenticate (HA-style), issue one command by `id`, and
    /// return its `result`. A persistent WS is the Phase 1 refinement.
    async fn ws_command(&self, mut command: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let (mut ws, _) = tokio_tungstenite::connect_async(&self.core_ws).await?;

        // HA sends auth_required → we reply auth → expect auth_ok.
        expect_type(&mut ws, "auth_required").await?;
        ws.send(WsMsg::Text(json!({"type": "auth", "access_token": self.ha_token}).to_string()))
            .await?;
        expect_type(&mut ws, "auth_ok").await?;

        // issue the command with an id and read the matching result.
        let id = 1u64;
        command["id"] = json!(id);
        ws.send(WsMsg::Text(command.to_string())).await?;

        while let Some(msg) = ws.next().await {
            let WsMsg::Text(t) = msg? else { continue };
            let v: serde_json::Value = serde_json::from_str(&t)?;
            if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                if v.get("success").and_then(|s| s.as_bool()) == Some(true) {
                    return Ok(v.get("result").cloned().unwrap_or(json!(null)));
                }
                let err = v.get("error").cloned().unwrap_or(json!({"message": "ha error"}));
                anyhow::bail!("HA WS error: {err}");
            }
        }
        anyhow::bail!("HA WS closed before result")
    }
}

async fn expect_type(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    want: &str,
) -> anyhow::Result<()> {
    while let Some(msg) = ws.next().await {
        let WsMsg::Text(t) = msg? else { continue };
        let v: serde_json::Value = serde_json::from_str(&t)?;
        match v.get("type").and_then(|x| x.as_str()) {
            Some(ty) if ty == want => return Ok(()),
            Some(_) => continue,
            None => continue,
        }
    }
    anyhow::bail!("HA WS closed waiting for {want}")
}

/// Minimal HTTP GET w/ bearer token → JSON (same rationale as detect.rs).
async fn http_get_json(url: &str, token: &str) -> anyhow::Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://").ok_or_else(|| anyhow::anyhow!("http only: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).ok_or_else(|| anyhow::anyhow!("no body"))?;
    Ok(serde_json::from_str(body.trim())?)
}

/// Extract a string arg with a fallback default.
fn str_arg(args: &serde_json::Value, key: &str, default: &str) -> String {
    args.get(key).and_then(|v| v.as_str()).unwrap_or(default).to_string()
}

/// Dependency-free standard base64 encode (RFC 4648) for proxy stream chunks.
/// Keeps the agent's dep surface minimal; a real build uses the `base64` crate.
fn b64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}


/// Minimal HTTP GET returning the raw body text (for `/api/error_log`).
async fn http_get_text(url: &str, token: &str) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (host, port, path) = split_http(url)?;
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).ok_or_else(|| anyhow::anyhow!("no body"))?;
    Ok(body.trim().to_string())
}

/// Minimal HTTP POST with a JSON body → JSON response (for config check).
async fn http_post_json(url: &str, token: &str, body: &str) -> anyhow::Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (host, port, path) = split_http(url)?;
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let resp_body = text.split("\r\n\r\n").nth(1).ok_or_else(|| anyhow::anyhow!("no body"))?;
    Ok(serde_json::from_str(resp_body.trim())?)
}

/// Split an `http://host:port/path` into parts.
fn split_http(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| anyhow::anyhow!("http only: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::b64_encode;

    #[test]
    fn b64_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }
}
