//! Capability detection (`02 §2.4`) and the local identity store.
//!
//! Phase 0 detects capabilities by probing the (mock) HA Core: a reachable
//! `/api/` + WS means the `core.*` set; a reachable Supervisor socket would add
//! `supervisor.*`. The mock has no Supervisor, so a Container-style set results.
//!
//! The identity store persists the agent's enrollment result (instance_id +
//! issued cert) to disk so steady-state reconnects (`03 §1b`) don't re-enroll.

use hafm_proto::{Capability, InstallType};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// What capability detection concluded about the local HA.
#[derive(Debug, Clone)]
pub struct Detected {
    pub install_type: InstallType,
    pub ha_version: Option<String>,
    pub capabilities: Vec<Capability>,
}

/// Probe the local HA Core over REST to decide install type + capabilities.
///
/// `core_base` is e.g. `http://127.0.0.1:8123`. Phase 0 treats a reachable Core
/// with no Supervisor as a `Container` install (the common no-Supervisor case).
pub async fn detect(core_base: &str) -> anyhow::Result<Detected> {
    let config_url = format!("{core_base}/api/config");
    let body = http_get_json(&config_url).await?;
    let ha_version = body
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Supervisor presence check: real agents look for the SUPERVISOR_TOKEN env
    // + the `http://supervisor` socket (`02 §2.3`). The mock exposes neither.
    let has_supervisor = std::env::var("SUPERVISOR_TOKEN").is_ok();
    let install_type = if has_supervisor { InstallType::Haos } else { InstallType::Container };

    // Core capabilities: everything the Core REST/WS surface backs (`03 §3`).
    let mut capabilities = vec![
        Capability::CoreStates,
        Capability::CoreServices,
        Capability::CoreLovelace,
        Capability::CoreAutomation,
        Capability::CoreErrorlog,
        Capability::CoreHealth,
        Capability::ProxyHttp,
    ];
    // `core.users` requires auth scope in real HA; advertise it only when the
    // probe says the auth component is present. Mock reports it via components.
    if body
        .get("components")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().any(|v| v.as_str() == Some("websocket_api")))
        .unwrap_or(false)
    {
        capabilities.push(Capability::CoreUsers);
    }
    if install_type.has_supervisor() {
        capabilities.extend([
            Capability::SupervisorBackup,
            Capability::SupervisorUpdate,
            Capability::SupervisorAddons,
            Capability::SupervisorHost,
            Capability::SupervisorLogs,
        ]);
    }

    Ok(Detected { install_type, ha_version, capabilities })
}

/// A tiny dependency-light HTTP GET returning parsed JSON. Phase 0 uses the
/// `tungstenite`/`tokio` stack already present and avoids pulling in a full HTTP
/// client; it only needs to hit the loopback mock. Real agents use `reqwest`.
async fn http_get_json(url: &str) -> anyhow::Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (host, port, path) = parse_url(url)?;
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no HTTP body from {url}"))?;
    Ok(serde_json::from_str(body.trim())?)
}

/// Minimal HTTP POST with a JSON body, returning the raw response body text.
/// Used for the self-provision bootstrap call (`05 §2.1`, SECURITY-TODO #8).
pub async fn http_post_text(url: &str, body: &str) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (host, port, path) = parse_url(url)?;
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let resp_body = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no HTTP body from {url}"))?;
    Ok(resp_body.trim().to_string())
}

fn parse_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// supported in Phase 0 probe: {url}"))?;
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

// --------------------------- identity store --------------------------------

/// Persisted enrollment identity (`03 §1a` result → `05 §2.4`). The private key
/// is generated locally at enrollment and **never leaves the box** (SECURITY-TODO
/// #3): only the CSR (public half) is sent to the relay. We store the private key
/// PEM, the CA-signed client cert, and the relay CA (to verify the relay server).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub instance_id: Uuid,
    /// PKCS#8 private key PEM — generated locally, never transmitted.
    pub client_key_pem: String,
    pub client_cert_pem: String,
    pub relay_ca_pem: String,
    /// The dedicated least-privilege HA token self-provisioned at first run
    /// (`05 §2.1`, SECURITY-TODO #8). `None` ⇒ fall back to the --ha-token dev
    /// default (test harness). The owner credential used to mint it is NEVER
    /// stored here.
    #[serde(default)]
    pub ha_token: Option<String>,
}

impl Identity {
    pub fn store_path(dir: &Path) -> PathBuf {
        dir.join("identity.json")
    }

    pub fn load(dir: &Path) -> anyhow::Result<Option<Self>> {
        let p = Self::store_path(dir);
        if !p.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(p)?;
        Ok(Some(serde_json::from_str(&s)?))
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let p = Self::store_path(dir);
        std::fs::write(p, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_splits_host_port_path() {
        let (h, p, path) = parse_url("http://127.0.0.1:8123/api/config").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8123);
        assert_eq!(path, "/api/config");
    }

    #[test]
    fn identity_round_trips(/* uses a temp dir under env TMPDIR */) {
        let dir = std::env::temp_dir().join(format!("hafm-id-{}", Uuid::new_v4()));
        let id = Identity {
            instance_id: Uuid::new_v4(),
            client_key_pem: "KEY".into(),
            client_cert_pem: "CERT".into(),
            relay_ca_pem: "CA".into(),
            ha_token: Some("llt".into()),
        };
        id.save(&dir).unwrap();
        let back = Identity::load(&dir).unwrap().unwrap();
        assert_eq!(back.instance_id, id.instance_id);
        std::fs::remove_dir_all(&dir).ok();
    }
}
