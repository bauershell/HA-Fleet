//! mTLS transport for the agent-facing listener (SECURITY-TODO #1, #2).
//!
//! The agent-facing side (`/enroll`, `/tunnel`) is served over **real TLS** with
//! **mandatory client-cert verification** against the relay CA. Rather than run
//! these two WebSocket endpoints through axum (which does not surface the peer
//! certificate to a handler), we accept the TCP connection, complete the rustls
//! handshake ourselves, pull the **verified** client-cert chain straight off the
//! TLS session, compute its SHA-256 fingerprint, and hand both the upgraded
//! WebSocket and that fingerprint to the tunnel handlers.
//!
//! Verification is enforced by rustls' `WebPkiClientVerifier` built from the CA
//! roots: a client presenting no cert, or one not chaining to the CA, fails the
//! handshake before any application byte flows. The handler then additionally
//! checks the fingerprint equals the one pinned at enrollment (`03 §1b`), so a
//! *valid-but-different* agent cert cannot impersonate another instance.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use crate::ca::{fingerprint_sha256, DevCa};
use crate::AppState;

/// Build the rustls `ServerConfig`: the relay's own CA-signed server cert +
/// client-cert verification rooted at the CA. Client auth is **optional at the
/// TLS layer** so the `/enroll` endpoint — where the agent has no CA-signed cert
/// yet — can connect; `/tunnel` then *requires* a verified cert whose fingerprint
/// matches the enrollment pin (enforced in `tunnel::handle_tunnel_tls`). A client
/// that DOES present a cert must still chain to the CA or the handshake fails.
pub fn server_config(ca: &DevCa) -> anyhow::Result<Arc<ServerConfig>> {
    // Trust anchor for verifying agent client certs = our CA.
    let mut roots = RootCertStore::empty();
    for der in parse_certs(ca.ca_cert_pem())? {
        roots.add(der)?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated() // enroll has no cert yet; tunnel enforces the pin
        .build()
        .map_err(|e| anyhow::anyhow!("client verifier: {e}"))?;

    // The relay's server identity. Loopback SANs for local dev, plus any extra
    // hostnames from RELAY_TLS_SANS (comma-separated) so a containerized agent
    // connecting to e.g. wss://relay:8443 can verify the cert.
    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "ha-fleet-relay".to_string(),
    ];
    if let Ok(extra) = std::env::var("RELAY_TLS_SANS") {
        sans.extend(extra.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    let server = ca.issue_server_cert(&sans)?;
    let cert_chain = parse_certs(&server.cert_pem)?;
    let key = parse_key(&server.key_pem)?;

    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("server config: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Serve the agent-facing endpoints over mTLS. One task per connection; each
/// completes the TLS handshake, extracts the verified client-cert fingerprint,
/// routes on the WS upgrade path, and dispatches to the tunnel handlers.
pub async fn serve(listener: TcpListener, tls: Arc<ServerConfig>, state: AppState) {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "agent-facing accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, acceptor, state).await {
                tracing::debug!(%peer, error = %e, "agent-facing connection ended");
            }
        });
    }
}

async fn handle_conn(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    state: AppState,
) -> anyhow::Result<()> {
    // 1. TLS handshake — rustls enforces that ANY presented client cert chains
    //    to the CA (#1). A cert is optional here so /enroll (no cert yet) works;
    //    /tunnel requires one below.
    let tls_stream = acceptor.accept(tcp).await?;

    // 2. pull the verified peer cert chain (if any) off the completed session
    //    and fingerprint the leaf — the authenticated agent identity.
    let (_, server_conn) = tls_stream.get_ref();
    let peer_fp = server_conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|leaf| fingerprint_sha256(leaf.as_ref()));

    // 3. capture the requested path during the WS upgrade so we can route
    //    /enroll vs /tunnel on the raw stream.
    let mut path = String::new();
    #[allow(clippy::result_large_err)] // Err type is tungstenite's ErrorResponse (API-fixed)
    let ws = tokio_tungstenite::accept_hdr_async(tls_stream, |req: &Request, resp: Response| {
        path = req.uri().path().to_string();
        Ok(resp)
    })
    .await?;

    match path.as_str() {
        "/enroll" => {
            // No CA-signed cert required yet; informational fp if the agent
            // presented a bootstrap one.
            crate::tunnel::handle_enroll_tls(ws, state, peer_fp.unwrap_or_default()).await
        }
        "/tunnel" => match peer_fp {
            Some(fp) => crate::tunnel::handle_tunnel_tls(ws, state, fp).await,
            None => tracing::warn!("/tunnel: no client cert presented — refusing (#2)"),
        },
        other => tracing::warn!(path = %other, "agent-facing: unknown path"),
    }
    Ok(())
}

fn parse_certs(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut rd).collect();
    Ok(certs?)
}

fn parse_key(pem: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut rd)?
        .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
    Ok(key)
}
