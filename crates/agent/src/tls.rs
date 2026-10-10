//! Agent-side mTLS client transport (SECURITY-TODO #3, #6).
//!
//! * [`generate_keypair_and_csr`] makes a fresh keypair locally and a PKCS#10
//!   CSR for it — only the CSR (public half) is sent to the relay; the private
//!   key never leaves the box (#3).
//! * [`connector_enroll`] builds a TLS client that trusts the relay CA but
//!   presents **no** client cert (used once, during enrollment, before we have
//!   one).
//! * [`connector_tunnel`] builds a TLS client that trusts the relay CA **and
//!   presents the issued client cert** (#6), so the relay's mTLS verifier
//!   authenticates us on `/tunnel`.

use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Fresh keypair + CSR. Returns `(private_key_pem, csr_pem)`.
pub fn generate_keypair_and_csr(cn: &str) -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![cn.to_string()])?;
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn
    };
    let csr = params.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

fn roots_from_ca(ca_pem: &str) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut rd = std::io::BufReader::new(ca_pem.as_bytes());
    for der in rustls_pemfile::certs(&mut rd) {
        roots.add(der?)?;
    }
    Ok(roots)
}

/// TLS connector trusting the relay CA, presenting NO client cert (enrollment).
pub fn connector_enroll(ca_pem: &str) -> anyhow::Result<TlsConnector> {
    let roots = roots_from_ca(ca_pem)?;
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// TLS connector trusting the relay CA AND presenting the issued client cert +
/// key (steady-state tunnel; this is what makes it mutual TLS, #6).
pub fn connector_tunnel(
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> anyhow::Result<TlsConnector> {
    let roots = roots_from_ca(ca_pem)?;
    let mut cert_rd = std::io::BufReader::new(client_cert_pem.as_bytes());
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_rd).collect::<Result<_, _>>()?;
    let mut key_rd = std::io::BufReader::new(client_key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_rd)?
        .ok_or_else(|| anyhow::anyhow!("no client private key in identity"))?;
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// Parse `wss://host:port` → (`ServerName`, `host:port`) for TLS + TCP connect.
pub fn parse_wss(url: &str) -> anyhow::Result<(ServerName<'static>, String)> {
    let rest = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or_else(|| anyhow::anyhow!("relay url must be ws(s)://: {url}"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {host}"))?;
    Ok((server_name, authority.to_string()))
}
