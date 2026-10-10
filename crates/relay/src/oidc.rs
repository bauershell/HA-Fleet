//! Real OIDC authorization-code flow with PKCE (`04 §8`, SECURITY-TODO #13).
//!
//! Replaces the dev `/auth/login` stand-in with the genuine browser flow against
//! an OIDC provider (bundled Dex in dev; any compliant IdP in prod):
//!
//!   1. `GET /auth/start` — generate a PKCE verifier + `state`, stash them in a
//!      short-lived httpOnly cookie, 302 the browser to the IdP's authorize
//!      endpoint with the `code_challenge`.
//!   2. IdP authenticates the user and redirects back to
//!   3. `GET /auth/callback?code=…&state=…` — verify `state`, exchange the code
//!      (+ PKCE verifier) for tokens at the IdP's token endpoint, **verify the
//!      `id_token` JWT** against the IdP's JWKS (signature, `iss`, `aud`, `exp`),
//!      map its `groups` claim to an RBAC [`Role`], create a server-side session,
//!      and set the `hafm_session` httpOnly cookie.
//!
//! The id_token is cryptographically verified — a forged or expired token is
//! rejected. Config comes from `--oidc-*` flags / `OIDC_*` env.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::rbac::Role;
use crate::registry::now_ms;
use crate::AppState;

/// OIDC relying-party config (the relay is the RP).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Where the IdP redirects back to — must match the registered redirect URI.
    pub redirect_uri: String,
    /// Discovered from `${issuer}/.well-known/openid-configuration`.
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

impl OidcConfig {
    /// Fetch the IdP's discovery document and build the config. Called once at
    /// relay startup when `--oidc-issuer` is set; a failure here means OIDC is
    /// unavailable and the relay logs it + falls back to dev-auth.
    ///
    /// `issuer` is the value the IdP stamps into the id_token's `iss` and that
    /// we therefore VALIDATE against. `discovery_base`, when different, is the
    /// address the relay actually calls for discovery/token/JWKS — needed when
    /// the browser-facing issuer (e.g. `http://127.0.0.1:5556/dex`) is not the
    /// address reachable from inside the relay's container (e.g.
    /// `http://host.containers.internal:5556/dex`). The endpoints discovered
    /// from `discovery_base` are rewritten onto the reachable host so every
    /// back-channel call stays container-reachable, while `issuer` (used only
    /// for `iss` validation) keeps the browser-facing value.
    pub async fn discover(
        issuer: &str,
        discovery_base: Option<&str>,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> anyhow::Result<Self> {
        let issuer = issuer.trim_end_matches('/');
        let back = discovery_base.map(|b| b.trim_end_matches('/')).unwrap_or(issuer);
        let url = format!("{back}/.well-known/openid-configuration");
        let d: Discovery = reqwest::Client::new().get(&url).send().await?.error_for_status()?.json().await?;
        // Rewrite discovered endpoints from the issuer host to the reachable
        // back-channel host (no-op when they are the same).
        let fix = |ep: String| -> String {
            if back != issuer { ep.replacen(issuer, back, 1) } else { ep }
        };
        Ok(Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_uri: redirect_uri.to_string(),
            authorization_endpoint: d.authorization_endpoint, // browser-facing — keep issuer host
            token_endpoint: fix(d.token_endpoint),
            jwks_uri: fix(d.jwks_uri),
        })
    }
}

/// In-flight auth attempts (state → PKCE verifier), short TTL. Keyed by the
/// `state` nonce we also stash in the browser cookie, so the callback can only
/// complete a flow this relay actually started (CSRF defense).
#[derive(Default)]
pub struct AuthFlights {
    inner: Mutex<HashMap<String, Flight>>,
}
struct Flight {
    pkce_verifier: String,
    expires_at_ms: u64,
}
impl AuthFlights {
    pub fn new() -> Self {
        Self::default()
    }
    fn put(&self, state: &str, pkce_verifier: String) {
        let mut g = self.inner.lock().unwrap();
        g.retain(|_, f| f.expires_at_ms > now_ms());
        g.insert(state.to_string(), Flight { pkce_verifier, expires_at_ms: now_ms() + 10 * 60 * 1000 });
    }
    fn take(&self, state: &str) -> Option<String> {
        let mut g = self.inner.lock().unwrap();
        g.remove(state).filter(|f| f.expires_at_ms > now_ms()).map(|f| f.pkce_verifier)
    }
}

// --- PKCE + nonce helpers (dependency-light; uuid for entropy, sha256 from ca) -

fn random_token() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

/// base64url(no-pad) of raw bytes.
fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { out.push(T[((n >> 6) & 63) as usize] as char); }
        if chunk.len() > 2 { out.push(T[(n & 63) as usize] as char); }
    }
    out
}

/// S256 PKCE challenge = base64url(sha256(verifier)).
fn pkce_challenge(verifier: &str) -> String {
    b64url(&crate::ca::sha256_raw(verifier.as_bytes()))
}

// --- route handlers ---------------------------------------------------------

/// `GET /auth/start` — begin the auth-code+PKCE flow: 302 to the IdP.
pub async fn auth_start(State(st): State<AppState>) -> Response {
    let Some(cfg) = st.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "OIDC not configured; use dev-auth").into_response();
    };
    let state = random_token();
    let verifier = random_token();
    let challenge = pkce_challenge(&verifier);
    st.auth_flights.put(&state, verifier);

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        cfg.authorization_endpoint,
        urlencode(&cfg.client_id),
        urlencode(&cfg.redirect_uri),
        urlencode("openid email profile groups"),
        urlencode(&state),
        urlencode(&challenge),
    );
    // Stash `state` in a short-lived httpOnly cookie so the callback can bind the
    // redirect to this browser (CSRF). SameSite=Lax so it survives the IdP hop.
    let cookie = format!("hafm_oidc_state={state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600");
    ([(header::SET_COOKIE, cookie)], Redirect::to(&auth_url)).into_response()
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// Claims we read out of the verified id_token.
#[derive(Deserialize)]
struct IdClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

/// `GET /auth/callback` — complete the flow. Verifies state + PKCE, exchanges
/// the code, cryptographically verifies the id_token, maps groups → role, mints
/// the session cookie, and redirects to the SPA.
pub async fn auth_callback(State(st): State<AppState>, Query(q): Query<CallbackQuery>, headers: axum::http::HeaderMap) -> Response {
    let Some(cfg) = st.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "OIDC not configured").into_response();
    };
    if let Some(err) = q.error {
        return (StatusCode::BAD_REQUEST, format!("IdP error: {err}")).into_response();
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    // Bind the callback to the browser that started it (CSRF).
    let cookie_state = cookie_val(&headers, "hafm_oidc_state");
    if cookie_state.as_deref() != Some(state.as_str()) {
        return (StatusCode::BAD_REQUEST, "state mismatch").into_response();
    }
    let Some(verifier) = st.auth_flights.take(&state) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired auth flight").into_response();
    };

    // 1. Exchange the authorization code (+ PKCE verifier) for tokens.
    let tok: TokenResponse = match reqwest::Client::new()
        .post(&cfg.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &cfg.redirect_uri),
            ("client_id", &cfg.client_id),
            ("client_secret", &cfg.client_secret),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .and_then(|r| r.error_for_status())
    {
        Ok(r) => match r.json().await {
            Ok(j) => j,
            Err(e) => return (StatusCode::BAD_GATEWAY, format!("token parse: {e}")).into_response(),
        },
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("token exchange failed: {e}")).into_response(),
    };

    // 2. Verify the id_token JWT against the IdP's JWKS (sig + iss + aud + exp).
    let claims = match verify_id_token(cfg, &tok.id_token).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("id_token verification failed: {e}")).into_response(),
    };

    // 3. Authorization: map IdP groups → role, falling back to the email local
    //    part for IdPs that send no groups claim (dev Dex). No match → denied.
    let Some(role) = Role::resolve(&claims.groups, claims.email.as_deref()) else {
        return (StatusCode::FORBIDDEN, "no ha-fleet role granted by your IdP groups/email").into_response();
    };

    // 4. Mint the server-side session + set the httpOnly cookie.
    let token = st.sessions.create_with_role(&claims.sub, claims.email.clone(), role);
    st.audit
        .record(Some(claims.sub.clone()), None, "auth.oidc", serde_json::json!({"role": role.as_str()}), "ok", serde_json::json!({}))
        .await;
    let session_cookie = format!("hafm_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800");
    let clear_state = "hafm_oidc_state=; Path=/; HttpOnly; Max-Age=0".to_string();
    // AppendHeaders (not a plain array): two Set-Cookie entries must both be
    // emitted. A `[(SET_COOKIE, a), (SET_COOKIE, b)]` tuple inserts into a
    // HeaderMap and the second REPLACES the first, silently dropping the session.
    (
        axum::response::AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, clear_state),
        ]),
        Redirect::to("/"),
    )
        .into_response()
}

/// `GET /auth/me` — who the current session is (role-aware UI reads this).
pub async fn auth_me(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let token = cookie_val(&headers, "hafm_session").or_else(|| {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|a| a.to_str().ok())
            .and_then(|a| a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer ")))
            .map(String::from)
    });
    match token.and_then(|t| st.sessions.session(&t)) {
        Some(s) => axum::Json(serde_json::json!({
            "authenticated": true, "sub": s.oidc_sub, "email": s.email, "role": s.role.as_str()
        }))
        .into_response(),
        None => axum::Json(serde_json::json!({ "authenticated": false })).into_response(),
    }
}

/// `POST /auth/logout` — clear the session cookie.
pub async fn auth_logout() -> Response {
    let clear = "hafm_session=; Path=/; HttpOnly; Max-Age=0".to_string();
    ([(header::SET_COOKIE, clear)], axum::Json(serde_json::json!({ "ok": true }))).into_response()
}

// --- id_token verification (JWKS) -------------------------------------------

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kid: Option<String>,
    n: String,
    e: String,
    #[serde(default)]
    alg: Option<String>,
}

/// Verify the id_token's signature against the matching JWKS key, and its
/// `iss`/`aud`/`exp` claims. Returns the decoded claims on success.
async fn verify_id_token(cfg: &OidcConfig, id_token: &str) -> anyhow::Result<IdClaims> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(id_token)?;
    let jwks: Jwks = reqwest::Client::new().get(&cfg.jwks_uri).send().await?.error_for_status()?.json().await?;
    let jwk = jwks
        .keys
        .iter()
        .find(|k| header.kid.is_some() && k.kid == header.kid)
        .or_else(|| jwks.keys.first())
        .ok_or_else(|| anyhow::anyhow!("no matching JWKS key"))?;

    let alg = jwk
        .alg
        .as_deref()
        .and_then(|a| a.parse::<Algorithm>().ok())
        .unwrap_or(Algorithm::RS256);
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&cfg.issuer]);
    validation.set_audience(&[&cfg.client_id]);
    validation.validate_exp = true;

    let data = decode::<IdClaims>(id_token, &key, &validation)?;
    Ok(data.claims)
}

// --- small helpers ----------------------------------------------------------

fn cookie_val(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for kv in cookie.split(';') {
        let kv = kv.trim();
        if let Some(v) = kv.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// Minimal percent-encoding for query params (RFC 3986 unreserved kept).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_b64url_sha256() {
        // RFC 7636 appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(pkce_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn urlencode_escapes_reserved() {
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
        assert_eq!(urlencode("openid email"), "openid%20email");
    }
}
