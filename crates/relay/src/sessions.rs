//! Operator OIDC session store (`05 FR-5`, `04 §8`, SECURITY-TODO #13).
//!
//! The identity-aware proxy must derive its principal from a **verified
//! server-side session**, not from a client-asserted request-body field. This
//! module is the session layer: an operator authenticates (dev build: a stubbed
//! `/auth/login` that trusts a configured dev principal; production: the OIDC
//! authorization-code callback populates the same table), receives an opaque
//! session token, and presents it as `Authorization: Bearer <token>` on
//! subsequent calls. The proxy resolves the principal from the session, so the
//! client can no longer name an arbitrary principal.
//!
//! The token is stored **hashed** (`05 §4`), mirroring `oauth_sessions` and the
//! proxy-token handling. In-memory default; `oauth_sessions` (migrations/0005)
//! is the Postgres target.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::rbac::Role;
use crate::registry::now_ms;

/// Default operator session TTL (dev). Production uses the OIDC token lifetime.
pub const SESSION_TTL_MS: u64 = 8 * 3_600_000; // 8h

#[derive(Debug, Clone)]
pub struct Session {
    pub oidc_sub: String,
    pub email: Option<String>,
    /// Authorization role resolved from the IdP's group claims (RBAC).
    pub role: Role,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

#[derive(Default)]
pub struct SessionStore {
    /// token_hash → session.
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a session for an authenticated principal with a resolved role;
    /// returns the opaque token (plaintext, returned once) — only its hash is
    /// stored. Used by both the dev `/auth/login` and the OIDC callback.
    pub fn create_with_role(&self, oidc_sub: &str, email: Option<String>, role: Role) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let token_hash = crate::ca::fingerprint_sha256(token.as_bytes());
        self.inner.lock().unwrap().insert(
            token_hash,
            Session {
                oidc_sub: oidc_sub.to_string(),
                email,
                role,
                expires_at_ms: now_ms() + SESSION_TTL_MS,
                revoked: false,
            },
        );
        token
    }

    /// Back-compat convenience: a session with the default dev role (Admin, so
    /// the dev-auth path and `start.sh test` keep full access).
    pub fn create(&self, oidc_sub: &str) -> String {
        self.create_with_role(oidc_sub, None, Role::Admin)
    }

    /// Resolve a bearer token to its principal, enforcing expiry + revocation.
    pub fn principal(&self, token: &str) -> Option<String> {
        self.session(token).map(|s| s.oidc_sub)
    }

    /// Resolve a bearer token to its full session (principal + role), enforcing
    /// expiry + revocation. This is what the RBAC layer reads.
    pub fn session(&self, token: &str) -> Option<Session> {
        let token_hash = crate::ca::fingerprint_sha256(token.as_bytes());
        let g = self.inner.lock().unwrap();
        let s = g.get(&token_hash)?;
        if s.revoked || now_ms() > s.expires_at_ms {
            return None;
        }
        Some(s.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_resolves_principal() {
        let s = SessionStore::new();
        let tok = s.create("alice@corp");
        assert_eq!(s.principal(&tok).as_deref(), Some("alice@corp"));
        assert_eq!(s.principal("not-a-token"), None);
    }

    #[test]
    fn session_carries_role() {
        let s = SessionStore::new();
        let tok = s.create_with_role("bob@corp", Some("bob@corp".into()), Role::Operator);
        let sess = s.session(&tok).unwrap();
        assert_eq!(sess.role, Role::Operator);
        assert_eq!(sess.email.as_deref(), Some("bob@corp"));
        assert!(s.session("nope").is_none());
    }
}
