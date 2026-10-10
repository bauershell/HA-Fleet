//! Role-based access control (`05 §6`, `04 §8`).
//!
//! OIDC gives us *authentication* (a verified `sub` + group claims); this module
//! is *authorization*. A [`Role`] is resolved from the IdP's group claims at
//! login and stored on the session. Each operator endpoint declares a minimum
//! role; the [`Operator`] / [`Admin`] extractors enforce it and reject with 401
//! (no/invalid session) or 403 (insufficient role) before the handler runs.
//!
//! Three roles, totally ordered by privilege:
//!   - **Viewer**   — read-only (instances, states, logs, audit).
//!   - **Operator** — Viewer + non-destructive writes (dashboard/template push,
//!     backup create, user create, proxy open).
//!   - **Admin**    — Operator + destructive ops (restart, backup restore, user
//!     delete, revoke, cert rotation, grant management).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer = 0,
    Operator = 1,
    Admin = 2,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// Resolve the highest role granted by a set of IdP group claims.
    /// Convention (any IdP with group claims — LDAP/SAML/OIDC): group names
    /// `ha-fleet-admin` / `ha-fleet-operator` / `ha-fleet-viewer` (or the bare
    /// `admin` / `operator` / `viewer`). Unknown groups grant nothing.
    pub fn from_groups(groups: &[String]) -> Option<Role> {
        let mut best: Option<Role> = None;
        for g in groups {
            let r = match g.rsplit('-').next().unwrap_or(g.as_str()) {
                "admin" => Some(Role::Admin),
                "operator" => Some(Role::Operator),
                "viewer" => Some(Role::Viewer),
                _ => None,
            };
            if let Some(r) = r {
                best = Some(best.map_or(r, |b| b.max(r)));
            }
        }
        best
    }

    /// Dev fallback when the IdP sends no `groups` claim (e.g. Dex's static
    /// password DB only emits `email`). The role is taken from the email local
    /// part: `admin@…` / `operator@…` / `viewer@…`. Production uses real groups
    /// and never reaches this; it exists so the bundled dev IdP can demo all
    /// three roles with password login.
    pub fn from_email(email: &str) -> Option<Role> {
        let local = email.split('@').next().unwrap_or(email);
        match local {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }

    /// Resolve a role from the verified claims: groups first (real IdP), then
    /// the email fallback (dev Dex). None → no ha-fleet access.
    pub fn resolve(groups: &[String], email: Option<&str>) -> Option<Role> {
        Self::from_groups(groups).or_else(|| email.and_then(Self::from_email))
    }
}

/// The authenticated caller resolved from the request's session (cookie
/// `hafm_session` or `Authorization: Bearer`). Handlers take this as an
/// extractor to read the principal/role without re-parsing the header.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: String,
    pub role: Role,
}

fn deny(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Pull the session token from the `hafm_session` cookie first (browser flow),
/// then fall back to `Authorization: Bearer` (CLI / curl / dev-auth).
fn token_from_parts(parts: &Parts) -> Option<String> {
    if let Some(cookie) = parts.headers.get(axum::http::header::COOKIE).and_then(|c| c.to_str().ok()) {
        for kv in cookie.split(';') {
            let kv = kv.trim();
            if let Some(v) = kv.strip_prefix("hafm_session=") {
                return Some(v.to_string());
            }
        }
    }
    let auth = parts.headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")).map(|s| s.to_string())
}

/// Resolve a `Caller` from the request, or `None` when there is no valid
/// session. Dev-auth is still honored because it mints a real session too.
fn caller_from_parts(parts: &Parts, st: &AppState) -> Option<Caller> {
    let token = token_from_parts(parts)?;
    let sess = st.sessions.session(&token)?;
    Some(Caller { principal: sess.oidc_sub, role: sess.role })
}

// --- extractors: one per minimum role --------------------------------------

macro_rules! role_extractor {
    ($name:ident, $min:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name(#[allow(dead_code)] pub Caller);

        #[async_trait::async_trait]
        impl FromRequestParts<AppState> for $name {
            type Rejection = Response;
            async fn from_request_parts(
                parts: &mut Parts,
                st: &AppState,
            ) -> Result<Self, Self::Rejection> {
                let Some(caller) = caller_from_parts(parts, st) else {
                    return Err(deny(StatusCode::UNAUTHORIZED, "no valid operator session; log in first"));
                };
                if caller.role < $min {
                    return Err(deny(
                        StatusCode::FORBIDDEN,
                        concat!("insufficient role — requires ", stringify!($min)),
                    ));
                }
                Ok($name(caller))
            }
        }
    };
}

role_extractor!(ViewerAuth, Role::Viewer, "Requires at least the Viewer role (any authenticated user).");
role_extractor!(OperatorAuth, Role::Operator, "Requires at least the Operator role.");
role_extractor!(AdminAuth, Role::Admin, "Requires the Admin role (destructive ops).");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ordering() {
        assert!(Role::Admin > Role::Operator);
        assert!(Role::Operator > Role::Viewer);
    }

    #[test]
    fn groups_map_to_highest_role() {
        assert_eq!(Role::from_groups(&["ha-fleet-viewer".into()]), Some(Role::Viewer));
        assert_eq!(Role::from_groups(&["admin".into()]), Some(Role::Admin));
        // highest wins when several map
        assert_eq!(
            Role::from_groups(&["ha-fleet-viewer".into(), "ha-fleet-admin".into()]),
            Some(Role::Admin)
        );
        // unknown groups grant nothing
        assert_eq!(Role::from_groups(&["random-group".into()]), None);
        assert_eq!(Role::from_groups(&[]), None);
    }
}
