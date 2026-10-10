//! Identity-aware proxy authorization (`05 §3`, `04 §2/§8`, FR-7).
//!
//! The cloud is the **only** authorization surface (`NFR-SEC-4`): a principal
//! must hold an explicit grant to an instance (default deny), and each proxy
//! session rides a **short-TTL, single-consume** token bound to
//! `(principal, instance, scope)`. The agent performs no authz of its own
//! (`03 §6`); it trusts the relay-minted token.
//!
//! Phase 4 is in-memory; `cp_instance_grants` (`04 §2`) + `proxy_tokens`
//! (`04 §8`) are the Postgres targets.

use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

use crate::registry::now_ms;

/// A grant: principal (or group) → instance, with a scope. Default deny means
/// the absence of a matching grant is a 403 (`05 §3`).
#[derive(Debug, Clone)]
pub struct Grant {
    pub principal: String,
    pub instance_id: Uuid,
    /// e.g. {"proxy": true, "read_only": true}
    pub scope: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyToken {
    pub token: String,
    pub principal: String,
    pub instance_id: Uuid,
    pub scope: serde_json::Value,
    pub expires_at_ms: u64,
    pub consumed: bool,
}

/// Default proxy-token TTL (short — a session opener, not a bearer credential).
pub const PROXY_TOKEN_TTL_MS: u64 = 30_000;

#[derive(Default)]
pub struct ProxyAuthz {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    grants: Vec<Grant>,
    tokens: HashMap<String, ProxyToken>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyAuthError {
    Denied,
    TokenUnknown,
    TokenExpired,
    TokenConsumed,
    TokenInstanceMismatch,
}

impl ProxyAuthz {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an explicit grant (operator admin action).
    pub fn grant(&self, principal: &str, instance_id: Uuid, scope: serde_json::Value) {
        self.inner.lock().unwrap().grants.push(Grant {
            principal: principal.to_string(),
            instance_id,
            scope,
        });
    }

    /// Authorize + mint a single-consume short-TTL token, or deny (`05 §3`).
    pub fn mint(&self, principal: &str, instance_id: Uuid) -> Result<ProxyToken, ProxyAuthError> {
        let mut g = self.inner.lock().unwrap();
        let grant = g
            .grants
            .iter()
            .find(|gr| {
                gr.principal == principal
                    && gr.instance_id == instance_id
                    && gr.scope.get("proxy").and_then(|p| p.as_bool()).unwrap_or(false)
            })
            .cloned();
        let Some(grant) = grant else {
            return Err(ProxyAuthError::Denied);
        };
        let token = Uuid::new_v4().to_string();
        let pt = ProxyToken {
            token: token.clone(),
            principal: principal.to_string(),
            instance_id,
            scope: grant.scope,
            expires_at_ms: now_ms() + PROXY_TOKEN_TTL_MS,
            consumed: false,
        };
        g.tokens.insert(token, pt.clone());
        Ok(pt)
    }

    /// Validate + consume a token for a given instance (the agent-open path).
    pub fn consume(&self, token: &str, instance_id: Uuid) -> Result<ProxyToken, ProxyAuthError> {
        let mut g = self.inner.lock().unwrap();
        let pt = g.tokens.get_mut(token).ok_or(ProxyAuthError::TokenUnknown)?;
        if pt.consumed {
            return Err(ProxyAuthError::TokenConsumed);
        }
        if now_ms() > pt.expires_at_ms {
            return Err(ProxyAuthError::TokenExpired);
        }
        if pt.instance_id != instance_id {
            return Err(ProxyAuthError::TokenInstanceMismatch);
        }
        pt.consumed = true;
        Ok(pt.clone())
    }
}

// --- ProxyStore impl (in-memory default) ------------------------------------

#[async_trait::async_trait]
impl crate::store::ProxyStore for ProxyAuthz {
    async fn grant(&self, principal: &str, instance_id: Uuid, scope: serde_json::Value) {
        ProxyAuthz::grant(self, principal, instance_id, scope)
    }
    async fn mint(
        &self,
        principal: &str,
        instance_id: Uuid,
    ) -> Result<ProxyToken, ProxyAuthError> {
        ProxyAuthz::mint(self, principal, instance_id)
    }
    async fn consume(
        &self,
        token: &str,
        instance_id: Uuid,
    ) -> Result<ProxyToken, ProxyAuthError> {
        ProxyAuthz::consume(self, token, instance_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_deny_without_grant() {
        let p = ProxyAuthz::new();
        let inst = Uuid::new_v4();
        assert_eq!(p.mint("alice", inst).unwrap_err(), ProxyAuthError::Denied);
    }

    #[test]
    fn grant_then_mint_then_single_consume() {
        let p = ProxyAuthz::new();
        let inst = Uuid::new_v4();
        p.grant("alice", inst, json!({"proxy": true}));
        let tok = p.mint("alice", inst).unwrap();
        assert!(!tok.consumed);
        // first consume ok
        assert!(p.consume(&tok.token, inst).is_ok());
        // second consume refused (single-use)
        assert_eq!(p.consume(&tok.token, inst).unwrap_err(), ProxyAuthError::TokenConsumed);
    }

    #[test]
    fn token_bound_to_instance() {
        let p = ProxyAuthz::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        p.grant("alice", a, json!({"proxy": true}));
        let tok = p.mint("alice", a).unwrap();
        assert_eq!(p.consume(&tok.token, b).unwrap_err(), ProxyAuthError::TokenInstanceMismatch);
    }

    #[test]
    fn grant_without_proxy_scope_denied() {
        let p = ProxyAuthz::new();
        let inst = Uuid::new_v4();
        p.grant("alice", inst, json!({"proxy": false}));
        assert_eq!(p.mint("alice", inst).unwrap_err(), ProxyAuthError::Denied);
    }
}
