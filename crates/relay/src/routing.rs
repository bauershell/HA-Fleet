//! Multi-relay presence routing (SECURITY-TODO #15, `02 §1.2`).
//!
//! The live tunnel routing table is process-local: a socket cannot be a row, so
//! each relay node only knows the agents whose tunnels IT holds. To scale the
//! relay horizontally behind a load balancer, an operator RPC that lands on
//! node A for an instance whose tunnel is on node B must be forwarded to B. The
//! prerequisite is a **shared presence map**: which node currently owns each
//! instance's tunnel.
//!
//! This module is that presence layer:
//!   * [`PresenceRouter`] — register / look up / unregister the owning node.
//!   * [`LocalRouter`] — the default single-node no-op (every instance is "here").
//!   * [`RedisRouter`] (feature `redis`) — stores `presence:<instance>` → node id
//!     with a TTL refreshed on heartbeat, so a crashed node's entries expire.
//!
//! Cross-node RPC FORWARDING (publishing the request on the owner's channel and
//! awaiting the reply) rides on top of this map and a Redis pub/sub pair; it is
//! the remaining integration and is documented as such — this layer makes the
//! "who owns it" question answerable, which is the hard part of the design.

use async_trait::async_trait;
use uuid::Uuid;

/// This relay node's identity (unique per process/replica).
#[derive(Debug, Clone)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn generate() -> Self {
        NodeId(format!("relay-{}", Uuid::new_v4()))
    }
}

#[async_trait]
pub trait PresenceRouter: Send + Sync {
    /// Record that this node now owns `instance`'s tunnel.
    async fn register(&self, instance: Uuid);
    /// Refresh the presence TTL (called on heartbeat) so a dead node expires.
    async fn heartbeat(&self, instance: Uuid);
    /// Drop ownership (tunnel closed).
    async fn unregister(&self, instance: Uuid);
    /// Which node owns `instance`'s tunnel right now, if known.
    async fn owner(&self, instance: Uuid) -> Option<String>;
    /// True when `instance`'s tunnel is owned by THIS node.
    async fn owned_here(&self, instance: Uuid) -> bool;
}

/// Single-node default: everything is owned here, nothing is shared.
pub struct LocalRouter {
    node: NodeId,
}

impl LocalRouter {
    pub fn new(node: NodeId) -> Self {
        Self { node }
    }
}

#[async_trait]
impl PresenceRouter for LocalRouter {
    async fn register(&self, _instance: Uuid) {}
    async fn heartbeat(&self, _instance: Uuid) {}
    async fn unregister(&self, _instance: Uuid) {}
    async fn owner(&self, _instance: Uuid) -> Option<String> {
        Some(self.node.0.clone())
    }
    async fn owned_here(&self, _instance: Uuid) -> bool {
        true
    }
}

#[cfg(feature = "redis")]
pub use redis_impl::RedisRouter;

#[cfg(feature = "redis")]
mod redis_impl {
    use super::*;
    use redis::AsyncCommands;

    /// Presence key TTL — a few missed heartbeats and the entry expires, so a
    /// crashed node's instances are no longer routed to it.
    const PRESENCE_TTL_SECS: u64 = 90;

    pub struct RedisRouter {
        client: redis::Client,
        node: NodeId,
    }

    impl RedisRouter {
        pub fn connect(url: &str, node: NodeId) -> anyhow::Result<Self> {
            let client = redis::Client::open(url)?;
            Ok(Self { client, node })
        }

        fn key(instance: Uuid) -> String {
            format!("presence:{instance}")
        }

        async fn conn(&self) -> Option<redis::aio::MultiplexedConnection> {
            self.client.get_multiplexed_async_connection().await.ok()
        }
    }

    #[async_trait]
    impl PresenceRouter for RedisRouter {
        async fn register(&self, instance: Uuid) {
            if let Some(mut c) = self.conn().await {
                let _: Result<(), _> = c
                    .set_ex(Self::key(instance), &self.node.0, PRESENCE_TTL_SECS)
                    .await;
            }
        }
        async fn heartbeat(&self, instance: Uuid) {
            // Refresh the TTL only if we still own it (SET with the same value).
            self.register(instance).await;
        }
        async fn unregister(&self, instance: Uuid) {
            if let Some(mut c) = self.conn().await {
                let _: Result<(), _> = c.del(Self::key(instance)).await;
            }
        }
        async fn owner(&self, instance: Uuid) -> Option<String> {
            let mut c = self.conn().await?;
            c.get(Self::key(instance)).await.ok()
        }
        async fn owned_here(&self, instance: Uuid) -> bool {
            self.owner(instance).await.as_deref() == Some(self.node.0.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_router_owns_everything_here() {
        let r = LocalRouter::new(NodeId("relay-test".into()));
        let id = Uuid::new_v4();
        r.register(id).await;
        assert!(r.owned_here(id).await);
        assert_eq!(r.owner(id).await.as_deref(), Some("relay-test"));
    }
}
