//! Offline write queue + idempotency (`03 §8`, `NFR-OFF-2`).
//!
//! Writes to an **offline** instance are enqueued server-side and delivered in
//! order on reconnect; each carries an `idempotency_key` so a replay after a
//! half-delivered op is safe. Reads against an offline instance fail fast with
//! `instance_offline` (`NFR-OFF-3`) — they are never queued.
//!
//! Phase 1 is in-memory (mirrors `04 §4` `command_queue`); Postgres-backed
//! delivery with at-least-once + dedup is the Phase 1→persistence step.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueuedCommand {
    pub cmd_id: Uuid,
    pub instance_id: Uuid,
    pub op: String,
    pub args: serde_json::Value,
    pub idempotency_key: String,
    pub state: CmdState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CmdState {
    Queued,
    Sent,
    Applied,
    Failed,
}

#[derive(Default)]
pub struct CommandQueue {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Per-instance FIFO of queued commands.
    queues: HashMap<Uuid, VecDeque<QueuedCommand>>,
    /// Global idempotency-key set so a replay is a no-op (`NFR-OFF-2`).
    seen_keys: HashSet<String>,
}

impl CommandQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a write for later delivery. Returns `None` (no-op) if the
    /// idempotency key was already seen — the safe-replay guarantee.
    pub fn enqueue(
        &self,
        instance_id: Uuid,
        op: &str,
        args: serde_json::Value,
        idempotency_key: String,
    ) -> Option<Uuid> {
        let mut g = self.inner.lock().unwrap();
        if g.seen_keys.contains(&idempotency_key) {
            return None;
        }
        g.seen_keys.insert(idempotency_key.clone());
        let cmd_id = Uuid::new_v4();
        let cmd = QueuedCommand {
            cmd_id,
            instance_id,
            op: op.to_string(),
            args,
            idempotency_key,
            state: CmdState::Queued,
        };
        g.queues.entry(instance_id).or_default().push_back(cmd);
        Some(cmd_id)
    }

    /// Drain the queued commands for an instance in order (called on reconnect).
    pub fn drain(&self, instance_id: Uuid) -> Vec<QueuedCommand> {
        let mut g = self.inner.lock().unwrap();
        g.queues
            .remove(&instance_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// How many commands are queued for an instance (for status / tests).
    pub fn depth(&self, instance_id: Uuid) -> usize {
        self.inner
            .lock()
            .unwrap()
            .queues
            .get(&instance_id)
            .map(|q| q.len())
            .unwrap_or(0)
    }
}

// --- QueueStore impl (in-memory default) ------------------------------------

#[async_trait::async_trait]
impl crate::store::QueueStore for CommandQueue {
    async fn enqueue(
        &self,
        instance_id: Uuid,
        op: &str,
        args: serde_json::Value,
        idempotency_key: String,
    ) -> Option<Uuid> {
        CommandQueue::enqueue(self, instance_id, op, args, idempotency_key)
    }
    async fn drain(&self, instance_id: Uuid) -> Vec<QueuedCommand> {
        CommandQueue::drain(self, instance_id)
    }
    async fn depth(&self, instance_id: Uuid) -> usize {
        CommandQueue::depth(self, instance_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enqueue_then_drain_fifo() {
        let q = CommandQueue::new();
        let inst = Uuid::new_v4();
        q.enqueue(inst, "core.restart", json!({}), "k1".into());
        q.enqueue(inst, "automation.reload", json!({}), "k2".into());
        assert_eq!(q.depth(inst), 2);
        let drained = q.drain(inst);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].op, "core.restart"); // FIFO
        assert_eq!(q.depth(inst), 0);
    }

    #[test]
    fn duplicate_idempotency_key_is_noop() {
        let q = CommandQueue::new();
        let inst = Uuid::new_v4();
        assert!(q.enqueue(inst, "core.restart", json!({}), "same".into()).is_some());
        assert!(q.enqueue(inst, "core.restart", json!({}), "same".into()).is_none());
        assert_eq!(q.depth(inst), 1);
    }
}
