//! Templater + push engine (`02 §1.3`, `03 §7`, `04 §3/4`).
//!
//! Stores versioned automation/dashboard templates, resolves assignments to a
//! set of instances, fans out `*.save` RPCs (bulk, FR-4), records a push job per
//! instance, then **reconciles** by reading the applied state back and computing
//! drift. Idempotent per `(template_version, instance)`.
//!
//! Phase 3 in-memory; `templates`/`template_versions`/`template_assignments`/
//! `push_jobs` (migrations/0004) are the Postgres targets.

use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateKind {
    Automation,
    Dashboard,
}

impl TemplateKind {
    /// The write op this template kind pushes with (`03 §5`).
    pub fn save_op(self) -> &'static str {
        match self {
            TemplateKind::Automation => hafm_proto::op::AUTOMATION_SAVE,
            TemplateKind::Dashboard => hafm_proto::op::DASHBOARD_SAVE,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Template {
    pub template_id: Uuid,
    pub kind: TemplateKind,
    pub name: String,
    /// version → body
    pub versions: Vec<TemplateVersion>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TemplateVersion {
    pub version: i32,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Sent,
    Reconciled,
    Drift,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PushJob {
    pub job_id: Uuid,
    pub template_id: Uuid,
    pub version: i32,
    pub instance_id: Uuid,
    pub idempotency_key: String,
    pub state: JobState,
    pub detail: serde_json::Value,
}

#[derive(Default)]
pub struct Templater {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    templates: HashMap<Uuid, Template>,
    jobs: Vec<PushJob>,
}

impl Templater {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a template with its first version. Returns the template id.
    pub fn create(&self, kind: TemplateKind, name: &str, body: serde_json::Value) -> Uuid {
        let mut g = self.inner.lock().unwrap();
        let template_id = Uuid::new_v4();
        g.templates.insert(
            template_id,
            Template {
                template_id,
                kind,
                name: name.to_string(),
                versions: vec![TemplateVersion { version: 1, body }],
            },
        );
        template_id
    }

    /// Append a new version; returns its number.
    pub fn add_version(&self, template_id: Uuid, body: serde_json::Value) -> Option<i32> {
        let mut g = self.inner.lock().unwrap();
        let t = g.templates.get_mut(&template_id)?;
        let next = t.versions.last().map(|v| v.version).unwrap_or(0) + 1;
        t.versions.push(TemplateVersion { version: next, body });
        Some(next)
    }

    pub fn get(&self, template_id: Uuid) -> Option<Template> {
        self.inner.lock().unwrap().templates.get(&template_id).cloned()
    }

    pub fn list(&self) -> Vec<Template> {
        self.inner.lock().unwrap().templates.values().cloned().collect()
    }

    /// Latest version body + number, for a push.
    pub fn latest(&self, template_id: Uuid) -> Option<(i32, serde_json::Value, TemplateKind, &'static str)> {
        let g = self.inner.lock().unwrap();
        let t = g.templates.get(&template_id)?;
        let v = t.versions.last()?;
        let op = t.kind.save_op();
        Some((v.version, v.body.clone(), t.kind, op))
    }

    /// Deterministic idempotency key per `(template_version, instance)` so a
    /// re-push of the same version is a no-op if already reconciled (`03 §7`).
    pub fn idem_key(template_id: Uuid, version: i32, instance_id: Uuid) -> String {
        format!("{template_id}:{version}:{instance_id}")
    }

    /// Record a push job (one per instance in the fan-out).
    pub fn record_job(
        &self,
        template_id: Uuid,
        version: i32,
        instance_id: Uuid,
        state: JobState,
        detail: serde_json::Value,
    ) -> Uuid {
        let mut g = self.inner.lock().unwrap();
        let job_id = Uuid::new_v4();
        g.jobs.push(PushJob {
            job_id,
            template_id,
            version,
            instance_id,
            idempotency_key: Self::idem_key(template_id, version, instance_id),
            state,
            detail,
        });
        job_id
    }

    pub fn jobs_for(&self, template_id: Uuid) -> Vec<PushJob> {
        self.inner
            .lock()
            .unwrap()
            .jobs
            .iter()
            .filter(|j| j.template_id == template_id)
            .cloned()
            .collect()
    }
}

// --- TemplateStore impl (in-memory default) ---------------------------------

#[async_trait::async_trait]
impl crate::store::TemplateStore for Templater {
    async fn create(&self, kind: TemplateKind, name: &str, body: serde_json::Value) -> Uuid {
        Templater::create(self, kind, name, body)
    }
    async fn add_version(&self, template_id: Uuid, body: serde_json::Value) -> Option<i32> {
        Templater::add_version(self, template_id, body)
    }
    async fn get(&self, template_id: Uuid) -> Option<Template> {
        Templater::get(self, template_id)
    }
    async fn list(&self) -> Vec<Template> {
        Templater::list(self)
    }
    async fn latest(
        &self,
        template_id: Uuid,
    ) -> Option<(i32, serde_json::Value, TemplateKind, &'static str)> {
        Templater::latest(self, template_id)
    }
    async fn record_job(
        &self,
        template_id: Uuid,
        version: i32,
        instance_id: Uuid,
        state: JobState,
        detail: serde_json::Value,
    ) -> Uuid {
        Templater::record_job(self, template_id, version, instance_id, state, detail)
    }
    async fn jobs_for(&self, template_id: Uuid) -> Vec<PushJob> {
        Templater::jobs_for(self, template_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_increment() {
        let t = Templater::new();
        let id = t.create(TemplateKind::Automation, "sunset", json!({"alias": "v1"}));
        assert_eq!(t.add_version(id, json!({"alias": "v2"})), Some(2));
        let (v, _, kind, op) = t.latest(id).unwrap();
        assert_eq!(v, 2);
        assert_eq!(kind, TemplateKind::Automation);
        assert_eq!(op, hafm_proto::op::AUTOMATION_SAVE);
    }

    #[test]
    fn idem_key_is_deterministic() {
        let tid = Uuid::nil();
        let iid = Uuid::nil();
        assert_eq!(Templater::idem_key(tid, 3, iid), Templater::idem_key(tid, 3, iid));
        assert_ne!(Templater::idem_key(tid, 3, iid), Templater::idem_key(tid, 4, iid));
    }
}
