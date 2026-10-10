//! Central log / notification collector (`02 §1.6`, `04 §6`, FR-4.3).
//!
//! Phase 3 pulls `log.stream` results on demand and stores parsed events in an
//! in-memory ring, queryable fleet-wide. A real collector ingests continuously
//! (chunk frames) with sampling/aggregation (`NFR-SCALE-3`) and cold-rolls to
//! GCS; this is the queryable hot store (`log_events`, migrations/0004).

use std::collections::VecDeque;
use std::sync::Mutex;
use uuid::Uuid;

use crate::registry::now_ms;

#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEvent {
    pub instance_id: Uuid,
    pub ts_ms: u64,
    pub level: String,
    pub source: String,
    pub message: String,
}

/// Bounded ring so a burst can't blow memory (`NFR-SCALE-3`).
const CAP: usize = 10_000;

#[derive(Default)]
pub struct LogCollector {
    inner: Mutex<VecDeque<LogEvent>>,
}

impl LogCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest raw HA error-log lines for an instance, parsing level + source.
    pub fn ingest_lines(&self, instance_id: Uuid, lines: &[String]) -> usize {
        let mut g = self.inner.lock().unwrap();
        let mut n = 0;
        for line in lines {
            let (level, source, message) = parse_line(line);
            if g.len() >= CAP {
                g.pop_front();
            }
            g.push_back(LogEvent { instance_id, ts_ms: now_ms(), level, source, message });
            n += 1;
        }
        n
    }

    /// Fleet-wide query, newest first, optional instance + substring filters.
    pub fn query(&self, instance_id: Option<Uuid>, contains: Option<&str>, limit: usize) -> Vec<LogEvent> {
        let g = self.inner.lock().unwrap();
        g.iter()
            .rev()
            .filter(|e| instance_id.is_none() || Some(e.instance_id) == instance_id)
            .filter(|e| contains.map(|c| e.message.contains(c)).unwrap_or(true))
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Parse an HA error-log line like
/// `2026-10-09 12:01:00 ERROR (MainThread) [component.bar] message`.
fn parse_line(line: &str) -> (String, String, String) {
    let level = ["ERROR", "WARNING", "CRITICAL", "INFO", "DEBUG"]
        .iter()
        .find(|lvl| line.contains(**lvl))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());
    let source = line
        .split('[')
        .nth(1)
        .and_then(|s| s.split(']').next())
        .unwrap_or("")
        .to_string();
    (level, source, line.to_string())
}

// --- CollectorStore impl (in-memory default) --------------------------------

#[async_trait::async_trait]
impl crate::store::CollectorStore for LogCollector {
    async fn ingest_lines(&self, instance_id: Uuid, lines: &[String]) -> usize {
        LogCollector::ingest_lines(self, instance_id, lines)
    }
    async fn query(
        &self,
        instance_id: Option<Uuid>,
        contains: Option<&str>,
        limit: usize,
    ) -> Vec<LogEvent> {
        LogCollector::query(self, instance_id, contains, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_level_and_source() {
        let (lvl, src, _) = parse_line("2026-10-09 12:01:00 ERROR (MainThread) [homeassistant.components.bar] connection refused");
        assert_eq!(lvl, "ERROR");
        assert_eq!(src, "homeassistant.components.bar");
    }

    #[test]
    fn ingest_and_fleet_query() {
        let c = LogCollector::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        c.ingest_lines(a, &["2026 ERROR [x] boom".to_string()]);
        c.ingest_lines(b, &["2026 WARNING [y] meh".to_string()]);
        assert_eq!(c.query(None, None, 10).len(), 2);
        assert_eq!(c.query(Some(a), None, 10).len(), 1);
        assert_eq!(c.query(None, Some("boom"), 10).len(), 1);
    }
}
