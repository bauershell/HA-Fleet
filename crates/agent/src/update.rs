//! Agent self-update with A/B slots + watchdog rollback (`05 §5.2`, T5/T10).
//!
//! The agent is on the critical path (`02 §2.7`): a bad update can sever both
//! management and the reverse proxy. So `agent.update` is the most dangerous op
//! and gets the strongest controls, modeled here as a testable state machine:
//!
//!   1. verify the release **signature** against a pinned key (T10/T2);
//!   2. write the new binary to the **secondary slot** (active slot untouched);
//!   3. **flip** the `current` symlink to the secondary slot;
//!   4. **health gate**: re-establish tunnel + pass a probe within a deadline;
//!   5. on failure, **watchdog auto-rollback** — re-point `current` to the
//!      previous slot.
//!
//! Two layers:
//!   * [`SelfUpdater`] — the pure, unit-tested control state machine.
//!   * [`SlotLayout`] — a REAL filesystem A/B swap (SECURITY-TODO #12): writes
//!     the payload to `slots/<a|b>/agent`, flips a `current` symlink, and rolls
//!     the symlink back on a failed health gate. This is the actual swap
//!     mechanism; wiring it to a live systemd/add-on restart of the new binary
//!     is the final deploy-env integration.

use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum UpdateOutcome {
    /// Flip succeeded and the new slot passed the health gate.
    Applied { active: Slot, version: String },
    /// Health gate failed; watchdog rolled back to the previous slot.
    RolledBack { active: Slot, reason: String },
    /// Rejected before any flip (bad signature / too old).
    Rejected { reason: String },
}

/// The pinned trust root. Phase 5 uses a constant marker; the real agent pins a
/// release public key and verifies an actual signature (T10).
pub const PINNED_SIGNER: &str = "ha-fleet-release-key-v1";

/// Is `candidate` strictly newer than `current`? Compares dotted versions
/// field-by-field **numerically** (so `9.9.10` > `9.9.9`, which a string
/// compare gets wrong). A leading `v`/`V` is ignored. If any field is
/// non-numeric the comparison falls back to a lexical `str` compare for that
/// pair, so unusual tags still order deterministically.
pub fn version_gt(candidate: &str, current: &str) -> bool {
    fn parts(s: &str) -> impl Iterator<Item = &str> {
        s.trim_start_matches(['v', 'V']).split('.')
    }
    let (mut a, mut b) = (parts(candidate), parts(current));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return false, // equal
            (Some(_), None) => return true, // candidate has more fields => newer
            (None, Some(_)) => return false,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    _ => x.cmp(y),
                };
                match ord {
                    std::cmp::Ordering::Greater => return true,
                    std::cmp::Ordering::Less => return false,
                    std::cmp::Ordering::Equal => continue,
                }
            }
        }
    }
}

/// Pure control state machine for the A/B update decision (signature, version
/// floor, flip, health gate, rollback). Kept as the unit-tested reference core;
/// the live agent drives the on-disk [`SlotLayout`], which embeds the same
/// decision logic plus the real filesystem swap.
#[allow(dead_code)]
pub struct SelfUpdater {
    active: Slot,
    current_version: String,
}

/// Inputs describing an `agent.update` request (`03 §5` `agent.update`).
pub struct UpdateRequest<'a> {
    pub version: &'a str,
    pub signer: &'a str,
    /// Simulated health-probe result after the flip (true = tunnel + health ok).
    pub health_ok_after_flip: bool,
}

#[allow(dead_code)]
impl SelfUpdater {
    pub fn new(active: Slot, current_version: impl Into<String>) -> Self {
        Self { active, current_version: current_version.into() }
    }

    pub fn active(&self) -> Slot {
        self.active
    }
    pub fn version(&self) -> &str {
        &self.current_version
    }

    /// Run the full staged update. Mutates `active`/`current_version` only on a
    /// successful, health-gated flip; a failed flip rolls back and leaves the
    /// previous slot active — the fleet-safety guarantee.
    pub fn apply(&mut self, req: UpdateRequest<'_>) -> UpdateOutcome {
        // 1. signature verification (T10).
        if req.signer != PINNED_SIGNER {
            return UpdateOutcome::Rejected {
                reason: format!("signature not from pinned signer '{PINNED_SIGNER}'"),
            };
        }
        // 2. version floor: refuse a downgrade (version-floor, not force).
        if !version_gt(req.version, self.current_version.as_str()) {
            return UpdateOutcome::Rejected {
                reason: format!("version {} is not newer than {}", req.version, self.current_version),
            };
        }

        // 3. write to the secondary slot + 4. flip (simulated).
        let target = self.active.other();

        // 5. health gate on the flipped slot.
        if req.health_ok_after_flip {
            self.active = target;
            self.current_version = req.version.to_string();
            UpdateOutcome::Applied { active: target, version: req.version.to_string() }
        } else {
            // watchdog auto-rollback: active slot unchanged.
            UpdateOutcome::RolledBack {
                active: self.active,
                reason: "health gate failed after flip; watchdog rolled back".to_string(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Real A/B filesystem swap (SECURITY-TODO #12)
// ---------------------------------------------------------------------------

/// A real on-disk A/B slot layout under a root dir:
///   root/slots/a/agent, root/slots/b/agent   — the two binaries
///   root/current  (symlink → slots/<active>)  — what the supervisor runs
///
/// `apply` writes the payload to the INACTIVE slot, flips `current` to it, runs
/// the health gate, and on failure re-points `current` back — the actual swap +
/// rollback mechanics, not a simulation. A production deploy additionally asks
/// systemd / the add-on supervisor to restart from `current`; that restart is
/// the one piece still environment-specific.
pub struct SlotLayout {
    root: PathBuf,
    active: Slot,
    version: String,
}

impl SlotLayout {
    /// Initialize the layout: create slot dirs, write the current binary to slot
    /// A, and point `current` at it.
    pub fn init(root: impl AsRef<Path>, current_binary: &[u8], version: &str) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        for s in ["a", "b"] {
            std::fs::create_dir_all(root.join("slots").join(s))?;
        }
        std::fs::write(Self::slot_bin(&root, Slot::A), current_binary)?;
        Self::point_current(&root, Slot::A)?;
        Ok(Self { root, active: Slot::A, version: version.to_string() })
    }

    fn slot_dir(root: &Path, slot: Slot) -> PathBuf {
        root.join("slots").join(match slot {
            Slot::A => "a",
            Slot::B => "b",
        })
    }
    fn slot_bin(root: &Path, slot: Slot) -> PathBuf {
        Self::slot_dir(root, slot).join("agent")
    }

    /// (Re)point the `current` symlink at a slot atomically (write-new + rename).
    fn point_current(root: &Path, slot: Slot) -> std::io::Result<()> {
        let link = root.join("current");
        let tmp = root.join(".current.tmp");
        let target = Self::slot_dir(root, slot);
        let _ = std::fs::remove_file(&tmp);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &tmp)?;
        #[cfg(not(unix))]
        std::fs::write(&tmp, target.to_string_lossy().as_bytes())?;
        std::fs::rename(&tmp, &link)?; // atomic swap of the pointer
        Ok(())
    }

    /// The slot `current` currently points at (read back from the symlink).
    pub fn current_slot(&self) -> Slot {
        let link = self.root.join("current");
        match std::fs::read_link(&link) {
            Ok(p) if p.ends_with("b") => Slot::B,
            _ => Slot::A,
        }
    }

    pub fn active(&self) -> Slot {
        self.active
    }
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Perform the real swap. On a failed health gate the `current` symlink is
    /// restored to the previously-active slot — the fleet-safety guarantee, now
    /// enforced on disk.
    pub fn apply(
        &mut self,
        req: UpdateRequest<'_>,
        new_binary: &[u8],
    ) -> std::io::Result<UpdateOutcome> {
        if req.signer != PINNED_SIGNER {
            return Ok(UpdateOutcome::Rejected {
                reason: format!("signature not from pinned signer '{PINNED_SIGNER}'"),
            });
        }
        if !version_gt(req.version, self.version.as_str()) {
            return Ok(UpdateOutcome::Rejected {
                reason: format!("version {} is not newer than {}", req.version, self.version),
            });
        }
        let prev = self.active;
        let target = prev.other();

        // 2. write the new binary to the inactive slot (active untouched).
        std::fs::write(Self::slot_bin(&self.root, target), new_binary)?;
        // 3. flip the pointer.
        Self::point_current(&self.root, target)?;

        // 4/5. health gate + watchdog rollback.
        if req.health_ok_after_flip {
            self.active = target;
            self.version = req.version.to_string();
            Ok(UpdateOutcome::Applied { active: target, version: req.version.to_string() })
        } else {
            // roll the symlink back to the previous slot on disk.
            Self::point_current(&self.root, prev)?;
            Ok(UpdateOutcome::RolledBack {
                active: prev,
                reason: "health gate failed after flip; watchdog restored previous slot".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_gt_orders_numerically_not_lexically() {
        // the bug this guards: string compare makes "9.9.10" < "9.9.9".
        assert!(version_gt("9.9.10", "9.9.9"));
        assert!(version_gt("9.9.1791572975", "9.9.9"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(version_gt("v2.0.0", "1.9.9")); // leading v ignored
        assert!(version_gt("1.2.3.1", "1.2.3")); // extra field => newer
        assert!(!version_gt("9.9.9", "9.9.9")); // equal is not newer
        assert!(!version_gt("1.0.0", "1.0.1")); // older
        assert!(!version_gt("1.2.3", "1.2.3.1"));
    }

    #[test]
    fn healthy_update_flips_slot_and_bumps_version() {
        let mut u = SelfUpdater::new(Slot::A, "0.1.0");
        let out = u.apply(UpdateRequest { version: "0.2.0", signer: PINNED_SIGNER, health_ok_after_flip: true });
        assert_eq!(out, UpdateOutcome::Applied { active: Slot::B, version: "0.2.0".into() });
        assert_eq!(u.active(), Slot::B);
        assert_eq!(u.version(), "0.2.0");
    }

    #[test]
    fn failed_health_gate_rolls_back_and_keeps_old_slot() {
        let mut u = SelfUpdater::new(Slot::A, "0.1.0");
        let out = u.apply(UpdateRequest { version: "0.2.0", signer: PINNED_SIGNER, health_ok_after_flip: false });
        assert!(matches!(out, UpdateOutcome::RolledBack { active: Slot::A, .. }));
        // crucial: a bad update must NOT change the active slot or version.
        assert_eq!(u.active(), Slot::A);
        assert_eq!(u.version(), "0.1.0");
    }

    #[test]
    fn bad_signature_rejected_before_flip() {
        let mut u = SelfUpdater::new(Slot::A, "0.1.0");
        let out = u.apply(UpdateRequest { version: "0.2.0", signer: "attacker-key", health_ok_after_flip: true });
        assert!(matches!(out, UpdateOutcome::Rejected { .. }));
        assert_eq!(u.active(), Slot::A);
    }

    #[test]
    fn downgrade_rejected() {
        let mut u = SelfUpdater::new(Slot::B, "0.5.0");
        let out = u.apply(UpdateRequest { version: "0.4.0", signer: PINNED_SIGNER, health_ok_after_flip: true });
        assert!(matches!(out, UpdateOutcome::Rejected { .. }));
        assert_eq!(u.version(), "0.5.0");
    }

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hafm-slot-{tag}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn fs_swap_healthy_flips_symlink_on_disk() {
        let root = tmp_root("ok");
        let mut l = SlotLayout::init(&root, b"agent-v1", "0.1.0").unwrap();
        assert_eq!(l.current_slot(), Slot::A);
        let out = l
            .apply(
                UpdateRequest { version: "0.2.0", signer: PINNED_SIGNER, health_ok_after_flip: true },
                b"agent-v2",
            )
            .unwrap();
        assert_eq!(out, UpdateOutcome::Applied { active: Slot::B, version: "0.2.0".into() });
        assert_eq!(l.current_slot(), Slot::B); // symlink actually moved
        // the new binary is on disk in slot B
        assert_eq!(std::fs::read(root.join("slots/b/agent")).unwrap(), b"agent-v2");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fs_swap_failed_health_rolls_symlink_back() {
        let root = tmp_root("rollback");
        let mut l = SlotLayout::init(&root, b"agent-v1", "0.1.0").unwrap();
        let out = l
            .apply(
                UpdateRequest { version: "0.2.0", signer: PINNED_SIGNER, health_ok_after_flip: false },
                b"agent-v2-bad",
            )
            .unwrap();
        assert!(matches!(out, UpdateOutcome::RolledBack { active: Slot::A, .. }));
        // crucial: current points back at slot A on disk after rollback.
        assert_eq!(l.current_slot(), Slot::A);
        assert_eq!(l.active(), Slot::A);
        assert_eq!(l.version(), "0.1.0");
        std::fs::remove_dir_all(&root).ok();
    }
}
