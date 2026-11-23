//! The session model: who holds which grant, and which spawns are pending.

use std::collections::BTreeMap;
use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::grant::Grant;

/// Key for the main conversation (hook input without `agent_id`).
pub const MAIN_ACTOR: &str = "main";

/// How a subagent was attached to the spawn that funds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BoundBy {
    /// Exact: Claude Code's metadata sidecar named the spawning `Agent` call.
    Sidecar,
    /// Oldest pending spawn of the type, single candidate parent.
    Fifo,
    /// Several candidate parents: bound to the meet of their grants.
    Meet,
}

impl fmt::Display for BoundBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BoundBy::Sidecar => "sidecar",
            BoundBy::Fifo => "fifo",
            BoundBy::Meet => "meet",
        })
    }
}

/// Live state of one actor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    /// Authority held.
    pub grant: Grant,
    /// Unspent budget (reservations for children already deducted).
    pub remaining: i64,
    /// Actor that funded this one; empty for the main thread.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent: String,
    /// Subagent type; empty for the main thread.
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub agent_type: String,
    /// Closed by `SubagentStop`; every further call is denied.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stopped: bool,
    /// Bound to the meet of several candidate parents.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ambiguous: bool,
    /// How the agent was bound; `None` for the main thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_by: Option<BoundBy>,
    /// Why the policy in force revoked this grant outright; every further call
    /// is denied. Distinct from `stopped`: nothing is refunded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_false(b: &bool) -> bool {
    !*b
}

/// A spawn that `PreToolUse(Agent)` admitted but no agent is bound to yet.
/// Its budget is already reserved from `parent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// Spawning actor.
    pub parent: String,
    /// Requested subagent type.
    #[serde(rename = "type")]
    pub agent_type: String,
    /// Grant reserved for the child.
    pub grant: Grant,
    /// `tool_use_id` of the spawning `Agent` call.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_use_id: String,
    /// When the spawn was admitted.
    pub created: Timestamp,
    /// Upper bound left by an earlier ambiguous binding of the same type:
    /// whoever binds this entry gets `grant.meet(cap)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<Grant>,
}

/// Everything the guard knows about one Claude Code session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Bound actors by id. Empty means a new session.
    #[serde(default)]
    pub agents: BTreeMap<String, Agent>,
    /// Admitted spawns not yet bound, oldest first.
    #[serde(default)]
    pub pending: Vec<Pending>,
    /// `agent_id` → type, seen at `SubagentStart` but not yet bound (sidecar mode).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub started: BTreeMap<String, String>,
    /// Latest time an event of this session was decided at. See [`Session::observe`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_decision: Option<Timestamp>,
}

impl Session {
    /// The time to decide an event at: `now`, or the last decision time if
    /// `now` is earlier. Events reach the session lock in any order, and their
    /// clocks are read before it, so a later decision can carry an older
    /// reading; the wall clock can also step back. A session's time never goes
    /// backwards, so grants never outlive what they would have, and an
    /// unchanged policy never looks narrower than the grants it issued.
    #[must_use = "decide at the returned time, not at `now`"]
    pub fn observe(&mut self, now: Timestamp) -> Timestamp {
        let at = self.last_decision.map_or(now, |last| last.max(now));
        self.last_decision = Some(at);
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observe_never_goes_backwards() {
        let t1: Timestamp = "2026-11-22T10:00:00.005Z".parse().unwrap();
        let t0: Timestamp = "2026-11-22T10:00:00Z".parse().unwrap();
        let t2: Timestamp = "2026-11-22T10:00:01Z".parse().unwrap();
        let mut s = Session::default();
        assert_eq!(s.observe(t1), t1);
        assert_eq!(s.observe(t0), t1, "an older reading is clamped");
        assert_eq!(s.observe(t2), t2, "a newer reading advances the clock");
        assert_eq!(s.last_decision, Some(t2));
    }
}
