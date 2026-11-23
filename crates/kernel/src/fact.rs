//! What the kernel decided, as facts for the evidence layer to record.

use serde::{Deserialize, Serialize};

/// What the guard decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Tool call allowed to proceed (to Claude Code's own permission checks).
    Pass,
    /// Tool call blocked.
    Deny,
    /// Reserved budget returned to a parent.
    Refund,
    /// Subagent seen starting; binding deferred.
    Start,
    /// Subagent matched no admitted spawn.
    Unbound,
    /// Subagent bound to an admitted spawn.
    Bind,
    /// Subagent stopped; grant closed.
    Close,
    /// An issued grant narrowed or revoked to fit the policy in force.
    Revoke,
}

/// One decision, without a timestamp (the caller owns the clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    /// Hook event (`PreToolUse`, `SubagentStart`, ...) or internal event.
    pub event: String,
    /// Actor the decision is about.
    pub actor: String,
    /// Subagent type, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_type: String,
    /// Tool name, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool: String,
    /// Claude Code's `tool_use_id`, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_use_id: String,
    /// The decision.
    pub decision: Decision,
    /// Human-readable reason or summary.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

impl Fact {
    /// A fact with the required fields; set the rest with the builder methods.
    #[must_use]
    pub fn new(event: &str, actor: &str, decision: Decision) -> Self {
        Fact {
            event: event.to_owned(),
            actor: actor.to_owned(),
            agent_type: String::new(),
            tool: String::new(),
            tool_use_id: String::new(),
            decision,
            reason: String::new(),
        }
    }

    /// Sets `agent_type`.
    #[must_use]
    pub fn agent_type(mut self, value: &str) -> Self {
        value.clone_into(&mut self.agent_type);
        self
    }

    /// Sets `tool`.
    #[must_use]
    pub fn tool(mut self, value: &str) -> Self {
        value.clone_into(&mut self.tool);
        self
    }

    /// Sets `tool_use_id`.
    #[must_use]
    pub fn tool_use_id(mut self, value: &str) -> Self {
        value.clone_into(&mut self.tool_use_id);
        self
    }

    /// Sets `reason`.
    #[must_use]
    pub fn reason(mut self, value: impl Into<String>) -> Self {
        self.reason = value.into();
        self
    }
}
