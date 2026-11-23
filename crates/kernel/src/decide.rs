//! `PreToolUse`: bind on first call (sidecar mode), then admit or deny the call.

use jiff::Timestamp;

use crate::bind::{SidecarBind, bind_fifo, bind_sidecar};
use crate::fact::{Decision, Fact};
use crate::grant::{Request, SPAWN_TOOL, attenuate};
use crate::lifecycle::prepare;
use crate::policy::ValidPolicy;
use crate::session::{Agent, MAIN_ACTOR, Pending, Session};
use crate::{KernelError, rfc3339, tool_list};

/// Claude Code's documented fallback when `subagent_type` is omitted.
pub const DEFAULT_SUBAGENT_TYPE: &str = "general-purpose";

/// One `PreToolUse` event, already decoded by the caller.
#[derive(Debug, Clone)]
pub struct ToolCall<'a> {
    /// Hook event name, recorded as is.
    pub event: &'a str,
    /// Empty for the main thread.
    pub agent_id: &'a str,
    /// Subagent type reported by Claude Code, if any.
    pub agent_type: &'a str,
    /// Tool being called.
    pub tool_name: &'a str,
    /// Claude Code's id for this call.
    pub tool_use_id: &'a str,
    /// For `Agent` calls: `tool_input.subagent_type` (empty if absent), or the
    /// reason it could not be read. Ignored for other tools.
    pub requested_type: Result<String, String>,
}

impl ToolCall<'_> {
    /// The actor key: `agent_id`, or [`MAIN_ACTOR`] when empty.
    #[must_use]
    pub fn actor(&self) -> &str {
        if self.agent_id.is_empty() {
            MAIN_ACTOR
        } else {
            self.agent_id
        }
    }
}

/// What Claude Code's metadata sidecar says about an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarClaim {
    /// `toolUseId`: the spawning `Agent` call.
    pub tool_use_id: String,
    /// `parentAgentId`: empty when the main thread spawned it.
    pub parent_agent_id: String,
    /// Where the claim was read, for the receipt.
    pub location: String,
}

/// The decision on one tool call, with the reason or pass summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Proceed (to Claude Code's own permission checks).
    Pass(String),
    /// Block.
    Deny(String),
}

impl Verdict {
    /// The reason (deny) or summary (pass).
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Pass(r) | Verdict::Deny(r) => r,
        }
    }
}

/// Decides one tool call and records it. `sidecar` is called at most once, only
/// when sidecar binding is on and the calling agent is not yet bound.
///
/// # Errors
///
/// [`KernelError`] if the session cannot be prepared; the caller must deny.
pub fn pre_tool_use(
    session: &mut Session,
    policy: &ValidPolicy,
    call: &ToolCall<'_>,
    sidecar: impl FnOnce() -> Option<SidecarClaim>,
    now: Timestamp,
    facts: &mut Vec<Fact>,
) -> Result<Verdict, KernelError> {
    let now = session.observe(now);
    prepare(session, policy, now, facts)?;
    let actor = call.actor();
    let verdict = match bind_on_first_call(session, policy, call, sidecar, facts) {
        Some(why) => Verdict::Deny(why),
        None => decide(session, policy, call, actor, now),
    };
    let decision = if matches!(verdict, Verdict::Pass(_)) {
        Decision::Pass
    } else {
        Decision::Deny
    };
    facts.push(
        Fact::new(call.event, actor, decision)
            .agent_type(call.agent_type)
            .tool(call.tool_name)
            .tool_use_id(call.tool_use_id)
            .reason(verdict.reason()),
    );
    Ok(verdict)
}

/// In sidecar mode an unbound subagent is bound at its first tool call.
/// Returns a deny reason if the sidecar contradicts what was admitted.
fn bind_on_first_call(
    session: &mut Session,
    policy: &ValidPolicy,
    call: &ToolCall<'_>,
    sidecar: impl FnOnce() -> Option<SidecarClaim>,
    facts: &mut Vec<Fact>,
) -> Option<String> {
    if !policy.sidecar_binding
        || call.agent_id.is_empty()
        || session.agents.contains_key(call.agent_id)
    {
        return None;
    }
    match bind_sidecar(session, call, sidecar(), facts) {
        SidecarBind::Bound => None,
        SidecarBind::Contradiction(why) => Some(why),
        SidecarBind::Absent => {
            bind_fifo(session, call.agent_id, call.agent_type, "Bind", facts);
            None
        }
    }
}

/// Why `agent` may not make this call at all, if it may not.
fn refusal(agent: &Agent, actor: &str, tool: &str, now: Timestamp) -> Option<String> {
    if let Some(why) = &agent.revoked {
        return Some(format!("grant for {actor:?} was revoked: {why}"));
    }
    if agent.stopped {
        return Some(format!("agent {actor:?} has stopped; its grant is closed"));
    }
    if agent.grant.expired(now) {
        return Some(format!(
            "grant for {actor:?} expired at {}",
            rfc3339(agent.grant.expires_at)
        ));
    }
    if !agent.grant.has(tool) {
        return Some(format!(
            "tool {tool:?} is not in the grant for {actor:?} {}",
            tool_list(&agent.grant.tools)
        ));
    }
    if agent.remaining <= 0 {
        return Some(format!(
            "budget for {actor:?} exhausted ({} calls)",
            agent.grant.max_calls
        ));
    }
    None
}

fn decide(
    session: &mut Session,
    policy: &ValidPolicy,
    call: &ToolCall<'_>,
    actor: &str,
    now: Timestamp,
) -> Verdict {
    let Some(agent) = session.agents.get_mut(actor) else {
        let tool = call.tool_name;
        return Verdict::Deny(format!(
            "agent {actor:?} has no admitted delegation (unbound subagent); denying {tool}"
        ));
    };
    if let Some(why) = refusal(agent, actor, call.tool_name, now) {
        return Verdict::Deny(why);
    }
    if call.tool_name != SPAWN_TOOL {
        agent.remaining -= 1;
        return Verdict::Pass(format!("remaining={}", agent.remaining));
    }
    match reserve_child(agent, policy, call, actor, now) {
        Ok((pending, summary)) => {
            session.pending.push(pending);
            Verdict::Pass(summary)
        }
        Err(why) => Verdict::Deny(why),
    }
}

/// For an `Agent` call: attenuates the child's grant from `agent`'s and
/// reserves its budget (plus one call for the spawn itself) from `agent`.
fn reserve_child(
    agent: &mut Agent,
    policy: &ValidPolicy,
    call: &ToolCall<'_>,
    actor: &str,
    now: Timestamp,
) -> Result<(Pending, String), String> {
    let subagent_type = match &call.requested_type {
        Ok(t) if t.is_empty() => DEFAULT_SUBAGENT_TYPE.to_owned(),
        Ok(t) => t.clone(),
        Err(e) => return Err(format!("cannot parse Agent tool_input: {e}")),
    };
    let Some(profile) = policy.profiles.get(&subagent_type) else {
        return Err(format!(
            "no delegation profile for subagent_type {subagent_type:?} (deny by default)"
        ));
    };
    let request = Request {
        tools: profile.tools.clone(),
        max_calls: profile.max_calls,
        ttl: profile.ttl,
    };
    // One call is spent on the Agent call itself; the child is funded from the rest.
    let child = attenuate(
        &agent.grant,
        agent.remaining - 1,
        &request,
        policy.max_depth,
        now,
    )
    .map_err(|e| format!("cannot delegate to {subagent_type:?}: {e}"))?;
    agent.remaining -= 1 + child.max_calls;
    let summary = format!(
        "reserved {} calls for {subagent_type}; tools={}; parent remaining={}",
        child.max_calls,
        tool_list(&child.tools),
        agent.remaining
    );
    let pending = Pending {
        parent: actor.to_owned(),
        agent_type: subagent_type,
        grant: child,
        tool_use_id: call.tool_use_id.to_owned(),
        created: now,
        cap: None,
    };
    Ok((pending, summary))
}
