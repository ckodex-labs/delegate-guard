//! Session preparation, pending expiry, and `SubagentStart` / `SubagentStop`.

use jiff::Timestamp;

use crate::KernelError;
use crate::bind::bind_fifo;
use crate::conform::conform;
use crate::fact::{Decision, Fact};
use crate::grant::{Grant, intersect};
use crate::policy::ValidPolicy;
use crate::session::{Agent, MAIN_ACTOR, Session};

/// Initialises a new session and expires stale pending spawns, refunding their
/// reserved budget to the parent.
pub(crate) fn prepare(
    session: &mut Session,
    policy: &ValidPolicy,
    now: Timestamp,
    facts: &mut Vec<Fact>,
) -> Result<(), KernelError> {
    if session.agents.is_empty() {
        let root = &policy.root;
        let grant = Grant {
            tools: intersect(&root.tools, &root.tools),
            max_calls: root.max_calls,
            expires_at: now.checked_add(root.ttl).map_err(KernelError::RootExpiry)?,
            depth: 0,
        };
        session.agents.insert(
            MAIN_ACTOR.to_owned(),
            Agent {
                grant,
                remaining: root.max_calls,
                ..Agent::default()
            },
        );
    }
    let (expired, kept) = std::mem::take(&mut session.pending)
        .into_iter()
        .partition::<Vec<_>, _>(|p| now.duration_since(p.created) > policy.pending_ttl);
    session.pending = kept;
    for pending in expired {
        refund(session, &pending.parent, pending.grant.max_calls);
        facts.push(
            Fact::new("PendingExpired", &pending.parent, Decision::Refund)
                .agent_type(&pending.agent_type)
                .tool_use_id(&pending.tool_use_id)
                .reason(format!("{} calls returned", pending.grant.max_calls)),
        );
    }
    conform(session, policy, now, facts);
    Ok(())
}

/// Returns `n` reserved calls to `parent`, unless it has stopped or been
/// revoked, never above the parent's (possibly narrowed) grant.
pub(crate) fn refund(session: &mut Session, parent: &str, n: i64) {
    if let Some(funder) = session.agents.get_mut(parent)
        && !funder.stopped
        && funder.revoked.is_none()
        && n > 0
    {
        funder.remaining = funder
            .remaining
            .saturating_add(n)
            .min(funder.grant.max_calls);
    }
}

/// What `SubagentStart` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// The agent was already bound; nothing changed.
    AlreadyBound,
    /// Sidecar mode: binding waits for the first tool call.
    Deferred,
    /// Bound to an admitted spawn.
    Bound(Grant),
    /// No admitted spawn of this type: every call it makes will be denied.
    Unbound,
}

/// Applies `SubagentStart` for `agent_id`.
///
/// # Errors
///
/// [`KernelError`] if the session cannot be prepared.
pub fn subagent_start(
    session: &mut Session,
    policy: &ValidPolicy,
    (event, agent_id, agent_type): (&str, &str, &str),
    now: Timestamp,
    facts: &mut Vec<Fact>,
) -> Result<Start, KernelError> {
    let now = session.observe(now);
    prepare(session, policy, now, facts)?;
    if session.agents.contains_key(agent_id) {
        return Ok(Start::AlreadyBound); // SubagentStart is idempotent
    }
    if policy.sidecar_binding {
        // Defer binding to the first PreToolUse, when Claude Code's
        // agent-<id>.meta.json sidecar names the exact spawning Agent call.
        session
            .started
            .insert(agent_id.to_owned(), agent_type.to_owned());
        facts.push(
            Fact::new(event, agent_id, Decision::Start)
                .agent_type(agent_type)
                .reason("binding deferred to first tool call (sidecar mode)"),
        );
        return Ok(Start::Deferred);
    }
    Ok(bind_fifo(session, agent_id, agent_type, event, facts).map_or(Start::Unbound, Start::Bound))
}

/// Applies `SubagentStop`: closes the agent and returns its unspent budget.
///
/// # Errors
///
/// [`KernelError`] if the session cannot be prepared.
pub fn subagent_stop(
    session: &mut Session,
    policy: &ValidPolicy,
    (event, agent_id, agent_type): (&str, &str, &str),
    now: Timestamp,
    facts: &mut Vec<Fact>,
) -> Result<(), KernelError> {
    let now = session.observe(now);
    prepare(session, policy, now, facts)?;
    let Some(agent) = session.agents.get_mut(agent_id).filter(|a| !a.stopped) else {
        return Ok(());
    };
    let (returned, parent) = (agent.remaining, agent.parent.clone());
    agent.stopped = true;
    agent.remaining = 0;
    refund(session, &parent, returned);
    facts.push(
        Fact::new(event, agent_id, Decision::Close)
            .agent_type(agent_type)
            .reason(format!("{returned} unused calls returned to {parent}")),
    );
    Ok(())
}
