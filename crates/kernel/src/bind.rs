//! Attaching a subagent to the admitted spawn that funds it.

use std::collections::BTreeSet;

use crate::decide::{SidecarClaim, ToolCall};
use crate::fact::{Decision, Fact};
use crate::grant::Grant;
use crate::lifecycle::refund;
use crate::session::{Agent, BoundBy, MAIN_ACTOR, Session};
use crate::tool_list;

/// Result of trying the metadata sidecar.
pub(crate) enum SidecarBind {
    /// Bound exactly.
    Bound,
    /// No usable sidecar; fall back to [`bind_fifo`].
    Absent,
    /// The sidecar contradicts what the guard admitted: deny.
    Contradiction(String),
}

/// Binds `agent_id` to the oldest pending spawn of its type. When the
/// candidates come from more than one parent, the child gets the meet of all
/// candidate grants and the other candidates are capped the same way, because
/// the hook payloads alone do not say which `Agent` call created which agent.
/// Returns the bound grant, or `None` if no spawn of the type is pending.
pub(crate) fn bind_fifo(
    session: &mut Session,
    agent_id: &str,
    agent_type: &str,
    event: &str,
    facts: &mut Vec<Fact>,
) -> Option<Grant> {
    let candidates: Vec<usize> = (0..session.pending.len())
        .filter(|&i| session.pending[i].agent_type == agent_type)
        .collect();
    let Some(&first) = candidates.first() else {
        facts.push(
            Fact::new(event, agent_id, Decision::Unbound)
                .agent_type(agent_type)
                .reason("no admitted spawn of this type"),
        );
        return None;
    };
    let (grant, ambiguous) = resolve_grant(session, &candidates);
    let pending = session.pending.remove(first);
    refund(
        session,
        &pending.parent,
        pending.grant.max_calls - grant.max_calls,
    );
    let bound_by = if ambiguous {
        BoundBy::Meet
    } else {
        BoundBy::Fifo
    };
    session.agents.insert(
        agent_id.to_owned(),
        Agent {
            grant: grant.clone(),
            remaining: grant.max_calls,
            parent: pending.parent.clone(),
            agent_type: agent_type.to_owned(),
            ambiguous,
            bound_by: Some(bound_by),
            stopped: false,
            revoked: None,
        },
    );
    session.started.remove(agent_id);
    let reason = format!(
        "bound to parent {} by {bound_by}; tools={} budget={}",
        pending.parent,
        tool_list(&grant.tools),
        grant.max_calls
    );
    facts.push(
        Fact::new(event, agent_id, Decision::Bind)
            .agent_type(agent_type)
            .tool_use_id(&pending.tool_use_id)
            .reason(reason),
    );
    Some(grant)
}

/// The grant the first candidate's child gets, and whether it is ambiguous.
/// Caps every other candidate when the candidates have different parents.
fn resolve_grant(session: &mut Session, candidates: &[usize]) -> (Grant, bool) {
    let first = &session.pending[candidates[0]];
    let mut ambiguous = first.cap.is_some();
    let mut grant = first
        .cap
        .as_ref()
        .map_or_else(|| first.grant.clone(), |cap| first.grant.meet(cap));
    let parents: BTreeSet<&str> = candidates
        .iter()
        .map(|&i| session.pending[i].parent.as_str())
        .collect();
    if parents.len() > 1 {
        ambiguous = true;
        let meet = candidates[1..].iter().fold(first.grant.clone(), |acc, &i| {
            acc.meet(&session.pending[i].grant)
        });
        grant = grant.meet(&meet);
        for &i in &candidates[1..] {
            let capped = session.pending[i]
                .cap
                .as_ref()
                .map_or_else(|| meet.clone(), |cap| meet.meet(cap));
            session.pending[i].cap = Some(capped);
        }
    }
    (grant, ambiguous)
}

/// Binds the agent to the exact pending spawn the sidecar names, after
/// cross-checking type and parent.
pub(crate) fn bind_sidecar(
    session: &mut Session,
    call: &ToolCall<'_>,
    claim: Option<SidecarClaim>,
    facts: &mut Vec<Fact>,
) -> SidecarBind {
    let Some(claim) = claim.filter(|c| !c.tool_use_id.is_empty()) else {
        return SidecarBind::Absent;
    };
    match match_claim(session, call, &claim) {
        Ok(index) => {
            bind_exact(session, call.agent_id, index, &claim.location, facts);
            SidecarBind::Bound
        }
        Err(why) => SidecarBind::Contradiction(why),
    }
}

/// The pending spawn the claim names, or why the claim contradicts what was admitted.
fn match_claim(
    session: &Session,
    call: &ToolCall<'_>,
    claim: &SidecarClaim,
) -> Result<usize, String> {
    let id = call.agent_id;
    let Some(index) = session
        .pending
        .iter()
        .position(|p| p.tool_use_id == claim.tool_use_id)
    else {
        return Err(format!(
            "sidecar says {id:?} was spawned by Agent call {:?}, which delegate-guard never admitted",
            claim.tool_use_id
        ));
    };
    let pending = &session.pending[index];
    if !call.agent_type.is_empty() && pending.agent_type != call.agent_type {
        return Err(format!(
            "sidecar binds {id:?} to a {:?} spawn but the agent reports type {:?}",
            pending.agent_type, call.agent_type
        ));
    }
    let want_parent = if claim.parent_agent_id.is_empty() {
        MAIN_ACTOR
    } else {
        claim.parent_agent_id.as_str()
    };
    if pending.parent != want_parent {
        return Err(format!(
            "sidecar parent {want_parent:?} does not match the admitted spawner {:?}",
            pending.parent
        ));
    }
    Ok(index)
}

/// Moves pending spawn `index` to a bound agent `id` with exactly its grant.
fn bind_exact(
    session: &mut Session,
    id: &str,
    index: usize,
    location: &str,
    facts: &mut Vec<Fact>,
) {
    let pending = session.pending.remove(index);
    let reason = format!(
        "exact: sidecar {location} names Agent call {} by {}; tools={} budget={}",
        pending.tool_use_id,
        pending.parent,
        tool_list(&pending.grant.tools),
        pending.grant.max_calls
    );
    facts.push(
        Fact::new("Bind", id, Decision::Bind)
            .agent_type(&pending.agent_type)
            .tool_use_id(&pending.tool_use_id)
            .reason(reason),
    );
    session.agents.insert(
        id.to_owned(),
        Agent {
            remaining: pending.grant.max_calls,
            grant: pending.grant,
            parent: pending.parent,
            agent_type: pending.agent_type,
            bound_by: Some(BoundBy::Sidecar),
            ..Agent::default()
        },
    );
    session.started.remove(id);
}
