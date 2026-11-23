//! Revocation on policy change: every issued grant is narrowed to what the
//! policy in force allows, before any decision is made with it.
//!
//! Runs on every event. For a grant that already fits the policy it changes
//! nothing and records nothing (a grant issued under a policy never exceeds
//! it), so no policy version needs to be tracked. It only ever narrows: a
//! wider policy applies to new sessions and new delegations, never to grants
//! already issued.
//!
//! Per grant, against its profile (`root` for the main thread):
//! tools ∩ profile.tools ∩ parent.tools, `Agent` removed at the leaf depth,
//! `max_calls` and `remaining` capped at `profile.max_calls`, expiry capped at
//! now + `profile.ttl` and at the parent's expiry. Revoked outright: no profile
//! for the type, depth beyond `max_depth`, or a revoked parent.

use jiff::{SignedDuration, Timestamp};

use crate::fact::{Decision, Fact};
use crate::grant::{Grant, SPAWN_TOOL, intersect};
use crate::lifecycle::refund;
use crate::policy::{Profile, ValidPolicy};
use crate::session::{MAIN_ACTOR, Session};
use crate::{rfc3339, tool_list};

pub(crate) fn conform(
    session: &mut Session,
    policy: &ValidPolicy,
    now: Timestamp,
    facts: &mut Vec<Fact>,
) {
    // Parents before children: a child is narrowed against its parent's new grant.
    let mut live: Vec<(i64, String)> = session
        .agents
        .iter()
        .filter(|(_, a)| !a.stopped && a.revoked.is_none())
        .map(|(id, a)| (a.grant.depth, id.clone()))
        .collect();
    live.sort();
    for (_, id) in live {
        conform_agent(session, policy, &id, now, facts);
    }
    conform_pending(session, policy, now, facts);
}

fn profile_for<'a>(policy: &'a ValidPolicy, id: &str, agent_type: &str) -> Option<&'a Profile> {
    if id == MAIN_ACTOR {
        Some(&policy.root)
    } else {
        policy.profiles.get(agent_type)
    }
}

/// `grant` narrowed to `profile`, `parent` and `max_depth`, or why it must go.
fn narrow(
    grant: &Grant,
    profile: &Profile,
    parent: Option<&Grant>,
    max_depth: i64,
    now: Timestamp,
) -> Result<Grant, String> {
    if grant.depth > max_depth {
        return Err(format!(
            "depth {} exceeds max_depth {max_depth}",
            grant.depth
        ));
    }
    let mut tools = intersect(&grant.tools, &profile.tools);
    if let Some(p) = parent {
        tools = intersect(&tools, &p.tools);
    }
    if grant.depth > 0 && grant.depth >= max_depth {
        tools.retain(|t| t != SPAWN_TOOL); // a leaf may not spawn
    }
    let mut expires_at = cap_expiry(grant.expires_at, now, profile.ttl);
    if let Some(p) = parent {
        expires_at = expires_at.min(p.expires_at);
    }
    Ok(Grant {
        tools,
        max_calls: grant.max_calls.min(profile.max_calls),
        expires_at,
        depth: grant.depth,
    })
}

fn cap_expiry(expires_at: Timestamp, now: Timestamp, ttl: SignedDuration) -> Timestamp {
    now.checked_add(ttl)
        .map_or(expires_at, |limit| expires_at.min(limit))
}

fn conform_agent(
    session: &mut Session,
    policy: &ValidPolicy,
    id: &str,
    now: Timestamp,
    facts: &mut Vec<Fact>,
) {
    let Some(agent) = session.agents.get(id) else {
        return;
    };
    let parent = session.agents.get(&agent.parent);
    let narrowed = if parent.is_some_and(|p| p.revoked.is_some()) {
        Err(format!("parent {:?} was revoked", agent.parent))
    } else {
        match profile_for(policy, id, &agent.agent_type) {
            None => Err(format!(
                "no profile for subagent_type {:?} in the policy in force",
                agent.agent_type
            )),
            Some(profile) => narrow(
                &agent.grant,
                profile,
                parent.map(|p| &p.grant),
                policy.max_depth,
                now,
            ),
        }
    };
    let Some(agent) = session.agents.get_mut(id) else {
        return;
    };
    let fact = |reason: String| {
        Fact::new("PolicyChange", id, Decision::Revoke)
            .agent_type(&agent.agent_type)
            .reason(reason)
    };
    match narrowed {
        Err(why) => {
            facts.push(fact(format!(
                "revoked: {why}; {} unused calls forfeited",
                agent.remaining
            )));
            agent.revoked = Some(why);
            agent.remaining = 0;
        }
        Ok(grant) => {
            let remaining = agent.remaining.min(grant.max_calls);
            let changes = describe(&agent.grant, &grant, agent.remaining, remaining);
            if !changes.is_empty() {
                facts.push(fact(format!("narrowed: {changes}")));
                agent.grant = grant;
                agent.remaining = remaining;
            }
        }
    }
}

/// Pending spawns are narrowed the same way, or dropped with their reservation
/// returned to the (still live) parent.
fn conform_pending(
    session: &mut Session,
    policy: &ValidPolicy,
    now: Timestamp,
    facts: &mut Vec<Fact>,
) {
    let mut kept = Vec::with_capacity(session.pending.len());
    for mut pending in std::mem::take(&mut session.pending) {
        let parent = session
            .agents
            .get(&pending.parent)
            .filter(|p| !p.stopped && p.revoked.is_none());
        let narrowed = match (parent, policy.profiles.get(&pending.agent_type)) {
            (None, _) => Err(format!(
                "spawner {:?} no longer holds a live grant",
                pending.parent
            )),
            (_, None) => Err(format!(
                "no profile for subagent_type {:?} in the policy in force",
                pending.agent_type
            )),
            (Some(p), Some(profile)) => narrow(
                &pending.grant,
                profile,
                Some(&p.grant),
                policy.max_depth,
                now,
            ),
        };
        let fact = Fact::new("PolicyChange", &pending.parent, Decision::Revoke)
            .agent_type(&pending.agent_type)
            .tool_use_id(&pending.tool_use_id);
        match narrowed {
            Err(why) => {
                refund(session, &pending.parent, pending.grant.max_calls);
                facts.push(fact.reason(format!("pending spawn dropped: {why}")));
            }
            Ok(grant) => {
                let changes = describe(
                    &pending.grant,
                    &grant,
                    pending.grant.max_calls,
                    grant.max_calls,
                );
                if !changes.is_empty() {
                    facts.push(fact.reason(format!("pending spawn narrowed: {changes}")));
                    pending.grant = grant;
                }
                kept.push(pending);
            }
        }
    }
    session.pending = kept;
}

/// What changed, empty if nothing did.
fn describe(old: &Grant, new: &Grant, old_remaining: i64, new_remaining: i64) -> String {
    let mut parts = Vec::new();
    if old.tools != new.tools {
        parts.push(format!(
            "tools {}→{}",
            tool_list(&old.tools),
            tool_list(&new.tools)
        ));
    }
    if old.max_calls != new.max_calls {
        parts.push(format!("max_calls {}→{}", old.max_calls, new.max_calls));
    }
    if old_remaining != new_remaining {
        parts.push(format!("remaining {old_remaining}→{new_remaining}"));
    }
    if old.expires_at != new.expires_at {
        parts.push(format!(
            "expires {}→{}",
            rfc3339(old.expires_at),
            rfc3339(new.expires_at)
        ));
    }
    parts.join("; ")
}
