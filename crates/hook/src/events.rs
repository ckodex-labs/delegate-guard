//! One function per hook event: state transaction around a kernel call.

use std::path::Path;

use delegate_guard_kernel::{
    self as kernel, Fact, SidecarClaim, Start, ToolCall, ValidPolicy, Verdict, rfc3339,
};
use delegate_guard_receipt::{self as receipt, Entry};
use delegate_guard_state as state;
use jiff::Timestamp;
use serde::Deserialize;

use crate::{HookError, Input, Outcome, find_sidecar_owned_by, nullable};

/// Processes one event. `dir` is the state directory; `now` is injected so
/// tests control time (the binary passes `Timestamp::now()`).
#[must_use]
pub fn handle(dir: &Path, policy: &ValidPolicy, input: &Input, now: Timestamp) -> Outcome {
    handle_as(dir, policy, input, now, None)
}

/// [`handle`] for a caller whose sidecar files must be owned by
/// `sidecar_owner` (a system daemon passes the peer's uid).
#[must_use]
pub fn handle_as(
    dir: &Path,
    policy: &ValidPolicy,
    input: &Input,
    now: Timestamp,
    sidecar_owner: Option<u32>,
) -> Outcome {
    match input.event.as_str() {
        "PreToolUse" => pre_tool_use(dir, policy, input, now, sidecar_owner),
        "SubagentStart" if !input.agent_id.is_empty() => subagent_start(dir, policy, input, now),
        "SubagentStop" if !input.agent_id.is_empty() => subagent_stop(dir, policy, input, now),
        _ => Outcome::pass(),
    }
}

fn record(receipts: &Path, now: Timestamp, facts: Vec<Fact>) -> Result<(), HookError> {
    for fact in facts {
        receipt::append(receipts, Entry::new(now, fact))?;
    }
    Ok(())
}

fn pre_tool_use(
    dir: &Path,
    policy: &ValidPolicy,
    input: &Input,
    now: Timestamp,
    sidecar_owner: Option<u32>,
) -> Outcome {
    let call = ToolCall {
        event: &input.event,
        agent_id: &input.agent_id,
        agent_type: &input.agent_type,
        tool_name: &input.tool_name,
        tool_use_id: &input.tool_use_id,
        requested_type: requested_type(&input.tool_input),
    };
    let lookup = || {
        find_sidecar_owned_by(
            &input.transcript_path,
            &input.session_id,
            &input.agent_id,
            sidecar_owner,
        )
        .map(|(sc, path)| SidecarClaim {
            tool_use_id: sc.tool_use_id,
            parent_agent_id: sc.parent_agent_id,
            location: path.display().to_string(),
        })
    };
    let result = state::with(
        dir,
        &input.session_id,
        |session, receipts| -> Result<Verdict, HookError> {
            let mut facts = Vec::new();
            let verdict = kernel::pre_tool_use(session, policy, &call, lookup, now, &mut facts)?;
            record(receipts, session.last_decision.unwrap_or(now), facts)?;
            Ok(verdict)
        },
    );
    match result {
        Ok(Verdict::Pass(_)) => Outcome::pass(),
        Ok(Verdict::Deny(why)) => Outcome::deny(&why),
        Err(e) => Outcome::deny(&format!("internal error, failing closed: {e}")),
    }
}

#[derive(Deserialize)]
struct SpawnInput {
    #[serde(default, deserialize_with = "nullable")]
    subagent_type: String,
}

/// `tool_input.subagent_type`, empty if absent, or why it cannot be read.
fn requested_type(tool_input: &serde_json::Value) -> Result<String, String> {
    if tool_input.is_null() {
        return Ok(String::new());
    }
    SpawnInput::deserialize(tool_input)
        .map(|s| s.subagent_type)
        .map_err(|e| e.to_string())
}

const DEFERRED: &str = "delegate-guard: your tool access is a delegated grant from the agent that spawned you, \
bound at your first tool call. Calls outside it are denied.";

fn subagent_start(dir: &Path, policy: &ValidPolicy, input: &Input, now: Timestamp) -> Outcome {
    let ids = (
        input.event.as_str(),
        input.agent_id.as_str(),
        input.agent_type.as_str(),
    );
    let result = state::with(
        dir,
        &input.session_id,
        |session, receipts| -> Result<Start, HookError> {
            let mut facts = Vec::new();
            let start = kernel::subagent_start(session, policy, ids, now, &mut facts)?;
            record(receipts, session.last_decision.unwrap_or(now), facts)?;
            Ok(start)
        },
    );
    // SubagentStart cannot block. An unbound agent is denied at its first
    // PreToolUse, so an error here still fails closed.
    match result {
        Ok(Start::AlreadyBound) => Outcome::pass(),
        Ok(Start::Deferred) => Outcome::context(DEFERRED),
        Ok(Start::Unbound) => Outcome::context(&format!(
            "delegate-guard: no admitted delegation matches this {:?} subagent. Every tool call you make will be denied.",
            input.agent_type
        )),
        Ok(Start::Bound(grant)) => Outcome::context(&format!(
            "delegate-guard: you hold a delegated grant. Tools: {}. Budget: {} tool calls. Expires: {}. Calls outside this grant are denied.",
            grant.tools.join(", "),
            grant.max_calls,
            rfc3339(grant.expires_at)
        )),
        Err(e) => Outcome::error(&format!("SubagentStart error: {e}")),
    }
}

fn subagent_stop(dir: &Path, policy: &ValidPolicy, input: &Input, now: Timestamp) -> Outcome {
    let ids = (
        input.event.as_str(),
        input.agent_id.as_str(),
        input.agent_type.as_str(),
    );
    let result = state::with(
        dir,
        &input.session_id,
        |session, receipts| -> Result<(), HookError> {
            let mut facts = Vec::new();
            kernel::subagent_stop(session, policy, ids, now, &mut facts)?;
            record(receipts, session.last_decision.unwrap_or(now), facts)
        },
    );
    // Never exit 2 here: that would keep the subagent running.
    match result {
        Ok(()) => Outcome::pass(),
        Err(e) => Outcome::error(&format!("SubagentStop error: {e}")),
    }
}
