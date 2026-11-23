//! The delegation-attenuation kernel: grants, the session model, the policy,
//! and every decision the guard makes. Pure: no files, sockets, environment or
//! clock. Callers pass `now`, supply the one external lookup (Claude Code's
//! sidecar) as a closure, and record the returned [`Fact`]s.
//!
//! Event entry points: [`pre_tool_use`], [`subagent_start`], [`subagent_stop`].
//! Each first runs session preparation (initialise the root grant, expire
//! stale pending spawns) and then applies the event's rules to the session.

mod bind;
mod conform;
mod decide;
pub mod duration;
pub mod fact;
pub mod grant;
mod lifecycle;
pub mod policy;
pub mod session;

use jiff::Timestamp;

pub use decide::{SidecarClaim, ToolCall, Verdict, pre_tool_use};
pub use fact::{Decision, Fact};
pub use lifecycle::{Start, subagent_start, subagent_stop};
pub use policy::{Policy, PolicyError, Profile, ValidPolicy};

/// Failures that stop the kernel from deciding at all. Callers fail closed.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    /// `now + root.ttl` is outside the representable time range.
    #[error("root grant expiry out of range: {0}")]
    RootExpiry(#[source] jiff::Error),
}

/// Go-style `%v` of a tool list: `[Glob Grep Read]`.
#[must_use]
pub fn tool_list(tools: &[String]) -> String {
    format!("[{}]", tools.join(" "))
}

/// RFC 3339 at second precision, UTC.
#[must_use]
pub fn rfc3339(timestamp: Timestamp) -> String {
    timestamp.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}
