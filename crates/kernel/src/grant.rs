//! Delegation attenuation: deriving a child grant from a parent grant such
//! that the child can never hold more than the parent.
//!
//! Invariants enforced by [`attenuate`] (and checked by the property test):
//!
//! ```text
//! child.tools      ⊆ parent.tools
//! child.max_calls  ≤ parent remaining budget  (reserved from the parent, never copied)
//! child.expires_at ≤ parent.expires_at
//! child.depth      = parent.depth + 1 ≤ max_depth
//! "Agent" ∈ child.tools ⟹ child.depth < max_depth
//! ```
//!
//! Pure: no I/O, no clock. Callers pass `now`.

use std::collections::BTreeSet;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

/// The Claude Code tool that creates subagents (renamed from `Task` in Claude
/// Code 2.1.63; see code.claude.com/docs/en/sub-agents).
pub const SPAWN_TOOL: &str = "Agent";

/// The authority held by one actor (the main thread or a subagent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Tools the actor may call, sorted and de-duplicated. Exact names, no wildcards.
    pub tools: Vec<String>,
    /// Tool-call budget this grant was issued with.
    pub max_calls: i64,
    /// The grant is invalid at and after this instant.
    pub expires_at: Timestamp,
    /// Delegation depth: 0 for the main thread.
    pub depth: i64,
}

/// What a delegation profile asks for on behalf of a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Tools asked for; the child gets their intersection with the parent's.
    pub tools: Vec<String>,
    /// Budget asked for; capped by the parent's remaining budget.
    pub max_calls: i64,
    /// Lifetime asked for; capped by the parent's expiry.
    pub ttl: SignedDuration,
}

/// Why a delegation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttenuateError {
    /// The request names no tools.
    #[error("delegation request lists no tools (deny by default)")]
    NoTools,
    /// Nothing is left after intersecting with the parent (and removing `Agent` at a leaf).
    #[error("requested tools do not intersect the parent's tools")]
    EmptyGrant,
    /// The parent has nothing left to share.
    #[error("parent has no remaining budget to share")]
    Budget,
    /// Non-positive budget or TTL.
    #[error("requested budget and TTL must be positive")]
    BadRequest,
    /// The parent's own grant has expired.
    #[error("parent grant has expired")]
    ParentExpiry,
    /// The child would sit deeper than `max_depth`.
    #[error("delegation depth limit reached: child depth {child} > max {max}")]
    Depth {
        /// Depth the child would have.
        child: i64,
        /// Configured limit.
        max: i64,
    },
}

impl Grant {
    /// Whether `tool` is in the grant (exact match; no wildcards).
    #[must_use]
    pub fn has(&self, tool: &str) -> bool {
        self.tools.iter().any(|t| t == tool)
    }

    /// Whether the grant is no longer valid at `now`.
    #[must_use]
    pub fn expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// The greatest grant that is ⊆ both inputs: tool intersection, minimum
    /// budget, earliest expiry, deepest depth. Used when a child cannot be
    /// attributed to a single parent.
    #[must_use]
    pub fn meet(&self, other: &Grant) -> Grant {
        Grant {
            tools: intersect(&self.tools, &other.tools),
            max_calls: self.max_calls.min(other.max_calls),
            expires_at: self.expires_at.min(other.expires_at),
            depth: self.depth.max(other.depth),
        }
    }
}

/// Derives a child grant. `parent_remaining` is the parent's unspent budget;
/// the returned `max_calls` must be deducted from it by the caller (shared,
/// not copied).
///
/// # Errors
///
/// Returns an [`AttenuateError`] naming the first rule the request breaks.
pub fn attenuate(
    parent: &Grant,
    parent_remaining: i64,
    req: &Request,
    max_depth: i64,
    now: Timestamp,
) -> Result<Grant, AttenuateError> {
    if req.tools.is_empty() {
        return Err(AttenuateError::NoTools);
    }
    if req.max_calls <= 0 || !req.ttl.is_positive() {
        return Err(AttenuateError::BadRequest);
    }
    if parent.expired(now) {
        return Err(AttenuateError::ParentExpiry);
    }
    let depth = parent.depth.saturating_add(1);
    if depth > max_depth {
        return Err(AttenuateError::Depth {
            child: depth,
            max: max_depth,
        });
    }
    if parent_remaining <= 0 {
        return Err(AttenuateError::Budget);
    }

    let mut tools = intersect(&req.tools, &parent.tools);
    if depth >= max_depth {
        tools.retain(|t| t != SPAWN_TOOL); // a leaf may not spawn
    }
    if tools.is_empty() {
        return Err(AttenuateError::EmptyGrant);
    }
    // On overflow the parent's expiry is the cap anyway.
    let expires_at = now
        .checked_add(req.ttl)
        .map_or(parent.expires_at, |e| e.min(parent.expires_at));
    Ok(Grant {
        tools,
        max_calls: req.max_calls.min(parent_remaining),
        expires_at,
        depth,
    })
}

/// The sorted, de-duplicated set `a ∩ b`.
#[must_use]
pub fn intersect(a: &[String], b: &[String]) -> Vec<String> {
    let in_b: BTreeSet<&str> = b.iter().map(String::as_str).collect();
    a.iter()
        .map(String::as_str)
        .filter(|x| in_b.contains(x))
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests;
