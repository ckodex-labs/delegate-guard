//! Adapter between Claude Code hook events and the delegation kernel.
//!
//! For each event: lock and load the session (`delegate-guard-state`), let the
//! kernel decide, append the kernel's facts as hash-chained receipts
//! (`delegate-guard-receipt`), save, and map the verdict to the hook's exit code
//! and output. The only other I/O here is the sidecar lookup the kernel asks for.
//!
//! Contract used (code.claude.com/docs/en/hooks, read 2026-11-22):
//! - Every event: `session_id`, `hook_event_name`; `agent_id`/`agent_type` are
//!   set when the hook fires inside a subagent.
//! - `PreToolUse`: exit 2 blocks the call and shows stderr as the reason. Any
//!   other exit does NOT block (unless the hook is configured with
//!   `"onFailure": "block"`, which the shipped templates set).
//! - `SubagentStart` cannot block; it can inject `additionalContext`.
//! - `SubagentStop`: exit 2 would keep the subagent running, so never exit 2 there.
//!
//! The guard only narrows. It never emits `permissionDecision: "allow"`.

mod events;
mod sidecar;

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

pub use delegate_guard_kernel::{Policy, PolicyError, Profile, ValidPolicy};
pub use events::{handle, handle_as};
pub use sidecar::{Sidecar, find_sidecar, find_sidecar_owned_by};

/// Exit code: proceed.
pub const EXIT_PASS: u8 = 0;
/// Exit code: non-blocking error (used where blocking would be wrong).
pub const EXIT_ERROR: u8 = 1;
/// Exit code: block the tool call (`PreToolUse`).
pub const EXIT_BLOCK: u8 = 2;

const PREFIX: &str = "delegate-guard: ";

/// The subset of the hook stdin payload the guard reads. Unknown fields are
/// ignored; missing or `null` strings read as empty.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Input {
    /// Claude Code session.
    #[serde(deserialize_with = "nullable")]
    pub session_id: String,
    /// Transcript of the conversation the hook fires in.
    #[serde(deserialize_with = "nullable")]
    pub transcript_path: String,
    /// `hook_event_name`.
    #[serde(rename = "hook_event_name", deserialize_with = "nullable")]
    pub event: String,
    /// Set inside a subagent; empty for the main thread.
    #[serde(deserialize_with = "nullable")]
    pub agent_id: String,
    /// Subagent type, when inside a subagent.
    #[serde(deserialize_with = "nullable")]
    pub agent_type: String,
    /// Tool being called (`PreToolUse`).
    #[serde(deserialize_with = "nullable")]
    pub tool_name: String,
    /// Tool arguments (`PreToolUse`); only `Agent`'s are read.
    pub tool_input: serde_json::Value,
    /// Claude Code's id for this tool call.
    #[serde(deserialize_with = "nullable")]
    pub tool_use_id: String,
}

impl Input {
    /// Decodes a hook payload.
    ///
    /// # Errors
    ///
    /// Fails if `raw` is not a JSON object with string-typed fields. (Serde
    /// would otherwise also accept an array as a positional struct.)
    pub fn parse(raw: &[u8]) -> Result<Input, serde_json::Error> {
        let v: serde_json::Value = serde_json::from_slice(raw)?;
        if !v.is_object() {
            return Err(serde::de::Error::custom("hook input must be a JSON object"));
        }
        serde_json::from_value(v)
    }

    /// Decodes a hook payload already parsed as JSON.
    ///
    /// # Errors
    ///
    /// Fails if `value` is not an object with string-typed fields.
    pub fn from_value(value: serde_json::Value) -> Result<Input, serde_json::Error> {
        if !value.is_object() {
            return Err(serde::de::Error::custom("hook input must be a JSON object"));
        }
        serde_json::from_value(value)
    }
}

/// The exit code for a failure on `event`: [`EXIT_BLOCK`] only on `PreToolUse`
/// (fail closed); [`EXIT_ERROR`] elsewhere, because exit 2 on `SubagentStop`
/// would keep the subagent running.
#[must_use]
pub fn fail_code(event: &str) -> u8 {
    if event == "PreToolUse" {
        EXIT_BLOCK
    } else {
        EXIT_ERROR
    }
}

pub(crate) fn nullable<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Option::<String>::deserialize(deserializer).map(Option::unwrap_or_default)
}

/// What the hook process should emit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Process exit code.
    pub exit: u8,
    /// Written to stdout (with a trailing newline) when non-empty.
    pub stdout: String,
    /// Written to stderr (with a trailing newline) when non-empty.
    pub stderr: String,
}

impl Outcome {
    pub(crate) fn pass() -> Self {
        Outcome::default()
    }

    pub(crate) fn deny(reason: &str) -> Self {
        Outcome {
            exit: EXIT_BLOCK,
            stderr: format!("{PREFIX}{reason}"),
            ..Outcome::default()
        }
    }

    pub(crate) fn error(msg: &str) -> Self {
        Outcome {
            exit: EXIT_ERROR,
            stderr: format!("{PREFIX}{msg}"),
            ..Outcome::default()
        }
    }

    /// `SubagentStart` output that injects `msg` into the subagent's context.
    pub(crate) fn context(msg: &str) -> Self {
        let body = serde_json::json!({
            "hookSpecificOutput": { "hookEventName": "SubagentStart", "additionalContext": msg }
        });
        Outcome {
            stdout: body.to_string(),
            ..Outcome::default()
        }
    }
}

/// Internal failures. Each event handler maps them to its fail-safe exit code.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HookError {
    #[error(transparent)]
    State(#[from] delegate_guard_state::StateError),
    #[error(transparent)]
    Receipt(#[from] delegate_guard_receipt::ReceiptError),
    #[error(transparent)]
    Kernel(#[from] delegate_guard_kernel::KernelError),
}

/// Why a policy file could not be used.
#[derive(Debug, thiserror::Error)]
#[error("policy {}: {source}", .path.display())]
pub struct LoadPolicyError {
    /// Policy file.
    pub path: PathBuf,
    /// Read, decode or validation failure.
    #[source]
    pub source: LoadPolicyCause,
}

/// The underlying reason in a [`LoadPolicyError`].
#[derive(Debug, thiserror::Error)]
pub enum LoadPolicyCause {
    /// The file could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The file is not a valid policy.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// Reads, decodes and validates a policy file.
///
/// # Errors
///
/// [`LoadPolicyError`] naming the file and the read, decode or rule failure.
pub fn load_policy(path: &Path) -> Result<ValidPolicy, LoadPolicyError> {
    let wrap = |source: LoadPolicyCause| LoadPolicyError {
        path: path.to_owned(),
        source,
    };
    let bytes = fs::read(path).map_err(|e| wrap(e.into()))?;
    Policy::from_json(&bytes).map_err(|e| wrap(e.into()))
}
