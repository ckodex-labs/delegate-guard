//! Claude Code's subagent metadata file, used for exact binding.
//!
//! Layout and keys are not part of the documented hook contract. They are
//! taken from the Claude Agent SDK for Python, which reads the same file
//! (`claude_agent_sdk/_internal/sessions.py`, commit `3184360`, 2026-11-20):
//!
//! ```text
//! ~/.claude/projects/<project>/<sessionId>/subagents/agent-<agentId>.meta.json
//! (possibly nested, e.g. subagents/workflows/<runId>/)
//! {"toolUseId": "<id of the spawning Agent tool_use>", "parentAgentId": "<spawner, if a subagent>", ...}
//! ```

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::nullable;

/// The part of the sidecar the guard uses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Sidecar {
    /// `tool_use_id` of the spawning `Agent` call.
    #[serde(rename = "toolUseId", deserialize_with = "nullable")]
    pub tool_use_id: String,
    /// Spawning subagent; empty when the main thread spawned it.
    #[serde(rename = "parentAgentId", deserialize_with = "nullable")]
    pub parent_agent_id: String,
}

const MAX_SIDECAR: u64 = 64 << 10;
const MAX_ID: usize = 128;
const SEARCH_DEPTH: usize = 3;

/// `[A-Za-z0-9_@.-]{1,128}` without `..`.
fn safe_id(s: &str) -> bool {
    (1..=MAX_ID).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@.-".contains(&b))
        && !s.contains("..")
}

/// Locates and parses the sidecar for `agent_id`. Returns `None` when there is
/// none or it is unusable: any doubt degrades to "no sidecar", never to a
/// guess. `agent_id` is untrusted and is validated before use in a path.
#[must_use]
pub fn find_sidecar(
    transcript_path: &str,
    session_id: &str,
    agent_id: &str,
) -> Option<(Sidecar, PathBuf)> {
    find_sidecar_owned_by(transcript_path, session_id, agent_id, None)
}

/// [`find_sidecar`], using only a file owned by `owner` when one is given. A
/// system daemon passes the caller's uid: it can read every granting user's
/// projects, and must not let one caller bind through another user's files.
#[must_use]
pub fn find_sidecar_owned_by(
    transcript_path: &str,
    session_id: &str,
    agent_id: &str,
    owner: Option<u32>,
) -> Option<(Sidecar, PathBuf)> {
    if !safe_id(agent_id) || transcript_path.is_empty() {
        return None;
    }
    let name = format!("agent-{agent_id}.meta.json");
    let transcript = Path::new(transcript_path);
    let base = transcript.file_name()?.to_str()?;
    let parent = transcript
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut dirs = Vec::new();
    if base.starts_with("agent-") {
        dirs.push(parent.to_path_buf()); // a subagent transcript: sidecar is a sibling
    }
    if let Some(stem) = base.strip_suffix(".jsonl") {
        dirs.push(parent.join(stem).join("subagents"));
    }
    if safe_id(session_id) {
        dirs.push(parent.join(session_id).join("subagents"));
    }
    dirs.iter()
        .filter(|dir| fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()))
        .filter_map(|dir| find(dir, &name, SEARCH_DEPTH))
        .find_map(|path| read(&path, owner).map(|sc| (sc, path)))
}

/// Looks for `name` in `dir`, then up to `depth` directory levels below, in
/// lexical order, never following symlinks.
fn find(dir: &Path, name: &str, depth: usize) -> Option<PathBuf> {
    let mut entries: Vec<_> = fs::read_dir(dir).ok()?.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() && depth > 0 {
            if let Some(path) = find(&entry.path(), name, depth - 1) {
                return Some(path);
            }
        } else if file_type.is_file() && entry.file_name() == name {
            return Some(entry.path());
        }
    }
    None
}

/// Ownership is checked on the opened file, so swapping the path after the
/// directory walk cannot pass someone else's file through.
fn read(path: &Path, owner: Option<u32>) -> Option<Sidecar> {
    let file = File::open(path).ok()?;
    if owner.is_some_and(|uid| file.metadata().map_or(true, |m| m.uid() != uid)) {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SIDECAR + 1).read_to_end(&mut bytes).ok()?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_SIDECAR) {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}
