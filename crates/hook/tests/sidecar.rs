//! Exact binding through Claude Code's `agent-<id>.meta.json` sidecar, using
//! files laid out the way Claude Code does (`<project>/<sessionId>.jsonl` and
//! `<project>/<sessionId>/subagents/`), so the guard reads real files.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fixture;

use std::fs;
use std::path::PathBuf;

use delegate_guard_hook::{Input, Outcome, find_sidecar, find_sidecar_owned_by};
use delegate_guard_kernel::session::{BoundBy, MAIN_ACTOR};
use fixture::{Env, mins, must_deny, must_pass, profile, t0};

struct SidecarEnv {
    e: Env,
    proj: tempfile::TempDir,
}

impl SidecarEnv {
    fn new(enabled: bool) -> SidecarEnv {
        let mut e = Env::new();
        e.p.sidecar_binding = enabled;
        e.p.root.max_calls = 100;
        e.p.profiles.insert(
            "general-purpose".into(),
            profile(&["Agent", "Grep", "Read"], 6, mins(5)),
        );
        e.p.profiles.insert(
            "Explore".into(),
            profile(&["Bash", "Grep", "Read"], 8, mins(10)),
        );
        let proj = tempfile::tempdir().unwrap();
        fs::write(proj.path().join(format!("{}.jsonl", e.sid)), b"{}\n").unwrap();
        SidecarEnv { e, proj }
    }

    fn transcript(&self) -> String {
        self.proj
            .path()
            .join(format!("{}.jsonl", self.e.sid))
            .to_string_lossy()
            .into_owned()
    }

    fn subagents(&self) -> PathBuf {
        self.proj.path().join(&self.e.sid).join("subagents")
    }

    fn write_sidecar(&self, agent: &str, tool_use_id: &str, parent: &str, nested: bool) {
        let dir = if nested {
            self.subagents().join("workflows").join("run-1")
        } else {
            self.subagents()
        };
        fs::create_dir_all(&dir).unwrap();
        let mut m = serde_json::json!({"toolUseId": tool_use_id, "agentType": "Explore", "description": "d"});
        if !parent.is_empty() {
            m["parentAgentId"] = parent.into();
        }
        fs::write(dir.join(format!("agent-{agent}.meta.json")), m.to_string()).unwrap();
    }

    fn spawn(&self, agent: &str, typ: &str, tool_use_id: &str) -> Outcome {
        let i = Input {
            transcript_path: self.transcript(),
            agent_type: if agent.starts_with("gp") {
                "general-purpose".into()
            } else {
                String::new()
            },
            tool_name: "Agent".into(),
            tool_input: serde_json::json!({"subagent_type": typ, "prompt": "x"}),
            tool_use_id: tool_use_id.into(),
            ..self.e.input("PreToolUse", agent)
        };
        self.e.run(&i, t0())
    }

    fn call(&self, agent: &str, typ: &str, tool: &str) -> Outcome {
        let i = Input {
            transcript_path: self.transcript(),
            agent_type: typ.into(),
            tool_name: tool.into(),
            tool_use_id: "toolu_x".into(),
            ..self.e.input("PreToolUse", agent)
        };
        self.e.run(&i, t0())
    }

    /// main and gp-1 both spawn Explore before either child starts: the case
    /// the hook payloads cannot disambiguate.
    fn concurrent_spawns(&self) {
        must_pass(&self.spawn("", "general-purpose", "toolu_gp"));
        self.e.start("gp-1", "general-purpose", t0());
        must_pass(&self.call("gp-1", "general-purpose", "Read")); // gp-1 binds (single candidate)
        must_pass(&self.spawn("", "Explore", "toolu_main_ex"));
        must_pass(&self.spawn("gp-1", "Explore", "toolu_gp_ex"));
        self.e.start("ex-1", "Explore", t0());
        self.e.start("ex-2", "Explore", t0());
    }
}

#[test]
fn test_sidecar_exact_binding_resolves_ambiguity() {
    let e = SidecarEnv::new(true);
    e.concurrent_spawns();
    e.write_sidecar("ex-1", "toolu_gp_ex", "gp-1", false); // ex-1 belongs to gp-1 (no Bash)
    e.write_sidecar("ex-2", "toolu_main_ex", "", true); // ex-2 belongs to main (has Bash); nested dir

    must_deny(
        &e.call("ex-1", "Explore", "Bash"),
        r#"tool "Bash" is not in the grant"#,
    );
    must_pass(&e.call("ex-2", "Explore", "Bash")); // exact binding: not reduced to the meet

    let s = e.e.session();
    for (id, parent) in [("ex-1", "gp-1"), ("ex-2", MAIN_ACTOR)] {
        let a = &s.agents[id];
        assert!(
            a.bound_by == Some(BoundBy::Sidecar) && a.parent == parent && !a.ambiguous,
            "{id}: {a:?}"
        );
    }
    // ex-1: gp-1's 6 - 1 Read - 1 Agent call; ex-2: main's own delegation.
    assert_eq!(
        (
            s.agents["ex-1"].grant.max_calls,
            s.agents["ex-2"].grant.max_calls
        ),
        (4, 8)
    );
}

#[test]
fn test_sidecar_naming_unadmitted_spawn_denied() {
    let e = SidecarEnv::new(true);
    e.concurrent_spawns();
    e.write_sidecar("ex-1", "toolu_forged", "", false);
    must_deny(&e.call("ex-1", "Explore", "Read"), "never admitted");
}

#[test]
fn test_sidecar_parent_mismatch_denied() {
    let e = SidecarEnv::new(true);
    e.concurrent_spawns();
    e.write_sidecar("ex-1", "toolu_main_ex", "gp-1", false); // main's spawn, but claims gp-1
    must_deny(
        &e.call("ex-1", "Explore", "Read"),
        "does not match the admitted spawner",
    );
}

#[test]
fn test_sidecar_type_mismatch_denied() {
    let e = SidecarEnv::new(true);
    e.concurrent_spawns();
    e.write_sidecar("ex-1", "toolu_main_ex", "", false);
    must_deny(
        &e.call("ex-1", "Plan", "Read"),
        "but the agent reports type",
    );
}

#[test]
fn test_sidecar_missing_falls_back_to_meet() {
    let e = SidecarEnv::new(true);
    e.concurrent_spawns();
    must_deny(&e.call("ex-1", "Explore", "Bash"), "not in the grant");
    assert_eq!(e.e.session().agents["ex-1"].bound_by, Some(BoundBy::Meet));
}

#[test]
fn test_sidecar_ignored_when_disabled() {
    let e = SidecarEnv::new(false);
    e.concurrent_spawns();
    e.write_sidecar("ex-2", "toolu_main_ex", "", false);
    assert_eq!(
        e.e.session().agents["ex-2"].bound_by,
        Some(BoundBy::Meet),
        "sidecar_binding=false must not read sidecars"
    );
}

#[test]
fn test_find_sidecar_rejects_unsafe_input() {
    let e = SidecarEnv::new(true);
    e.write_sidecar("ok", "toolu_1", "", false);
    let found = find_sidecar(&e.transcript(), &e.e.sid, "ok").map(|(sc, _)| sc.tool_use_id);
    assert_eq!(found.as_deref(), Some("toolu_1"));
    for id in ["../ok", "a/b", "..", "x\0", ""] {
        assert!(
            find_sidecar(&e.transcript(), &e.e.sid, id).is_none(),
            "agent id {id:?} must not resolve"
        );
    }
    // A symlinked sidecar is not followed.
    let target = e.proj.path().join("evil.json");
    fs::write(&target, r#"{"toolUseId":"toolu_evil"}"#).unwrap();
    std::os::unix::fs::symlink(&target, e.subagents().join("agent-ln.meta.json")).unwrap();
    assert!(
        find_sidecar(&e.transcript(), &e.e.sid, "ln").is_none(),
        "symlinked sidecar must be ignored"
    );
}

/// Tier S: the daemon reads sidecars through an ACL on every granting user's
/// projects, so a caller could point `transcript_path` at someone else's. Only a
/// sidecar owned by the caller is used.
#[test]
fn test_find_sidecar_owned_by_requires_the_callers_file() {
    use std::os::unix::fs::MetadataExt;
    let e = SidecarEnv::new(true);
    e.write_sidecar("ok", "toolu_1", "", false);
    let mine = fs::metadata(e.subagents().join("agent-ok.meta.json"))
        .unwrap()
        .uid();
    let found = |owner| find_sidecar_owned_by(&e.transcript(), &e.e.sid, "ok", owner).is_some();
    assert!(found(None), "no owner given: any sidecar");
    assert!(found(Some(mine)), "the caller's own sidecar");
    assert!(
        !found(Some(mine.wrapping_add(1))),
        "another user's sidecar is ignored"
    );
}

#[test]
fn test_find_sidecar_rejects_oversized_file() {
    let e = SidecarEnv::new(true);
    fs::create_dir_all(e.subagents()).unwrap();
    let pad = " ".repeat(65 * 1024);
    fs::write(
        e.subagents().join("agent-big.meta.json"),
        format!(r#"{{"toolUseId":"t"}}{pad}"#),
    )
    .unwrap();
    assert!(find_sidecar(&e.transcript(), &e.e.sid, "big").is_none());
}

/// A `subagents` directory that is a symlink is not walked: its target is
/// outside what Claude Code wrote.
#[test]
fn test_find_sidecar_ignores_symlinked_directory() {
    let e = SidecarEnv::new(true);
    let elsewhere = e.proj.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(
        elsewhere.join("agent-ln.meta.json"),
        r#"{"toolUseId":"toolu_evil"}"#,
    )
    .unwrap();
    fs::create_dir_all(e.subagents().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, e.subagents()).unwrap();
    assert!(
        find_sidecar(&e.transcript(), &e.e.sid, "ln").is_none(),
        "symlinked subagents dir must be ignored"
    );
}
