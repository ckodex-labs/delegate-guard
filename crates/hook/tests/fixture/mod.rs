//! Test fixtures: a policy, a temp state dir, and one helper per hook event.
#![allow(dead_code, clippy::missing_panics_doc)]

use std::path::PathBuf;

use delegate_guard_hook::{Input, Outcome, Policy, Profile, ValidPolicy, handle};
use delegate_guard_state::{self as state, Session, StateError};
use jiff::{SignedDuration, Timestamp};

pub fn t0() -> Timestamp {
    "2026-11-22T10:00:00Z".parse().unwrap()
}

pub fn mins(n: i64) -> SignedDuration {
    SignedDuration::from_mins(n)
}

pub fn tools(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

pub fn profile(t: &[&str], max_calls: i64, ttl: SignedDuration) -> Profile {
    Profile {
        tools: tools(t),
        max_calls,
        ttl,
    }
}

pub fn pol() -> Policy {
    Policy {
        root: profile(
            &["Agent", "Bash", "Glob", "Grep", "Read"],
            30,
            SignedDuration::from_hours(1),
        ),
        max_depth: 2,
        pending_ttl: mins(2),
        profiles: [
            (
                "Explore".to_owned(),
                profile(&["Glob", "Grep", "Read", "Write"], 5, mins(10)),
            ),
            (
                "general-purpose".to_owned(),
                profile(&["Agent", "Bash", "Read"], 10, mins(20)),
            ),
        ]
        .into(),
        sidecar_binding: false,
    }
}

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub dir: PathBuf,
    pub p: Policy,
    pub sid: String,
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        Env {
            tmp,
            dir,
            p: pol(),
            sid: "sess-1".to_owned(),
        }
    }

    pub fn input(&self, event: &str, agent: &str) -> Input {
        Input {
            session_id: self.sid.clone(),
            event: event.to_owned(),
            agent_id: agent.to_owned(),
            ..Input::default()
        }
    }

    pub fn run(&self, input: &Input, at: Timestamp) -> Outcome {
        let policy = ValidPolicy::try_from(self.p.clone()).expect("test policy must be valid");
        handle(&self.dir, &policy, input, at)
    }

    pub fn tool(&self, agent: &str, tool: &str, at: Timestamp) -> Outcome {
        let i = Input {
            tool_name: tool.to_owned(),
            tool_use_id: format!("tu-{tool}"),
            ..self.input("PreToolUse", agent)
        };
        self.run(&i, at)
    }

    pub fn spawn(&self, agent: &str, typ: &str, at: Timestamp) -> Outcome {
        let i = Input {
            tool_name: "Agent".to_owned(),
            tool_input: serde_json::json!({"subagent_type": typ, "prompt": "x"}),
            tool_use_id: "tu-spawn".to_owned(),
            ..self.input("PreToolUse", agent)
        };
        self.run(&i, at)
    }

    pub fn start(&self, id: &str, typ: &str, at: Timestamp) -> Outcome {
        self.run(
            &Input {
                agent_type: typ.to_owned(),
                ..self.input("SubagentStart", id)
            },
            at,
        )
    }

    pub fn stop(&self, id: &str, typ: &str, at: Timestamp) -> Outcome {
        self.run(
            &Input {
                agent_type: typ.to_owned(),
                ..self.input("SubagentStop", id)
            },
            at,
        )
    }

    pub fn session(&self) -> Session {
        state::with::<_, StateError>(&self.dir, &self.sid, |s, _| Ok(s.clone())).unwrap()
    }
}

#[track_caller]
pub fn must_pass(r: &Outcome) {
    assert_eq!(r.exit, 0, "want pass, got exit {}: {}", r.exit, r.stderr);
}

#[track_caller]
pub fn must_deny(r: &Outcome, substr: &str) {
    assert_eq!(
        r.exit, 2,
        "want deny containing {substr:?}, got exit {}",
        r.exit
    );
    assert!(
        r.stderr.contains(substr),
        "deny reason {:?} does not contain {substr:?}",
        r.stderr
    );
}
