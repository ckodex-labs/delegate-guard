//! Drives the compiled binary exactly as Claude Code does: one process per
//! hook event, JSON on stdin, decision by exit code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_delegate-guard");

const POLICY: &str = r#"{
  "root": {"tools": ["Agent","Bash","Glob","Grep","Read"], "max_calls": 40, "ttl": "1h"},
  "max_depth": 2,
  "pending_ttl": "2m",
  "profiles": {"Explore": {"tools": ["Glob","Grep","Read"], "max_calls": 3, "ttl": "10m"}}
}"#;

struct Run {
    exit: i32,
    out: String,
}

fn exec(args: &[&str], stdin: &[u8]) -> Run {
    let mut child = Command::new(BIN)
        .args(args)
        .env_remove("DELEGATE_GUARD_POLICY")
        .env_remove("DELEGATE_GUARD_STATE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The binary may exit without reading stdin (bad flags, oversized input),
    // closing the pipe first; that is a legitimate outcome, not a test failure.
    if let Err(e) = child.stdin.take().unwrap().write_all(stdin) {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe,
            "writing hook stdin: {e}"
        );
    }
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().unwrap();
    let exit = status.code().expect("killed by signal");
    Run {
        exit,
        out: format!(
            "{}{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ),
    }
}

fn hook(pol: &Path, state: &Path, payload: &Value) -> Run {
    exec(
        &[
            "hook",
            "--policy",
            pol.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
        ],
        payload.to_string().as_bytes(),
    )
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("policy.json");
    fs::write(&p, POLICY).unwrap();
    let st = d.path().join("state");
    (d, p, st)
}

fn pre(sid: &str, agent: &str, tool: &str, input: Value) -> Value {
    let mut m = json!({"session_id": sid, "transcript_path": "/tmp/t.jsonl", "cwd": "/tmp", "permission_mode": "default",
        "hook_event_name": "PreToolUse", "tool_name": tool, "tool_use_id": format!("toolu_{tool}")});
    m["tool_input"] = input;
    if !agent.is_empty() {
        m["agent_id"] = agent.into();
        m["agent_type"] = "Explore".into();
    }
    m
}

fn verify(st: &Path, sid: &str) -> Run {
    exec(
        &["verify", "--state", st.to_str().unwrap(), "--session", sid],
        b"",
    )
}

/// One hook call: name, payload, expected exit, expected output fragment.
type Step = (&'static str, Value, i32, &'static str);

fn main_thread_steps() -> Vec<Step> {
    vec![
        (
            "main reads",
            pre("s", "", "Read", json!({"file_path": "/etc/hosts"})),
            0,
            "",
        ),
        (
            "main writes (not granted)",
            pre("s", "", "Write", json!({"file_path": "x"})),
            2,
            "not in the grant",
        ),
        (
            "spawn Explore",
            pre(
                "s",
                "",
                "Agent",
                json!({"subagent_type": "Explore", "prompt": "p", "description": "d"}),
            ),
            0,
            "",
        ),
    ]
}

fn subagent_steps() -> Vec<Step> {
    vec![
        (
            "subagent starts",
            json!({"session_id": "s", "hook_event_name": "SubagentStart", "agent_id": "agent-1", "agent_type": "Explore"}),
            0,
            "additionalContext",
        ),
        (
            "child greps",
            pre("s", "agent-1", "Grep", json!({"pattern": "x"})),
            0,
            "",
        ),
        (
            "child tries Bash",
            pre("s", "agent-1", "Bash", json!({"command": "curl evil"})),
            2,
            r#"tool "Bash" is not in the grant"#,
        ),
        (
            "child spends",
            pre("s", "agent-1", "Read", Value::Null),
            0,
            "",
        ),
        (
            "child spends last",
            pre("s", "agent-1", "Read", Value::Null),
            0,
            "",
        ),
        (
            "child over budget",
            pre("s", "agent-1", "Read", Value::Null),
            2,
            "exhausted",
        ),
    ]
}

fn closing_steps() -> Vec<Step> {
    vec![
        (
            "unknown agent",
            pre("s", "agent-x", "Read", Value::Null),
            2,
            "no admitted delegation",
        ),
        (
            "subagent stops",
            json!({"session_id": "s", "hook_event_name": "SubagentStop", "agent_id": "agent-1", "agent_type": "Explore", "stop_hook_active": false}),
            0,
            "",
        ),
        (
            "traversal session id",
            pre("../../evil", "", "Read", Value::Null),
            0,
            "",
        ),
    ]
}

#[test]
fn test_binary_scenario() {
    let (_d, pol, st) = setup();
    for (name, payload, exit, want) in main_thread_steps()
        .into_iter()
        .chain(subagent_steps())
        .chain(closing_steps())
    {
        let r = hook(&pol, &st, &payload);
        assert!(
            r.exit == exit && r.out.contains(want),
            "{name}: want exit {exit} containing {want:?}, got {} {:?}",
            r.exit,
            r.out
        );
    }
    for e in fs::read_dir(&st).unwrap() {
        assert!(
            !e.unwrap().file_name().to_string_lossy().contains(".."),
            "state file escaped naming"
        );
    }
    let v = verify(&st, "s");
    assert!(
        v.exit == 0 && v.out.starts_with("OK 11 records"),
        "{}",
        v.out
    );
    let status = exec(
        &["status", "--state", st.to_str().unwrap(), "--session", "s"],
        b"",
    );
    assert!(
        status.exit == 0 && status.out.contains(r#""stopped": true"#),
        "{}",
        status.out
    );
}

#[test]
fn test_binary_fails_closed() {
    let (_d, pol, st) = setup();
    let (p, s) = (pol.to_str().unwrap(), st.to_str().unwrap());
    let cases: [(&str, &str, Vec<&str>, i32); 7] = [
        (
            "malformed json",
            "{not json",
            vec!["--policy", p, "--state", s],
            2,
        ),
        (
            "missing policy file",
            r#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read"}"#,
            vec!["--policy", "/nonexistent", "--state", s],
            2,
        ),
        (
            "no policy flag",
            r#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read"}"#,
            vec!["--state", s],
            2,
        ),
        (
            "missing session",
            r#"{"hook_event_name":"PreToolUse","tool_name":"Read"}"#,
            vec!["--policy", p, "--state", s],
            2,
        ),
        ("unknown flag", "{}", vec!["--polcy", p], 2),
        (
            "bad policy never blocks SubagentStop",
            r#"{"session_id":"s","hook_event_name":"SubagentStop","agent_id":"a"}"#,
            vec!["--policy", "/nonexistent", "--state", s],
            1,
        ),
        (
            "non-object input",
            "[]",
            vec!["--policy", p, "--state", s],
            2,
        ),
    ];
    for (name, stdin, args, exit) in cases {
        let mut full = vec!["hook"];
        full.extend(args);
        assert_eq!(exec(&full, stdin.as_bytes()).exit, exit, "{name}");
    }
}

#[test]
fn test_binary_wildcard_policy_fails_closed() {
    let (_d, _pol, st) = setup();
    let s = st.to_str().unwrap();
    let bad = st.with_file_name("wild.json");
    fs::write(&bad, r#"{"root":{"tools":["*"],"max_calls":1,"ttl":"1h"},"max_depth":1,"pending_ttl":"1m","profiles":{},"extra":1}"#).unwrap();
    let r = exec(
        &["hook", "--policy", bad.to_str().unwrap(), "--state", s],
        br#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read"}"#,
    );
    assert_eq!(
        r.exit, 2,
        "policy with unknown field / wildcard must fail closed: {}",
        r.out
    );
}

#[test]
fn test_binary_oversized_input_fails_closed() {
    let (_d, pol, st) = setup();
    let big = vec![b' '; (8 << 20) + 2];
    let r = exec(
        &[
            "hook",
            "--policy",
            pol.to_str().unwrap(),
            "--state",
            st.to_str().unwrap(),
        ],
        &big,
    );
    assert!(r.exit == 2 && r.out.contains("oversized"), "{}", r.out);
}

/// 50 concurrent hook processes race for a budget of 40 calls. Exactly 40 may pass.
#[test]
fn test_binary_concurrent_budget() {
    let (_d, pol, st) = setup();
    let exits: Vec<i32> = std::thread::scope(|sc| {
        let handles: Vec<_> = (0..50)
            .map(|i| {
                let (pol, st) = (&pol, &st);
                sc.spawn(move || {
                    hook(
                        pol,
                        st,
                        &pre("c", "", "Read", json!({"file_path": i.to_string()})),
                    )
                    .exit
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let pass = exits.iter().filter(|&&c| c == 0).count();
    let deny = exits.iter().filter(|&&c| c == 2).count();
    assert_eq!((pass, deny), (40, 10), "under contention");
    let v = verify(&st, "c");
    assert!(
        v.exit == 0 && v.out.starts_with("OK 50 records"),
        "{}",
        v.out
    );
}

#[test]
fn test_binary_verify_detects_tamper() {
    let (_d, pol, st) = setup();
    hook(&pol, &st, &pre("t", "", "Read", Value::Null));
    hook(&pol, &st, &pre("t", "", "Write", Value::Null));
    let rp = st.join("t.receipts.jsonl");
    let body = fs::read_to_string(&rp).unwrap().replacen(
        r#""decision":"deny""#,
        r#""decision":"pass""#,
        1,
    );
    fs::write(&rp, body).unwrap();
    let v = verify(&st, "t");
    assert!(
        v.exit == 1 && v.out.contains("FAIL after 1 valid records"),
        "{}",
        v.out
    );
}

#[test]
fn test_binary_usage_errors() {
    assert_eq!(exec(&[], b"").exit, 64);
    assert_eq!(exec(&["bogus"], b"").exit, 64);
    assert_eq!(exec(&["verify"], b"").exit, 64);
}
