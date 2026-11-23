//! The shared daemon end to end: a real `delegate-guard serve` process, real
//! `hook --socket` client processes, and raw socket peers for protocol abuse.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_delegate-guard");

const POLICY: &str = r#"{
  "root": {"tools": ["Agent","Bash","Glob","Grep","Read"], "max_calls": 40, "ttl": "1h"},
  "max_depth": 2,
  "pending_ttl": "2m",
  "profiles": {"Explore": {"tools": ["Glob","Grep","Read"], "max_calls": 3, "ttl": "10m"}}
}"#;

/// A running daemon; killed when dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    state: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start_with(extra: &[&str]) -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("policy.json");
        fs::write(&policy, POLICY).unwrap();
        let (socket, state) = (
            dir.path().join("run").join("hook.sock"),
            dir.path().join("state"),
        );
        let child = spawn_serve_with(&socket, &policy, &state, extra);
        Daemon {
            child,
            socket,
            state,
            _dir: dir,
        }
    }

    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        Daemon::start_in(dir)
    }

    fn start_in(dir: tempfile::TempDir) -> Daemon {
        let policy = dir.path().join("policy.json");
        fs::write(&policy, POLICY).unwrap();
        let (socket, state) = (
            dir.path().join("run").join("hook.sock"),
            dir.path().join("state"),
        );
        let child = spawn_serve(&socket, &policy, &state);
        Daemon {
            child,
            socket,
            state,
            _dir: dir,
        }
    }

    fn hook(&self, payload: &Value) -> (i32, String) {
        client(&self.socket, payload)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `serve` and waits for its "listening" line (a signal, not a sleep).
fn spawn_serve(socket: &Path, policy: &Path, state: &Path) -> Child {
    spawn_serve_with(socket, policy, state, &[])
}

fn spawn_serve_with(socket: &Path, policy: &Path, state: &Path, extra: &[&str]) -> Child {
    let mut child = Command::new(BIN)
        .args([
            "serve",
            "--socket",
            socket.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .args(["--state", state.to_str().unwrap()])
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(
        line.contains("listening on"),
        "daemon did not start: {line}"
    );
    child
}

fn client(socket: &Path, payload: &Value) -> (i32, String) {
    let mut child = Command::new(BIN)
        .args(["hook", "--socket", socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(e) = child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
    {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().expect("client killed by signal"), text)
}

fn pre(sid: &str, agent: &str, tool: &str, input: Value) -> Value {
    let mut m = json!({"session_id": sid, "transcript_path": "/tmp/t.jsonl", "hook_event_name": "PreToolUse",
        "tool_name": tool, "tool_use_id": format!("toolu_{tool}")});
    m["tool_input"] = input;
    if !agent.is_empty() {
        m["agent_id"] = agent.into();
        m["agent_type"] = "Explore".into();
    }
    m
}

fn lifecycle(sid: &str, event: &str, agent: &str) -> Value {
    json!({"session_id": sid, "hook_event_name": event, "agent_id": agent, "agent_type": "Explore"})
}

fn verify(state: &Path, sid: &str) -> String {
    let out = Command::new(BIN)
        .args([
            "verify",
            "--state",
            state.to_str().unwrap(),
            "--session",
            sid,
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Raw protocol access, for peers that are not our client.
fn raw_exchange(socket: &Path, frame: &[u8]) -> Option<Value> {
    let mut s = UnixStream::connect(socket).unwrap();
    s.write_all(frame).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
    s.read_exact(&mut body).unwrap();
    Some(serde_json::from_slice(&body).unwrap())
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut f = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

#[test]
fn test_daemon_scenario_matches_in_process_rules() {
    let d = Daemon::start();
    let steps: Vec<(&str, Value, i32, &str)> = vec![
        ("main reads", pre("s", "", "Read", json!({})), 0, ""),
        (
            "main writes",
            pre("s", "", "Write", json!({})),
            2,
            "not in the grant",
        ),
        (
            "spawn",
            pre("s", "", "Agent", json!({"subagent_type": "Explore"})),
            0,
            "",
        ),
        (
            "start",
            lifecycle("s", "SubagentStart", "agent-1"),
            0,
            "additionalContext",
        ),
        ("child greps", pre("s", "agent-1", "Grep", json!({})), 0, ""),
        (
            "child Bash",
            pre("s", "agent-1", "Bash", json!({})),
            2,
            r#"tool "Bash" is not in the grant"#,
        ),
        (
            "unknown agent",
            pre("s", "agent-x", "Read", json!({})),
            2,
            "no admitted delegation",
        ),
        ("stop", lifecycle("s", "SubagentStop", "agent-1"), 0, ""),
    ];
    for (name, payload, exit, want) in steps {
        let (code, out) = d.hook(&payload);
        assert!(
            code == exit && out.contains(want),
            "{name}: want {exit} containing {want:?}, got {code} {out:?}"
        );
    }
    assert!(
        verify(&d.state, "s").starts_with("OK 8 records"),
        "{}",
        verify(&d.state, "s")
    );
}

#[test]
fn test_daemon_down_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nobody.sock");
    let (code, out) = client(&missing, &pre("s", "", "Read", json!({})));
    assert!(
        code == 2 && out.contains("daemon unavailable"),
        "{code} {out}"
    );
    let (code, _) = client(&missing, &lifecycle("s", "SubagentStop", "a"));
    assert_eq!(code, 1, "SubagentStop must never exit 2");
}

#[test]
fn test_daemon_killed_mid_session_fails_closed_then_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start_in(dir);
    assert_eq!(d.hook(&pre("r", "", "Read", json!({}))).0, 0);
    d.child.kill().unwrap();
    d.child.wait().unwrap();
    assert_eq!(
        d.hook(&pre("r", "", "Read", json!({}))).0,
        2,
        "a dead daemon must block"
    );
    let policy = d
        .socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policy.json");
    d.child = spawn_serve(&d.socket, &policy, &d.state); // stale socket is replaced
    assert_eq!(d.hook(&pre("r", "", "Read", json!({}))).0, 0);
    let status = fs::read_to_string(d.state.join("r.json")).unwrap();
    assert!(
        status.contains(r#""remaining": 38"#),
        "state must survive the restart: {status}"
    );
    assert!(verify(&d.state, "r").starts_with("OK 2 records"));
}

#[test]
fn test_daemon_serves_sessions_independently() {
    let d = Daemon::start();
    for _ in 0..3 {
        for sid in ["alpha", "beta"] {
            assert_eq!(d.hook(&pre(sid, "", "Read", json!({}))).0, 0);
        }
    }
    for sid in ["alpha", "beta"] {
        assert!(verify(&d.state, sid).starts_with("OK 3 records"), "{sid}");
    }
}

/// 50 concurrent client processes race for a budget of 40 calls through one daemon.
#[test]
fn test_daemon_concurrent_budget() {
    let d = Daemon::start();
    let codes: Vec<i32> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..50)
            .map(|_| sc.spawn(|| d.hook(&pre("c", "", "Read", json!({}))).0))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let pass = codes.iter().filter(|&&c| c == 0).count();
    let deny = codes.iter().filter(|&&c| c == 2).count();
    assert_eq!((pass, deny), (40, 10));
    assert!(verify(&d.state, "c").starts_with("OK 50 records"));
}

#[test]
fn test_daemon_answers_garbage_and_wrong_version_without_blocking_stop() {
    let d = Daemon::start();
    let garbage = raw_exchange(&d.socket, &frame(b"{not json")).unwrap();
    assert_eq!(garbage["exit"], 2);
    let stop = json!({"v": 99, "event": lifecycle("s", "SubagentStop", "a")});
    let wrong = raw_exchange(&d.socket, &frame(stop.to_string().as_bytes())).unwrap();
    assert_eq!(wrong["exit"], 1, "never 2 outside PreToolUse: {wrong}");
    assert!(
        wrong["stderr"]
            .as_str()
            .unwrap()
            .contains("unsupported protocol version")
    );
    let not_object = json!({"v": 1, "event": [1, 2]});
    assert_eq!(
        raw_exchange(&d.socket, &frame(not_object.to_string().as_bytes())).unwrap()["exit"],
        1
    );
}

#[test]
fn test_daemon_drops_oversized_frame_without_reading_it() {
    let d = Daemon::start();
    let huge = u32::MAX.to_be_bytes();
    assert!(
        raw_exchange(&d.socket, &huge).is_none(),
        "an oversized frame gets no reply"
    );
    assert_eq!(
        d.hook(&pre("s", "", "Read", json!({}))).0,
        0,
        "the daemon keeps serving"
    );
}

#[test]
fn test_daemon_socket_is_private_and_single_instance() {
    let d = Daemon::start();
    let mode = fs::metadata(&d.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let policy = d
        .socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("policy.json");
    let second = Command::new(BIN)
        .args([
            "serve",
            "--socket",
            d.socket.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(69));
    assert!(String::from_utf8_lossy(&second.stderr).contains("another delegate-guard daemon"));
}

#[test]
fn test_daemon_refuses_shared_socket_directory() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let policy = dir.path().join("policy.json");
    fs::write(&policy, POLICY).unwrap();
    let out = Command::new(BIN)
        .args([
            "serve",
            "--socket",
            shared.join("hook.sock").to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(69));
    assert!(String::from_utf8_lossy(&out.stderr).contains("writable by group or others"));
}

#[test]
fn test_hook_rejects_socket_and_policy_together() {
    let (code, out) = {
        let mut child = Command::new(BIN)
            .args([
                "hook",
                "--socket",
                "/nonexistent.sock",
                "--policy",
                "/p.json",
            ])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(pre("s", "", "Read", json!({})).to_string().as_bytes())
            .unwrap();
        let o = child.wait_with_output().unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    assert!(code == 2 && out.contains("not both"), "{code} {out}");
}

#[test]
fn test_daemon_applies_group_socket_mode() {
    let d = Daemon::start_with(&["--socket-mode", "660"]);
    assert_eq!(
        fs::metadata(&d.socket).unwrap().permissions().mode() & 0o777,
        0o660
    );
}

/// One slot, held by a peer that never sends: the next client is turned away
/// (fail closed). The long deadline keeps the slot held for the whole check.
#[test]
fn test_daemon_full_fails_closed() {
    let d = Daemon::start_with(&["--max-connections", "1", "--timeout-ms", "60000"]);
    let idle = UnixStream::connect(&d.socket).unwrap();
    let (code, out) = d.hook(&pre("b", "", "Read", json!({})));
    assert!(
        code == 2 && out.contains("daemon unavailable"),
        "a full daemon must fail closed: {code} {out}"
    );
    drop(idle);
}

/// The idle peer's deadline frees its slot, and not before the deadline.
#[test]
fn test_daemon_idle_peer_deadline_frees_slot() {
    const IDLE_TIMEOUT: Duration = Duration::from_millis(300);
    const GIVE_UP: Duration = Duration::from_secs(10);
    let d = Daemon::start_with(&["--max-connections", "1", "--timeout-ms", "300"]);
    let idle = UnixStream::connect(&d.socket).unwrap();
    let opened = Instant::now();
    // Poll against a wall-clock deadline: attempt counts depend on how fast the
    // platform spawns processes.
    let freed_after = loop {
        if d.hook(&pre("b", "", "Read", json!({}))).0 == 0 {
            break opened.elapsed();
        }
        assert!(
            opened.elapsed() < GIVE_UP,
            "the idle peer's deadline never released its slot"
        );
    };
    assert!(
        freed_after >= IDLE_TIMEOUT / 2,
        "slot freed after {freed_after:?}, before the idle deadline could fire"
    );
    drop(idle);
}
