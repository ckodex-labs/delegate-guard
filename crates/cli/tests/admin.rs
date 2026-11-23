//! The admin API end to end: a real daemon with `--admin-socket`, driven by
//! `delegate-guard admin` processes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_delegate-guard");

const POLICY: &str = r#"{"root":{"tools":["Agent","Glob","Read"],"max_calls":40,"ttl":"1h"},"max_depth":2,"pending_ttl":"2m","profiles":{}}"#;
const NARROWER: &str = r#"{"root":{"tools":["Glob"],"max_calls":40,"ttl":"1h"},"max_depth":2,"pending_ttl":"2m","profiles":{}}"#;

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("policy.json"), POLICY).unwrap();
        let p = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
        let mut child = Command::new(BIN)
            .args([
                "serve",
                "--socket",
                &p("run/hook.sock"),
                "--policy",
                &p("policy.json"),
            ])
            .args([
                "--state",
                &p("state"),
                "--admin-socket",
                &p("run/admin.sock"),
            ])
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
            line.contains("listening on") && line.contains("admin"),
            "daemon did not start: {line}"
        );
        Daemon { child, dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn admin(&self, args: &[&str]) -> (i32, String) {
        let socket = self.path("run/admin.sock");
        let out = Command::new(BIN)
            .arg("admin")
            .args(args)
            .args(["--admin-socket", socket.to_str().unwrap()])
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn read(&self, session: &str) -> i32 {
        let payload = json!({"session_id": session, "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_use_id": "t"});
        let socket = self.path("run/hook.sock");
        let mut child = Command::new(BIN)
            .args(["hook", "--socket", socket.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait().unwrap().code().unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_admin_health_status_and_private_socket() {
    let d = Daemon::start();
    let (code, out) = d.admin(&["health"]);
    assert!(
        code == 0 && out.contains("SERVING_STATUS_SERVING"),
        "{code} {out}"
    );
    let (code, out) = d.admin(&["status"]);
    assert!(
        code == 0 && out.contains("policy_sha256") && out.contains("hook.sock"),
        "{out}"
    );
    assert_eq!(
        fs::metadata(d.path("run/admin.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn test_admin_lists_sessions_and_verifies_chains() {
    let d = Daemon::start();
    for _ in 0..3 {
        assert_eq!(d.read("alpha"), 0);
    }
    let (code, out) = d.admin(&["sessions"]);
    assert!(
        code == 0 && out.contains("alpha\tagents=1\tpending=0\troot_remaining=37"),
        "{out}"
    );
    let (code, out) = d.admin(&["verify", "--session", "alpha"]);
    assert!(
        code == 0 && out.starts_with("CHAIN_STATE_INTACT 3 records"),
        "{out}"
    );
    let (code, out) = d.admin(&["verify", "--session", "nobody"]);
    assert!(code == 0 && out.starts_with("CHAIN_STATE_EMPTY"), "{out}");

    let receipts = d.path("state/alpha.receipts.jsonl");
    let tampered =
        fs::read_to_string(&receipts)
            .unwrap()
            .replacen("remaining=39", "remaining=99", 1);
    fs::write(&receipts, tampered).unwrap();
    let (code, out) = d.admin(&["verify", "--session", "alpha"]);
    assert!(
        code == 1 && out.starts_with("CHAIN_STATE_BROKEN 0 records"),
        "{out}"
    );
}

/// A rejected reload keeps the last valid policy and reports DEGRADED. An
/// applied, narrower reload governs new sessions and also revokes what issued
/// grants no longer may do.
#[test]
fn test_admin_reload_rejects_invalid_and_applies_valid() {
    let d = Daemon::start();
    assert_eq!(d.read("before"), 0);
    fs::write(d.path("policy.json"), r#"{"root":{"tools":["*"]}}"#).unwrap();
    let (code, out) = d.admin(&["reload"]);
    assert!(
        code == 1 && out.contains("RELOAD_OUTCOME_REJECTED"),
        "{out}"
    );
    let (code, out) = d.admin(&["health"]);
    assert!(
        code == 1 && out.contains("SERVING_STATUS_DEGRADED"),
        "{out}"
    );
    assert_eq!(d.read("during"), 0, "the last valid policy still governs");

    fs::write(d.path("policy.json"), NARROWER).unwrap();
    let (code, out) = d.admin(&["reload"]);
    assert!(code == 0 && out.contains("RELOAD_OUTCOME_APPLIED"), "{out}");
    assert_eq!(d.admin(&["health"]).0, 0, "a good reload clears DEGRADED");
    assert_eq!(
        d.read("after"),
        2,
        "a new session gets the narrower root grant"
    );
    assert_eq!(
        d.read("before"),
        2,
        "a narrowing reload revokes the tool from an issued grant"
    );
}

#[test]
fn test_admin_unreachable_is_exit_69() {
    let dir = tempfile::tempdir().unwrap();
    let missing: &Path = &dir.path().join("none.sock");
    let out = Command::new(BIN)
        .args([
            "admin",
            "health",
            "--admin-socket",
            missing.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(69));
}
