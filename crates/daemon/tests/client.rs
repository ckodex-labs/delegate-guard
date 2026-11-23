//! The client against a deliberately misbehaving daemon: it must never let a
//! reply block where blocking is wrong, and must treat silence as failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use delegate_guard_daemon::protocol::{read_frame, write_frame};
use delegate_guard_daemon::{ClientError, forward};

const TIMEOUT: Duration = Duration::from_secs(5);

/// A one-shot fake daemon that reads one frame and answers `reply` (or nothing).
fn fake_daemon(
    reply: Option<&'static str>,
) -> (tempfile::TempDir, PathBuf, thread::JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_frame(&mut stream).unwrap();
        if let Some(body) = reply {
            write_frame(&mut stream, body.as_bytes()).unwrap();
        }
    });
    (dir, socket, handle)
}

fn event(name: &str) -> Vec<u8> {
    format!(r#"{{"session_id":"s","hook_event_name":"{name}","agent_id":"a"}}"#).into_bytes()
}

#[test]
fn test_forward_clamps_block_outside_pre_tool_use() {
    let (_d, socket, h) = fake_daemon(Some(r#"{"v":1,"exit":2,"stderr":"x"}"#));
    assert_eq!(
        forward(&socket, &event("SubagentStop"), TIMEOUT)
            .unwrap()
            .exit,
        1
    );
    h.join().unwrap();
}

#[test]
fn test_forward_maps_unknown_exit_to_fail_code() {
    let (_d, socket, h) = fake_daemon(Some(r#"{"v":1,"exit":7}"#));
    assert_eq!(
        forward(&socket, &event("PreToolUse"), TIMEOUT)
            .unwrap()
            .exit,
        2
    );
    h.join().unwrap();
}

#[test]
fn test_forward_keeps_block_on_pre_tool_use() {
    let (_d, socket, h) = fake_daemon(Some(r#"{"v":1,"exit":2}"#));
    assert_eq!(
        forward(&socket, &event("PreToolUse"), TIMEOUT)
            .unwrap()
            .exit,
        2
    );
    h.join().unwrap();
}

#[test]
fn test_forward_rejects_other_protocol_version() {
    let (_d, socket, h) = fake_daemon(Some(r#"{"v":2,"exit":0}"#));
    assert!(matches!(
        forward(&socket, &event("PreToolUse"), TIMEOUT),
        Err(ClientError::Version(2))
    ));
    h.join().unwrap();
}

#[test]
fn test_forward_treats_silence_as_failure() {
    let (_d, socket, h) = fake_daemon(None);
    assert!(matches!(
        forward(&socket, &event("PreToolUse"), TIMEOUT),
        Err(ClientError::Receive(_))
    ));
    h.join().unwrap();
}

#[test]
fn test_forward_rejects_non_json_payload_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let r = forward(&dir.path().join("none.sock"), b"{not json", TIMEOUT);
    assert!(matches!(r, Err(ClientError::Decode(_))), "{r:?}");
}
