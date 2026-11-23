//! The hook server's accept check, wired end to end: a peer the allowlist does
//! not admit gets no reply, so the client fails closed. The test runs as one
//! user, so it names a foreign owner to stand in for a foreign peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use delegate_guard_daemon::peer::own_uid;
use delegate_guard_daemon::{Allowlist, ClientError, Server, ServerConfig, SharedPolicy, forward};
use jiff::Timestamp;

const POLICY: &str = r#"{"root":{"tools":["Read"],"max_calls":5,"ttl":"1h"},"pending_ttl":"1m"}"#;
const EVENT: &[u8] =
    br#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"t"}"#;

fn start(dir: &Path, allowed: Allowlist) -> std::path::PathBuf {
    std::fs::write(dir.join("policy.json"), POLICY).unwrap();
    let socket = dir.join("run/hook.sock");
    let config = ServerConfig {
        socket: socket.clone(),
        state_dir: dir.join("state"),
        policy: Arc::new(SharedPolicy::load(&dir.join("policy.json"), Timestamp::now()).unwrap()),
        allowed,
        socket_mode: 0o600,
        max_connections: 4,
        io_timeout: Duration::from_secs(5),
    };
    drop(Server::bind(config).unwrap().spawn());
    socket
}

/// The refused peer gets no reply. Depending on how fast the daemon closes the
/// connection, the client sees that while writing (broken pipe) or reading
/// (no frame); both fail closed.
fn no_reply(result: &Result<u8, ClientError>) -> bool {
    matches!(result, Err(ClientError::Send(_) | ClientError::Receive(_)))
}

fn send(socket: &Path) -> Result<u8, ClientError> {
    forward(socket, EVENT, Duration::from_secs(5)).map(|r| r.exit)
}

#[test]
fn test_server_refuses_unadmitted_peer_without_reply() {
    let dir = tempfile::tempdir().unwrap();
    let foreign_owner = own_uid().wrapping_add(1);
    let socket = start(dir.path(), Allowlist::with_owner(foreign_owner, vec![]));
    let refused = send(&socket);
    assert!(no_reply(&refused), "{refused:?}");
    assert!(
        !dir.path().join("state").exists(),
        "a refused peer must not reach the state directory"
    );

    let other_list = tempfile::tempdir().unwrap();
    let socket = start(
        other_list.path(),
        Allowlist::with_owner(foreign_owner, vec![foreign_owner.wrapping_add(1)]),
    );
    let refused = send(&socket);
    assert!(
        no_reply(&refused),
        "a list without the caller still refuses it: {refused:?}"
    );
}

#[test]
fn test_server_admits_owner_and_listed_peer() {
    let owner = tempfile::tempdir().unwrap();
    let socket = start(owner.path(), Allowlist::new(vec![]));
    assert_eq!(
        send(&socket).unwrap(),
        0,
        "the daemon's own uid is admitted"
    );

    let listed = tempfile::tempdir().unwrap();
    let foreign_owner = own_uid().wrapping_add(1);
    let socket = start(
        listed.path(),
        Allowlist::with_owner(foreign_owner, vec![own_uid()]),
    );
    assert_eq!(send(&socket).unwrap(), 0, "a listed uid is admitted");
}

/// Tier S: a listed peer's sessions live under `uid-<n>/`, so one user cannot
/// name another user's session id and spend its budget. The owner's stay flat,
/// which keeps a per-user daemon sharing state with in-process mode.
#[test]
fn test_listed_peer_sessions_are_kept_apart_from_the_owners() {
    let listed = tempfile::tempdir().unwrap();
    let foreign_owner = own_uid().wrapping_add(1);
    let socket = start(
        listed.path(),
        Allowlist::with_owner(foreign_owner, vec![own_uid()]),
    );
    assert_eq!(send(&socket).unwrap(), 0);
    let state = listed.path().join("state");
    assert!(state.join(format!("uid-{}/s.json", own_uid())).is_file());
    assert!(
        !state.join("s.json").exists(),
        "a listed peer must not write the shared namespace"
    );

    let owner = tempfile::tempdir().unwrap();
    let socket = start(owner.path(), Allowlist::new(vec![]));
    assert_eq!(send(&socket).unwrap(), 0);
    assert!(owner.path().join("state/s.json").is_file());
}
