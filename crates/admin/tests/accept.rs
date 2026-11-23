//! The admin server's accept filter, wired end to end: a peer the allowlist
//! does not admit is dropped before any RPC is read. The test runs as one user,
//! so it names a foreign owner to stand in for a foreign peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use delegate_guard_admin::pb::HealthRequest;
use delegate_guard_admin::{AdminContext, connect, serve};
use delegate_guard_daemon::peer::own_uid;
use delegate_guard_daemon::{Allowlist, SharedPolicy, bind_private};
use jiff::Timestamp;

const POLICY: &str = r#"{"root":{"tools":["Read"],"max_calls":5,"ttl":"1h"},"pending_ttl":"1m"}"#;

fn start(dir: &Path, allowed: Allowlist) -> PathBuf {
    std::fs::write(dir.join("policy.json"), POLICY).unwrap();
    let socket = dir.join("run/admin.sock");
    let listener = bind_private(&socket, 0o600).unwrap();
    let ctx = AdminContext {
        version: "test".to_owned(),
        started_at: Timestamp::now(),
        hook_socket: dir.join("run/hook.sock"),
        state_dir: dir.join("state"),
        policy: Arc::new(SharedPolicy::load(&dir.join("policy.json"), Timestamp::now()).unwrap()),
    };
    tokio::spawn(serve(listener, ctx, allowed));
    socket
}

/// Health over a fresh connection; any transport or RPC failure is `Err`.
async fn health(socket: &Path) -> Result<(), String> {
    let mut client = connect(socket).await.map_err(|e| e.to_string())?;
    client
        .health(HealthRequest {})
        .await
        .map(drop)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn test_admin_refuses_unadmitted_peer() {
    let dir = tempfile::tempdir().unwrap();
    let foreign_owner = own_uid().wrapping_add(1);
    let socket = start(dir.path(), Allowlist::with_owner(foreign_owner, vec![]));
    assert!(
        health(&socket).await.is_err(),
        "an unadmitted peer got an answer"
    );

    let other_list = tempfile::tempdir().unwrap();
    let socket = start(
        other_list.path(),
        Allowlist::with_owner(foreign_owner, vec![foreign_owner.wrapping_add(1)]),
    );
    assert!(
        health(&socket).await.is_err(),
        "a list without the caller still refuses it"
    );
}

#[tokio::test]
async fn test_admin_admits_owner_and_listed_peer() {
    let owner = tempfile::tempdir().unwrap();
    let socket = start(owner.path(), Allowlist::new(vec![]));
    health(&socket).await.unwrap();

    let listed = tempfile::tempdir().unwrap();
    let foreign_owner = own_uid().wrapping_add(1);
    let socket = start(
        listed.path(),
        Allowlist::with_owner(foreign_owner, vec![own_uid()]),
    );
    health(&socket).await.unwrap();
}
