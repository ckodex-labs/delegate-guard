//! The daemon: accept loop, per-connection handling, socket setup.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use delegate_guard_hook::{Input, Outcome, fail_code, handle_as};
use jiff::Timestamp;

use crate::peer::{Allowlist, peer_uid};
use crate::policy::SharedPolicy;
use crate::protocol::{PROTOCOL_VERSION, Request, Response, read_frame, write_frame};
use crate::socket::bind_private;

/// Everything the daemon needs; built and validated by the caller.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Hook socket path.
    pub socket: PathBuf,
    /// Session state directory.
    pub state_dir: PathBuf,
    /// Policy applied to every session; reloadable through the admin API.
    pub policy: Arc<SharedPolicy>,
    /// Peers allowed to submit events (the daemon's own uid and a list).
    pub allowed: Allowlist,
    /// Socket file mode (0o600 for a per-user daemon, 0o660 with a group for Tier S).
    pub socket_mode: u32,
    /// Connections handled at once; extra ones are closed (clients fail closed).
    pub max_connections: usize,
    /// Read and write deadline per connection.
    pub io_timeout: Duration,
}

/// Why the daemon could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// A filesystem or socket operation failed.
    #[error("{op} {}: {source}", .path.display())]
    Io {
        /// What was being done.
        op: &'static str,
        /// Path involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// Another daemon is accepting on the socket.
    #[error("another delegate-guard daemon is listening on {}", .0.display())]
    AlreadyRunning(PathBuf),
    /// Something other than a socket sits at the socket path; it is not removed.
    #[error("{} exists and is not a socket; refusing to replace it", .0.display())]
    NotASocket(PathBuf),
    /// The socket directory is writable by other users, who could swap the socket.
    #[error("{} is writable by group or others; use a private directory", .0.display())]
    UnsafeDirectory(PathBuf),
}

/// A bound daemon, ready to [`Server::run`].
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    config: Arc<ServerConfig>,
    active: Arc<AtomicUsize>,
}

impl Server {
    /// Prepares the socket directory, clears a stale socket, binds and applies
    /// the socket mode.
    ///
    /// # Errors
    ///
    /// [`ServeError`] if the directory is unsafe, a live daemon owns the socket,
    /// a non-socket file is in the way, or binding fails.
    pub fn bind(config: ServerConfig) -> Result<Server, ServeError> {
        let listener = bind_private(&config.socket, config.socket_mode)?;
        Ok(Server {
            listener,
            config: Arc::new(config),
            active: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Accepts connections until the process ends. Every decision is persisted
    /// before its reply, so killing the daemon at any point loses nothing that
    /// was acknowledged.
    pub fn run(self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => self.dispatch(stream),
                Err(e) => eprintln!("delegate-guard serve: accept: {e}"),
            }
        }
    }

    /// Starts `run` on a background thread (tests and embedding).
    #[must_use]
    pub fn spawn(self) -> thread::JoinHandle<()> {
        thread::spawn(move || self.run())
    }

    fn dispatch(&self, stream: UnixStream) {
        if self.active.fetch_add(1, Ordering::SeqCst) >= self.config.max_connections {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return; // dropped: the client fails closed
        }
        let slot = Slot(Arc::clone(&self.active));
        let config = Arc::clone(&self.config);
        thread::spawn(move || {
            let _slot = slot; // released on return or panic
            serve_connection(&stream, &config);
        });
    }
}

/// Decrements the active-connection count when dropped, including on panic.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve_connection(stream: &UnixStream, config: &ServerConfig) {
    let uid = match peer_uid(stream) {
        Ok(uid) if config.allowed.admits(uid) => uid,
        Ok(_) => return, // closed without a reply: the client applies its own fail code
        Err(e) => {
            eprintln!("delegate-guard serve: peer credentials: {e}");
            return;
        }
    };
    // Deadlines bound how long a slow or stuck peer can hold a slot.
    if stream.set_read_timeout(Some(config.io_timeout)).is_err()
        || stream.set_write_timeout(Some(config.io_timeout)).is_err()
    {
        return;
    }
    let mut reader = stream;
    let Ok(body) = read_frame(&mut reader) else {
        return;
    };
    let response = respond(&body, config, uid);
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let mut writer = stream;
        let _ = write_frame(&mut writer, &bytes); // a vanished client fails closed on its side
    }
}

/// Where a caller's sessions live and whose sidecars it may bind through. The
/// owner keeps the flat layout; any other admitted uid (Tier S) gets its own
/// `uid-<n>` directory and only its own sidecar files.
fn caller_scope(config: &ServerConfig, uid: u32) -> (PathBuf, Option<u32>) {
    if uid == config.allowed.owner() {
        (config.state_dir.clone(), None)
    } else {
        (config.state_dir.join(format!("uid-{uid}")), Some(uid))
    }
}

fn respond(body: &[u8], config: &ServerConfig, uid: u32) -> Response {
    let reply = |out: Outcome| Response {
        v: PROTOCOL_VERSION,
        exit: out.exit,
        stdout: out.stdout,
        stderr: out.stderr,
    };
    let request: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return reply(failure("PreToolUse", &format!("malformed request: {e}"))),
    };
    let event = request
        .event
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if request.v != PROTOCOL_VERSION {
        return reply(failure(
            &event,
            &format!(
                "unsupported protocol version {} (daemon speaks {PROTOCOL_VERSION})",
                request.v
            ),
        ));
    }
    let input = match Input::from_value(request.event) {
        Ok(i) => i,
        Err(e) => {
            return reply(failure(
                &event,
                &format!("malformed hook input, failing closed: {e}"),
            ));
        }
    };
    if input.session_id.is_empty() {
        return reply(failure(&event, "hook input has no session_id"));
    }
    let (dir, sidecar_owner) = caller_scope(config, uid);
    reply(handle_as(
        &dir,
        &config.policy.current(),
        &input,
        Timestamp::now(),
        sidecar_owner,
    ))
}

fn failure(event: &str, msg: &str) -> Outcome {
    Outcome {
        exit: fail_code(event),
        stdout: String::new(),
        stderr: format!("delegate-guard: {msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_allowed_only_own_or_listed_uids() {
        let own = crate::peer::own_uid();
        let other = own.wrapping_add(1);
        assert!(Allowlist::new(vec![]).admits(own));
        assert!(Allowlist::new(vec![other]).admits(other));
        assert!(
            !Allowlist::new(vec![]).admits(other),
            "an unlisted uid is refused"
        );
        if own != 0 {
            assert!(
                !Allowlist::new(vec![other]).admits(0),
                "root is not implicitly allowed"
            );
        }
    }
}
