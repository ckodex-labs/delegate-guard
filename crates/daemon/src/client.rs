//! The per-event client: one connection, one frame each way. Std only, so its
//! start-up cost matches the in-process binary.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use delegate_guard_hook::{EXIT_BLOCK, EXIT_ERROR, fail_code};

use crate::protocol::{FrameError, PROTOCOL_VERSION, Request, Response, read_frame, write_frame};

/// Why the daemon could not answer. Every variant means "fail closed".
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Socket missing, refused, or not ours to connect to.
    #[error("cannot connect to {}: {source}", .socket)]
    Connect {
        /// Socket path as given.
        socket: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// Sending failed or timed out.
    #[error("send: {0}")]
    Send(#[source] io::Error),
    /// No reply, a truncated or oversized reply, or a timeout (also what a peer-uid rejection looks like).
    #[error("no valid reply: {0}")]
    Receive(#[from] FrameError),
    /// The reply is not a valid [`Response`].
    #[error("malformed reply: {0}")]
    Decode(#[from] serde_json::Error),
    /// The daemon speaks another protocol version.
    #[error("daemon speaks protocol version {0}, client speaks {PROTOCOL_VERSION}")]
    Version(u32),
}

/// Sends the hook payload `raw` to the daemon at `socket` and returns its reply, with the exit
/// code clamped so the daemon can never block where blocking is wrong: anything
/// other than 0/1/2 becomes the event's fail code, and 2 outside `PreToolUse`
/// becomes 1.
///
/// # Errors
///
/// [`ClientError`] for any transport or protocol failure; the caller must exit
/// with `fail_code(event)`.
pub fn forward(socket: &Path, raw: &[u8], timeout: Duration) -> Result<Response, ClientError> {
    let event: serde_json::Value = serde_json::from_slice(raw)?;
    let name = event
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let mut stream = UnixStream::connect(socket).map_err(|source| ClientError::Connect {
        socket: socket.display().to_string(),
        source,
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(ClientError::Send)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(ClientError::Send)?;
    let body = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        event,
    })?;
    write_frame(&mut stream, &body).map_err(ClientError::Send)?;
    let mut response: Response = serde_json::from_slice(&read_frame(&mut stream)?)?;
    if response.v != PROTOCOL_VERSION {
        return Err(ClientError::Version(response.v));
    }
    response.exit = clamp_exit(response.exit, &name);
    Ok(response)
}

fn clamp_exit(exit: u8, event: &str) -> u8 {
    match exit {
        0 | EXIT_ERROR => exit,
        EXIT_BLOCK if event == "PreToolUse" => EXIT_BLOCK,
        EXIT_BLOCK => EXIT_ERROR,
        _ => fail_code(event),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_exit_never_blocks_outside_pre_tool_use() {
        assert_eq!(clamp_exit(2, "PreToolUse"), 2);
        assert_eq!(clamp_exit(2, "SubagentStop"), 1);
        assert_eq!(clamp_exit(7, "PreToolUse"), 2);
        assert_eq!(clamp_exit(7, "SubagentStop"), 1);
        assert_eq!(clamp_exit(0, "SubagentStop"), 0);
    }
}
