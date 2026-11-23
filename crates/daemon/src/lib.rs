//! The shared delegate-guard daemon and its client (ADR-0001).
//!
//! One daemon serves every Claude Code session and agent on the machine. Each
//! hook event is one connection on a Unix socket: the client sends one frame,
//! the daemon runs the same `delegate-guard-hook` adapter as in-process mode and
//! answers one frame. The client owns the exit code, so every transport failure
//! fails closed on `PreToolUse`.
//!
//! Callers are authenticated by the socket's file permissions and the peer's
//! uid (`getpeereid` / `SO_PEERCRED`), with no credential exchanged.

pub mod client;
pub mod peer;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod socket;

pub use client::{ClientError, forward};
pub use peer::Allowlist;
pub use policy::{PolicyInfo, SharedPolicy};
pub use protocol::{PROTOCOL_VERSION, Request, Response};
pub use server::{ServeError, Server, ServerConfig};
pub use socket::bind_private;
