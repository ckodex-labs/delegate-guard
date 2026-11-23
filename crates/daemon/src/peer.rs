//! The connecting process's uid, from the kernel (not from anything it sends).

use std::io;
use std::os::unix::net::UnixStream;

/// Effective uid of the peer on `stream`.
///
/// # Errors
///
/// The kernel call fails, for example on a socket the peer already closed.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let (uid, _gid) = nix::unistd::getpeereid(stream)?;
    Ok(uid.as_raw())
}

/// Uid of the peer on `stream` (`SO_PEERCRED`, recorded at `connect`).
///
/// # Errors
///
/// The kernel call fails, for example on a socket the peer already closed.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(creds.uid())
}

/// This process's effective uid: the default and minimum allowlist.
#[must_use]
pub fn own_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Who may use a socket: the owner uid always, others only if listed. Root
/// gets no implicit pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    owner: u32,
    extra: Vec<u32>,
}

impl Allowlist {
    /// This process's uid plus `extra`. The only constructor the CLI uses.
    #[must_use]
    pub fn new(extra: Vec<u32>) -> Allowlist {
        Allowlist::with_owner(own_uid(), extra)
    }

    /// An explicit owner instead of this process's uid. Tests use it to stand
    /// in for a foreign peer, since a second account is rarely available.
    #[must_use]
    pub fn with_owner(owner: u32, extra: Vec<u32>) -> Allowlist {
        Allowlist { owner, extra }
    }

    /// Whether a peer with `uid` is admitted.
    #[must_use]
    pub fn admits(&self, uid: u32) -> bool {
        uid == self.owner || self.extra.contains(&uid)
    }

    /// The uid the socket belongs to (the daemon's own, outside tests).
    #[must_use]
    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// The uids admitted besides the owner.
    #[must_use]
    pub fn extra(&self) -> &[u32] {
        &self.extra
    }
}
