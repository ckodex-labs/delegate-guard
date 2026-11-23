//! Creating a listening socket safely: private directory, stale-socket
//! handling, restrictive umask at bind time. Shared by the hook and admin sockets.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use nix::sys::stat::{Mode, umask};

use crate::server::ServeError;

pub(crate) fn io_err<'a>(
    op: &'static str,
    path: &'a Path,
) -> impl FnOnce(io::Error) -> ServeError + 'a {
    move |source| ServeError::Io {
        op,
        path: path.to_owned(),
        source,
    }
}

/// Binds `socket` after checking its directory and clearing a stale socket,
/// creating it under umask 077 and then applying `mode`.
///
/// # Errors
///
/// [`ServeError`] if the directory is unsafe, a live listener owns the path, a
/// non-socket file is in the way, or binding fails.
pub fn bind_private(socket: &Path, mode: u32) -> Result<UnixListener, ServeError> {
    let dir = socket
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    prepare_dir(dir)?;
    clear_stale(socket)?;
    let previous = umask(Mode::from_bits_truncate(0o077));
    let bound = UnixListener::bind(socket);
    umask(previous);
    let listener = bound.map_err(io_err("bind", socket))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(mode))
        .map_err(io_err("chmod", socket))?;
    Ok(listener)
}

fn prepare_dir(dir: &Path) -> Result<(), ServeError> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(io_err("create", dir))?;
    }
    let mode = fs::metadata(dir)
        .map_err(io_err("stat", dir))?
        .permissions()
        .mode();
    if mode & 0o022 != 0 {
        return Err(ServeError::UnsafeDirectory(dir.to_owned()));
    }
    Ok(())
}

fn clear_stale(socket: &Path) -> Result<(), ServeError> {
    let Ok(meta) = fs::symlink_metadata(socket) else {
        return Ok(());
    };
    if !meta.file_type().is_socket() {
        return Err(ServeError::NotASocket(socket.to_owned()));
    }
    match UnixStream::connect(socket) {
        Ok(_) => Err(ServeError::AlreadyRunning(socket.to_owned())),
        Err(_) => fs::remove_file(socket).map_err(io_err("remove stale", socket)),
    }
}
