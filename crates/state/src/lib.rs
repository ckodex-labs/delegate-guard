//! Per-session delegation state persisted across hook processes.
//!
//! Claude Code runs each hook as a separate process, and hooks for parallel
//! tool calls can run concurrently. Every read-modify-write therefore happens
//! under an exclusive `flock(2)` on a per-session lock file (`File::lock`),
//! and the state file is replaced atomically (write temp → fsync → rename).
//!
//! The session model itself lives in the kernel; this crate only persists it.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::hash::{BuildHasher, Hasher, RandomState};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub use delegate_guard_kernel::session::Session;
use sha2::{Digest, Sha256};

/// Errors from loading or saving session state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Hook input carried no session id.
    #[error("empty session_id")]
    EmptySessionId,
    /// A filesystem operation failed.
    #[error("{op} {}: {source}", .path.display())]
    Io {
        /// What was being done.
        op: &'static str,
        /// File or directory involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The state file is not valid JSON for [`Session`].
    #[error("corrupt state {}: {source}", .path.display())]
    Corrupt {
        /// State file.
        path: PathBuf,
        /// Decode error.
        #[source]
        source: serde_json::Error,
    },
    /// The session could not be encoded.
    #[error("encode state: {0}")]
    Encode(#[source] serde_json::Error),
}

fn io_err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> StateError + 'a {
    move |source| StateError::Io {
        op,
        path: path.to_owned(),
        source,
    }
}

/// Files that belong to one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPaths {
    /// JSON state.
    pub state: PathBuf,
    /// Lock file (contents unused).
    pub lock: PathBuf,
    /// Hash-chained receipt log.
    pub receipts: PathBuf,
}

const MAX_STEM: usize = 128;

/// Maps an untrusted `session_id` to a safe file name. Ids that are not plain
/// `[A-Za-z0-9_-]{1,128}` are hashed, so `../../etc/x` can never escape the
/// state directory.
#[must_use]
pub fn file_stem(session_id: &str) -> String {
    let plain = (1..=MAX_STEM).contains(&session_id.len())
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if plain {
        return session_id.to_owned();
    }
    let sum = Sha256::digest(session_id.as_bytes());
    format!("h-{}", hex(&sum[..16]))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// State, lock and receipt paths for a session.
#[must_use]
pub fn paths(dir: &Path, session_id: &str) -> SessionPaths {
    let stem = file_stem(session_id);
    SessionPaths {
        state: dir.join(format!("{stem}.json")),
        lock: dir.join(format!("{stem}.lock")),
        receipts: dir.join(format!("{stem}.receipts.jsonl")),
    }
}

/// Locks the session, loads it (empty `agents` ⇒ new session), runs `f`, and
/// saves the result atomically if `f` succeeds. The receipt path is passed so
/// `f` can append receipts under the same lock.
///
/// # Errors
///
/// Returns `f`'s error unchanged (state is then not saved), or a
/// [`StateError`] converted into `E` if locking, loading or saving fails.
pub fn with<T, E>(
    dir: &Path,
    session_id: &str,
    mutate: impl FnOnce(&mut Session, &Path) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<StateError>,
{
    if session_id.is_empty() {
        return Err(StateError::EmptySessionId.into());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_err("create", dir))?;
    let session_paths = paths(dir, session_id);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&session_paths.lock)
        .map_err(io_err("open", &session_paths.lock))?;
    // Exclusive flock; released when `lock` is dropped (fd closed).
    lock.lock().map_err(io_err("flock", &session_paths.lock))?;

    let mut session = load(&session_paths.state)?;
    let out = mutate(&mut session, &session_paths.receipts)?;
    save(dir, &session_paths.state, &session)?;
    drop(lock);
    Ok(out)
}

/// File stems of every session with state in `dir`, sorted. A missing `dir`
/// has no sessions.
///
/// # Errors
///
/// Fails if `dir` exists but cannot be listed.
pub fn list(dir: &Path) -> Result<Vec<String>, StateError> {
    let entries = match fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        r => r.map_err(io_err("list", dir))?,
    };
    let mut stems: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .filter_map(|n| n.strip_suffix(".json").map(str::to_owned))
        .collect();
    stems.sort();
    Ok(stems)
}

/// Reads a session without changing anything: no file is created, and the
/// read happens under a shared lock so it never sees a half-applied event.
/// `None` if the session has no state.
///
/// # Errors
///
/// Fails if the lock or state file cannot be read or the state is corrupt.
pub fn inspect(dir: &Path, session_id: &str) -> Result<Option<Session>, StateError> {
    let session_paths = paths(dir, session_id);
    let lock = match File::open(&session_paths.lock) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        r => r.map_err(io_err("open", &session_paths.lock))?,
    };
    lock.lock_shared()
        .map_err(io_err("flock", &session_paths.lock))?;
    if !session_paths.state.exists() {
        return Ok(None);
    }
    load(&session_paths.state).map(Some)
}

fn load(path: &Path) -> Result<Session, StateError> {
    match fs::read(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Session::default()),
        Err(e) => Err(io_err("read", path)(e)),
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| StateError::Corrupt {
            path: path.to_owned(),
            source,
        }),
    }
}

fn save(dir: &Path, state_path: &Path, session: &Session) -> Result<(), StateError> {
    let body = serde_json::to_vec_pretty(session).map_err(StateError::Encode)?;
    let (tmp_path, tmp) = create_temp(dir)?;
    let result = write_and_replace(tmp, &tmp_path, state_path, &body);
    if result.is_err() {
        // Best effort: the error being returned is the one that matters.
        let _ = fs::remove_file(&tmp_path);
    }
    result.map_err(io_err("replace", state_path))
}

fn write_and_replace(mut tmp: File, tmp_path: &Path, dest: &Path, body: &[u8]) -> io::Result<()> {
    tmp.write_all(body)?;
    tmp.sync_all()?;
    drop(tmp);
    fs::rename(tmp_path, dest)
}

const TEMP_ATTEMPTS: usize = 16;

/// Creates a fresh temp file with `O_EXCL` so a planted file or symlink at a
/// predictable name can never be written through.
fn create_temp(dir: &Path) -> Result<(PathBuf, File), StateError> {
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..TEMP_ATTEMPTS {
        let path = dir.join(format!(
            ".state-{:016x}",
            RandomState::new().build_hasher().finish()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(io_err("create temp in", dir)(e)),
        }
    }
    Err(io_err("create temp in", dir)(last))
}

#[cfg(test)]
mod tests {
    use delegate_guard_kernel::session::{Agent, MAIN_ACTOR};

    use super::*;

    /// 64 threads each open the lock file independently (separate open file
    /// descriptions, as separate hook processes would); no update may be lost.
    #[test]
    fn test_with_concurrent_increments_are_serialized() {
        const N: i64 = 64;
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|sc| {
            for _ in 0..N {
                sc.spawn(|| {
                    with::<_, StateError>(dir.path(), "s1", |s, _| {
                        s.agents.entry(MAIN_ACTOR.to_owned()).or_default().remaining += 1;
                        Ok(())
                    })
                    .unwrap();
                });
            }
        });
        let got =
            with::<_, StateError>(dir.path(), "s1", |s, _| Ok(s.agents[MAIN_ACTOR].remaining))
                .unwrap();
        assert_eq!(got, N, "lost updates");
    }

    #[test]
    fn test_file_stem_blocks_traversal() {
        let long = "a".repeat(200);
        for id in [
            "../../etc/passwd",
            "a/b",
            "x\0y",
            "x\u{0}y",
            long.as_str(),
            ".",
            "",
        ] {
            let stem = file_stem(id);
            assert!(
                stem.starts_with("h-") && !stem.contains(['/', '\\', '\0']),
                "unsafe stem {stem:?} for {id:?}"
            );
            assert_eq!(
                paths(Path::new("/var/dg"), id).state.parent(),
                Some(Path::new("/var/dg"))
            );
        }
        assert_eq!(
            file_stem("abc-123_X"),
            "abc-123_X",
            "plain ids stay readable"
        );
    }

    #[test]
    fn test_with_failed_closure_does_not_save() {
        let dir = tempfile::tempdir().unwrap();
        let r: Result<(), StateError> = with(dir.path(), "s", |s, _| {
            s.agents.insert(MAIN_ACTOR.to_owned(), Agent::default());
            Err(StateError::EmptySessionId)
        });
        assert!(r.is_err());
        assert!(
            !paths(dir.path(), "s").state.exists(),
            "state must not be written when f fails"
        );
    }

    #[test]
    fn test_with_corrupt_state_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(paths(dir.path(), "s").state, b"{not json").unwrap();
        let r = with::<_, StateError>(dir.path(), "s", |_, _| Ok(()));
        assert!(matches!(r, Err(StateError::Corrupt { .. })), "{r:?}");
    }

    #[test]
    fn test_inspect_and_list_never_create_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(inspect(dir.path(), "ghost").unwrap(), None);
        assert!(
            fs::read_dir(dir.path()).unwrap().next().is_none(),
            "inspect must not create files"
        );
        with::<_, StateError>(dir.path(), "s2", |s, _| {
            s.agents.insert(MAIN_ACTOR.to_owned(), Agent::default());
            Ok(())
        })
        .unwrap();
        assert_eq!(list(dir.path()).unwrap(), vec!["s2".to_owned()]);
        assert!(
            inspect(dir.path(), "s2")
                .unwrap()
                .unwrap()
                .agents
                .contains_key(MAIN_ACTOR)
        );
        assert_eq!(
            list(&dir.path().join("missing")).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_with_empty_session_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            with::<_, StateError>(dir.path(), "", |_, _| Ok(())),
            Err(StateError::EmptySessionId)
        ));
    }
}
