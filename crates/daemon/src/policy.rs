//! The policy in force, swappable at runtime. A reload that fails leaves the
//! last valid policy in force and records why (ADR-0001 §4).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use delegate_guard_hook::{Policy, ValidPolicy};
use jiff::Timestamp;
use sha2::{Digest, Sha256};

/// Identity and history of the policy in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInfo {
    /// sha256 of the file bytes in force.
    pub sha256: String,
    /// When they were loaded.
    pub loaded_at: Timestamp,
    /// Why the last reload was rejected; `None` if it applied.
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct Loaded {
    policy: Arc<ValidPolicy>,
    info: PolicyInfo,
}

/// A policy file and the last valid policy read from it.
#[derive(Debug)]
pub struct SharedPolicy {
    path: PathBuf,
    loaded: RwLock<Loaded>,
}

fn read(path: &Path) -> Result<(Arc<ValidPolicy>, String), String> {
    let bytes = fs::read(path).map_err(|e| format!("policy {}: {e}", path.display()))?;
    let policy =
        Policy::from_json(&bytes).map_err(|e| format!("policy {}: {e}", path.display()))?;
    Ok((Arc::new(policy), hex(&Sha256::digest(&bytes))))
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

impl SharedPolicy {
    /// Loads `path`; the daemon does not start without a valid policy.
    ///
    /// # Errors
    ///
    /// A message naming the file and the read, decode or validation failure.
    pub fn load(path: &Path, now: Timestamp) -> Result<SharedPolicy, String> {
        let (policy, sha256) = read(path)?;
        let info = PolicyInfo {
            sha256,
            loaded_at: now,
            last_error: None,
        };
        Ok(SharedPolicy {
            path: path.to_owned(),
            loaded: RwLock::new(Loaded { policy, info }),
        })
    }

    /// The policy file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The policy in force. Callers hold the `Arc` for one decision, so a
    /// concurrent reload never changes a decision halfway.
    #[must_use]
    pub fn current(&self) -> Arc<ValidPolicy> {
        Arc::clone(
            &self
                .loaded
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .policy,
        )
    }

    /// Identity and reload history of the policy in force.
    #[must_use]
    pub fn info(&self) -> PolicyInfo {
        self.loaded
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .info
            .clone()
    }

    /// Re-reads the file. On success the new policy is in force; on failure the
    /// previous one stays and the error is recorded.
    ///
    /// # Errors
    ///
    /// The read, decode or validation failure; nothing changed except
    /// `info().last_error`.
    pub fn reload(&self, now: Timestamp) -> Result<PolicyInfo, String> {
        let result = read(&self.path);
        let mut loaded = self.loaded.write().unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok((policy, sha256)) => {
                *loaded = Loaded {
                    policy,
                    info: PolicyInfo {
                        sha256,
                        loaded_at: now,
                        last_error: None,
                    },
                };
                Ok(loaded.info.clone())
            }
            Err(e) => {
                loaded.info.last_error = Some(e.clone());
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"root":{"tools":["Read"],"max_calls":1,"ttl":"1h"},"pending_ttl":"1m"}"#;
    const OTHER: &str =
        r#"{"root":{"tools":["Grep"],"max_calls":2,"ttl":"1h"},"pending_ttl":"1m"}"#;

    #[test]
    fn test_reload_rejects_invalid_and_keeps_last_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        fs::write(&path, GOOD).unwrap();
        let shared = SharedPolicy::load(&path, Timestamp::UNIX_EPOCH).unwrap();
        let before = shared.info().sha256;
        fs::write(&path, r#"{"root":{"tools":["*"]}}"#).unwrap();
        assert!(shared.reload(Timestamp::UNIX_EPOCH).is_err());
        assert_eq!(
            shared.current().root.tools,
            vec!["Read".to_owned()],
            "last valid policy stays in force"
        );
        assert_eq!(shared.info().sha256, before);
        assert!(shared.info().last_error.is_some());
        fs::write(&path, OTHER).unwrap();
        let after = shared.reload(Timestamp::UNIX_EPOCH).unwrap();
        assert_ne!(after.sha256, before);
        assert_eq!(after.last_error, None, "a good reload clears the error");
        assert_eq!(shared.current().root.tools, vec!["Grep".to_owned()]);
    }
}
