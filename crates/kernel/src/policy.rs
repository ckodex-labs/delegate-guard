//! The policy: what the root holds and what each subagent type may ask its
//! parent to delegate. Anything not listed is denied.
//!
//! Parse, don't validate: the kernel only accepts a [`ValidPolicy`], and the only
//! ways to get one are [`Policy::from_json`] and `ValidPolicy::try_from`, which
//! both run [`Policy::validate`].

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::ops::Deref;

use jiff::SignedDuration;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::duration::parse_go_duration;

/// A grant request: for the root, what the main thread holds; for a subagent
/// type, what it asks its parent to delegate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Profile {
    /// Exact tool names. Must be non-empty; `*` is rejected.
    pub tools: Vec<String>,
    /// Tool-call budget.
    pub max_calls: i64,
    /// Lifetime, Go syntax (`"10m"`).
    #[serde(deserialize_with = "go_duration")]
    pub ttl: SignedDuration,
}

/// Guard configuration as written. Unknown fields are rejected so a typo cannot
/// silently widen or drop a constraint. Not usable by the kernel until validated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// What the main thread holds.
    pub root: Profile,
    /// Deepest allowed delegation; agents at this depth cannot spawn.
    pub max_depth: i64,
    /// Admitted spawns that never start are refunded after this long.
    #[serde(deserialize_with = "go_duration")]
    pub pending_ttl: SignedDuration,
    /// Delegation profile per subagent type. A type listed twice is rejected.
    #[serde(deserialize_with = "unique_profiles")]
    pub profiles: BTreeMap<String, Profile>,
    /// Bind each subagent to its exact spawning `Agent` call using the
    /// undocumented `agent-<id>.meta.json` file Claude Code writes. Off by
    /// default; see the README for the trust model.
    pub sidecar_binding: bool,
}

/// A policy that passed [`Policy::validate`]. Read-only: it derefs to
/// [`Policy`] but cannot be mutated back into an invalid state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidPolicy(Policy);

impl Deref for ValidPolicy {
    type Target = Policy;

    fn deref(&self) -> &Policy {
        &self.0
    }
}

impl TryFrom<Policy> for ValidPolicy {
    type Error = PolicyError;

    fn try_from(policy: Policy) -> Result<Self, PolicyError> {
        policy.validate()?;
        Ok(ValidPolicy(policy))
    }
}

fn go_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SignedDuration, D::Error> {
    let text = String::deserialize(deserializer).map_err(|e| {
        serde::de::Error::custom(format!("duration must be a string like \"20m\": {e}"))
    })?;
    parse_go_duration(&text).map_err(serde::de::Error::custom)
}

/// Profiles keyed by subagent type, rejecting a key that appears twice: a plain
/// map would keep the last entry, which is not the one a reader sees first.
fn unique_profiles<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Profile>, D::Error> {
    struct Unique;

    impl<'de> Visitor<'de> for Unique {
        type Value = BTreeMap<String, Profile>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map from subagent type to profile")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut profiles = BTreeMap::new();
            while let Some((name, profile)) = map.next_entry::<String, Profile>()? {
                match profiles.entry(name) {
                    Entry::Vacant(slot) => {
                        slot.insert(profile);
                    }
                    Entry::Occupied(slot) => {
                        return Err(de::Error::custom(format!(
                            "duplicate profile {:?}",
                            slot.key()
                        )));
                    }
                }
            }
            Ok(profiles)
        }
    }

    deserializer.deserialize_map(Unique)
}

/// Why a policy cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The document does not decode (syntax, types, unknown fields).
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    /// The policy decodes but breaks a rule; every violation is listed.
    #[error("{}", .0.join("; "))]
    Invalid(Vec<String>),
}

impl Policy {
    /// Decodes and validates a policy document.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Parse`] if it does not decode (including unknown fields),
    /// [`PolicyError::Invalid`] if it breaks a rule.
    pub fn from_json(bytes: &[u8]) -> Result<ValidPolicy, PolicyError> {
        let policy: Policy = serde_json::from_slice(bytes)?;
        ValidPolicy::try_from(policy)
    }

    /// Rejects policies that would be ambiguous or permissive by accident.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Invalid`] listing every violation.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut errors = Vec::new();
        check_profile("root", &self.root, &mut errors);
        for (name, profile) in &self.profiles {
            check_profile(&format!("profiles.{name}"), profile, &mut errors);
        }
        if self.max_depth < 0 {
            errors.push("max_depth must be >= 0".to_owned());
        }
        if !self.pending_ttl.is_positive() {
            errors.push("pending_ttl must be > 0".to_owned());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::Invalid(errors))
        }
    }
}

fn check_profile(name: &str, profile: &Profile, errors: &mut Vec<String>) {
    if profile.tools.is_empty() {
        errors.push(format!("{name}: tools must be non-empty"));
    }
    for tool in profile.tools.iter().filter(|t| t.is_empty() || *t == "*") {
        errors.push(format!(
            "{name}: tool {tool:?} not allowed (list tools explicitly)"
        ));
    }
    if profile.max_calls <= 0 {
        errors.push(format!("{name}: max_calls must be > 0"));
    }
    if !profile.ttl.is_positive() {
        errors.push(format!("{name}: ttl must be > 0"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_policy_rejects_invalid_policy() {
        let bad = Policy {
            root: Profile {
                tools: vec!["*".into()],
                ..Profile::default()
            },
            ..Policy::default()
        };
        let err = ValidPolicy::try_from(bad).unwrap_err().to_string();
        for want in [
            r#""*" not allowed"#,
            "max_calls must be > 0",
            "ttl must be > 0",
            "pending_ttl must be > 0",
        ] {
            assert!(err.contains(want), "{err} lacks {want}");
        }
    }

    #[test]
    fn test_from_json_rejects_unknown_field() {
        let err = Policy::from_json(br#"{"root":{"tools":["Read"],"max_calls":1,"ttl":"1h"},"pending_ttl":"1m","sidecar_bindng":true}"#);
        assert!(matches!(err, Err(PolicyError::Parse(_))), "{err:?}");
    }

    /// A reviewer reads the first entry; a parser that keeps the last one would
    /// enforce a policy nobody reviewed.
    #[test]
    fn test_from_json_rejects_duplicate_profile() {
        let doc = br#"{"root":{"tools":["Read"],"max_calls":1,"ttl":"1h"},"pending_ttl":"1m",
            "profiles":{"Explore":{"tools":["Read"],"max_calls":1,"ttl":"1m"},
                        "Explore":{"tools":["Bash","Read"],"max_calls":99,"ttl":"9h"}}}"#;
        let err = Policy::from_json(doc).unwrap_err().to_string();
        assert!(err.contains("duplicate profile \"Explore\""), "{err}");
    }

    #[test]
    fn test_from_json_rejects_duplicate_field() {
        let doc = br#"{"root":{"tools":["Read"],"max_calls":1,"ttl":"1h"},"pending_ttl":"1m",
            "max_depth":0,"max_depth":5}"#;
        let err = Policy::from_json(doc).unwrap_err().to_string();
        assert!(err.contains("duplicate field"), "{err}");
    }

    #[test]
    fn test_from_json_accepts_minimal_policy() {
        let p = Policy::from_json(
            br#"{"root":{"tools":["Read"],"max_calls":1,"ttl":"1h"},"pending_ttl":"1m"}"#,
        )
        .unwrap();
        assert_eq!(
            (p.max_depth, p.sidecar_binding, p.root.max_calls),
            (0, false, 1)
        );
    }
}
