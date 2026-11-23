//! The gates: one container per check, built lazily; nothing runs until a
//! gate is synced.

use dagger_sdk::{Container, ContainerWithDirectoryOptsBuilder, Directory, Query};

// Tags are for readers; the digest (multi-arch index, resolved 2026-11-22 with
// `crane digest`) is what is pulled.
const RUST_IMAGE: &str =
    "rust:1.95-slim@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0";
const BUF_IMAGE: &str =
    "bufbuild/buf:1.75.0@sha256:adf82c7170be6629ec81dc907921ac1699407cd11c4f7fd7521b13c74152f849";
const AUDIT_VER: &str = "0.22.1";
const DENY_VER: &str = "0.19.0";
const TOOLS_PATH: &str = "/tools/bin:/cargo-home/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// One named check.
pub struct Gate {
    /// Name in the report.
    pub name: &'static str,
    /// The container whose successful sync is the check.
    pub container: Container,
}

/// What every gate is built from.
pub struct Pipeline<'a> {
    /// The Dagger session.
    pub client: &'a Query,
    /// The workspace (without `target/` or `.git/`).
    pub source: Directory,
    /// Prefix for cache volume names; change it to force a cold build.
    pub cache_prefix: String,
}

impl Pipeline<'_> {
    /// Every gate: rustfmt, clippy (pedantic, warnings denied), debug and
    /// release tests, cargo-audit, cargo-deny, buf lint and format, and
    /// generated-code drift. With `advisory_db`, no gate fetches advisories.
    ///
    /// # Errors
    ///
    /// An SDK option builder rejects its input.
    pub fn gates(&self, advisory_db: Option<Directory>) -> eyre::Result<Vec<Gate>> {
        let run = |profile: &str, args: &[&str]| -> eyre::Result<Container> {
            Ok(self.base(profile)?.with_exec(args.to_vec()))
        };
        let (audit, deny) = self.audit_gates(advisory_db)?;
        Ok(vec![
            gate("fmt", run("fmt", &["cargo", "fmt", "--all", "--check"])?),
            gate(
                "clippy",
                run(
                    "clippy",
                    &[
                        "cargo",
                        "clippy",
                        "--workspace",
                        "--all-targets",
                        "--locked",
                        "--",
                        "-D",
                        "warnings",
                    ],
                )?,
            ),
            gate(
                "test",
                run("debug", &["cargo", "test", "--workspace", "--locked"])?,
            ),
            gate(
                "test-release",
                run(
                    "release",
                    &["cargo", "test", "--workspace", "--locked", "--release"],
                )?,
            ),
            gate("audit", audit),
            gate("deny", deny),
            gate("proto", self.proto()?),
            gate("codegen", self.codegen()?),
        ])
    }

    /// The Rust toolchain with the workspace mounted and per-profile target
    /// caches, so gates run concurrently without contending on cargo's
    /// build-directory lock. The whole `CARGO_HOME` is shared, including its
    /// package-cache lock, so downloads and unpacking serialize instead of racing.
    pub(crate) fn base(&self, profile: &str) -> eyre::Result<Container> {
        let cache = |name: &str| {
            self.client
                .cache_volume(format!("{}{name}", self.cache_prefix))
        };
        Ok(self
            .client
            .container()
            .from(RUST_IMAGE)
            .with_exec(vec!["rustup", "component", "add", "rustfmt", "clippy"])
            .with_mounted_cache("/cargo-home", cache("cargo-home"))
            .with_env_variable("CARGO_HOME", "/cargo-home")
            .with_mounted_cache("/target", cache(&format!("target-{profile}")))
            .with_env_variable("CARGO_TARGET_DIR", "/target")
            .with_directory_opts(
                "/src",
                self.source.clone(),
                ContainerWithDirectoryOptsBuilder::default()
                    .exclude(vec!["target/", ".git/"])
                    .build()?,
            )
            .with_workdir("/src"))
    }

    /// cargo-audit and cargo-deny (pinned, cached across runs). Offline,
    /// cargo-deny skips its advisory check, which needs its own fetched
    /// database; cargo-audit covers advisories from the mounted clone.
    fn audit_gates(&self, advisory_db: Option<Directory>) -> eyre::Result<(Container, Container)> {
        let tools = self.client.cache_volume(format!(
            "{}tools-audit{AUDIT_VER}-deny{DENY_VER}",
            self.cache_prefix
        ));
        let mut base = self
            .base("audit")?
            .with_exec(vec!["sh", "-c", "apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev"])
            .with_mounted_cache("/tools", tools)
            .with_exec(vec!["cargo", "install", "--locked", "--root", "/tools", &format!("cargo-audit@{AUDIT_VER}"), &format!("cargo-deny@{DENY_VER}")])
            .with_env_variable("PATH", TOOLS_PATH);
        let mut audit = vec!["cargo", "audit", "--deny", "warnings"];
        let mut deny = vec!["cargo", "deny", "check"];
        if let Some(db) = advisory_db {
            base = base.with_mounted_directory("/advisory-db", db);
            audit.extend(["--db", "/advisory-db", "--no-fetch"]);
            deny.extend(["bans", "licenses", "sources"]);
        }
        Ok((base.with_exec(audit), base.with_exec(deny)))
    }

    /// buf lint and format check of the gRPC contract.
    fn proto(&self) -> eyre::Result<Container> {
        Ok(self
            .client
            .container()
            .from(BUF_IMAGE)
            .with_directory_opts(
                "/src",
                self.source.clone(),
                ContainerWithDirectoryOptsBuilder::default()
                    .include(vec!["buf.yaml", "proto/"])
                    .build()?,
            )
            .with_workdir("/src")
            .with_exec(vec!["buf", "lint"])
            .with_exec(vec!["buf", "format", "-d", "--exit-code"]))
    }

    /// Regenerates the admin API code with the isolated generator
    /// (`tools/codegen`, its own lockfile) and fails if the checked-in copy differs.
    fn codegen(&self) -> eyre::Result<Container> {
        Ok(self
            .base("codegen")?
            .with_exec(vec![
                "cargo",
                "run",
                "--locked",
                "--manifest-path",
                "tools/codegen/Cargo.toml",
                "--",
                "proto",
                "/tmp/generated",
            ])
            .with_exec(vec![
                "diff",
                "-r",
                "/tmp/generated",
                "crates/admin/src/generated",
            ]))
    }
}

fn gate(name: &'static str, container: Container) -> Gate {
    Gate { name, container }
}
