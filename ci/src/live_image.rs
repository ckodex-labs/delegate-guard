//! The live-test image: Claude Code, jq and a delegate-guard built from this
//! workspace, exported as an image archive. A microVM boots it with no network
//! pull, so its egress allowlist can stay closed (see
//! `scripts/live-matrix-smolvm.sh`). The image is built for the engine's
//! platform, which matches the host's microVM guests (arm64 on Apple Silicon).

use dagger_sdk::Container;

use crate::gates::Pipeline;

// Digest of the multi-arch index, resolved 2026-11-23 with `crane digest`.
const NODE_IMAGE: &str =
    "node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee";
/// The Claude Code version the live tests ran against on macOS.
const CLAUDE_CODE: &str = "2.1.330";
const APT: &str = "apt-get update -qq && apt-get install -y -qq --no-install-recommends jq ca-certificates procps acl && rm -rf /var/lib/apt/lists/*";

impl Pipeline<'_> {
    /// The live-test image. The guard binary sits at
    /// `/opt/dg/bin/delegate-guard`; tests run as the unprivileged `tester`.
    ///
    /// # Errors
    ///
    /// An SDK option builder rejects its input.
    pub fn live_image(&self) -> eyre::Result<Container> {
        let guard = self
            .base("live-image")?
            .with_exec(vec![
                "cargo",
                "build",
                "--locked",
                "--release",
                "-p",
                "delegate-guard",
            ])
            // The target directory is a cache mount, which is not part of the
            // container's filesystem; copy the binary out of it.
            .with_exec(vec![
                "cp",
                "/target/release/delegate-guard",
                "/delegate-guard",
            ])
            .file("/delegate-guard");
        Ok(self
            .client
            .container()
            .from(NODE_IMAGE)
            .with_exec(vec!["sh", "-c", APT])
            .with_exec(vec![
                "npm",
                "install",
                "--global",
                "--no-fund",
                "--no-audit",
                &format!("@anthropic-ai/claude-code@{CLAUDE_CODE}"),
            ])
            .with_exec(vec![
                "useradd",
                "--create-home",
                "--shell",
                "/bin/bash",
                "tester",
            ])
            .with_file("/opt/dg/bin/delegate-guard", guard))
    }
}
