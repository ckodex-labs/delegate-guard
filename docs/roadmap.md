# Roadmap

Each phase ends with the full gate green: `dagger run cargo run --locked
--manifest-path ci/Cargo.toml -- check` (fmt, clippy pedantic, debug and
release tests, cargo-audit, cargo-deny, buf, codegen drift), README evidence
updated with measured numbers, and every stub listed with `TODO(ckodex)`.

| Phase | Scope | Exit criteria |
| --- | --- | --- |
| 1 (done 2026-11-22) | Pure kernel crate, `ValidPolicy`, `onFailure: "block"` templates, Apache-2.0, `deny.toml`, Dagger `check` | behaviour unchanged (all tests, 23 planted bugs caught), kernel has no I/O dependencies |
| 2 (done 2026-11-22) | Daemon hook path: `serve`, `hook --socket`, framed JSON, peer-uid check, per-session serialization | e2e through a live socket; daemon-down and garbage-frame cases fail closed; 50-process contention test via the daemon |
| 3 (done 2026-11-22) | gRPC admin API (`proto/`, Buf v2), `delegate-guard admin …` | admin socket separate from hook socket; reload keeps last valid policy |
| 4 (partly done 2026-11-23) | Service integration: launchd (agent + daemon), systemd (user + system; socket activation deferred, ADR-0001), Tier S install, sidecar ACL helper | install and uninstall documented and tested on macOS and Linux. Done: Tier U on both, Tier S on Linux in a microVM without systemd. Open: Tier S under a running systemd, Tier S on macOS (both need root on a real host) |
| 5 | Release pipeline: multi-arch builds, SBOM, checksums, cosign, SLSA provenance, deb/rpm, OCI image + artifacts, air-gap bundle, Homebrew tap, Claude Code plugin | offline verification of the bundle succeeds in a network-less container |
| 6 | Windows port and Authenticode signing via `ck-vaultd` | Windows e2e green; signed artifacts verify |
| — | Live test against an authenticated Claude Code (`scripts/live-test.sh`) | pending since the Go version; needed before any production claim |
