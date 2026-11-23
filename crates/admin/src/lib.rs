//! The daemon's admin API: `ckodex.delegateguard.v1.AdminService` (gRPC) on
//! its own Unix socket (ADR-0001 §3). Connections from uids that are neither
//! the daemon's nor allowlisted are dropped at accept, before any RPC is read.

mod client;
mod service;

pub use client::connect;
pub use service::{AdminContext, AdminError, serve};

/// Generated protobuf and gRPC types. Checked in, produced by
/// `scripts/gen-proto.sh` (isolated generator in `tools/codegen`); the Dagger
/// `proto` gate fails if this copy drifts from `proto/`.
#[allow(clippy::pedantic, missing_docs)]
pub mod pb {
    include!("generated/ckodex.delegateguard.v1.rs");
}
