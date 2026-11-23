//! Generates `crates/admin/src/generated/` from `proto/` with protox (a
//! pure-Rust protobuf compiler, no system `protoc`).
//!
//!     cargo run --locked --manifest-path tools/codegen/Cargo.toml -- <proto_root> <out_dir>

use std::path::PathBuf;

const FILE: &str = "ckodex/delegateguard/v1/admin.proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(proto_root), Some(out_dir)) = (args.next(), args.next()) else {
        return Err("usage: delegate-guard-codegen <proto_root> <out_dir>".into());
    };
    std::fs::create_dir_all(&out_dir)?;
    let descriptors = protox::compile([FILE], [&proto_root])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .out_dir(&out_dir)
        .compile_fds(descriptors)?;
    Ok(())
}
