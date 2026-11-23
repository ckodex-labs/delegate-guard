//! The delegate-guard pipeline, written with the Dagger Rust SDK. Every build,
//! lint, test and audit step runs here; CI configuration only runs this.
//!
//! ```sh
//! dagger run cargo run --locked --manifest-path ci/Cargo.toml -- check
//! dagger run cargo run --locked --manifest-path ci/Cargo.toml -- check --advisory-db ./advisory-db
//! dagger run cargo run --locked --manifest-path ci/Cargo.toml -- live-image --out ./dg-live.tar
//! ```
//!
//! Always start it through `dagger run`, which hands it the CLI's session.
//! Started any other way it exits 69, because the SDK would otherwise download
//! a Dagger CLI from the network.
//!
//! The Rust SDK is a client library, not a module SDK: engine v0.21.12 rejects
//! `dagger init --sdk=rust`. So this is a binary, not a module behind `dagger call`.

mod gates;
mod live_image;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use dagger_sdk::{ContainerExportOptsBuilder, HostDirectoryOpts, ImageMediaTypes};

use crate::gates::Pipeline;

/// `EX_USAGE`: bad arguments.
const EXIT_USAGE: u8 = 64;
/// `EX_UNAVAILABLE`: not started under `dagger run`.
const EXIT_UNAVAILABLE: u8 = 69;
/// Set by `dagger run` for the session it opens. Only its presence is checked.
const SESSION_PORT_VAR: &str = "DAGGER_SESSION_PORT";
const USAGE: &str = "usage: delegate-guard-ci check [--advisory-db DIR] [--cache-prefix PREFIX]\n       delegate-guard-ci live-image --out FILE [--cache-prefix PREFIX]";
/// Workspace root, fixed at build time so the working directory does not matter.
const WORKSPACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

/// What to do.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Run every gate.
    Check,
    /// Build the live-test image and write it to `out` as an image archive.
    LiveImage {
        /// Archive path on the host.
        out: PathBuf,
    },
}

/// Parsed command line.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    command: Command,
    /// Local clone of the `RustSec` advisory database: no advisory fetch.
    advisory_db: Option<PathBuf>,
    /// Prefix for cache volume names; change it to force a cold build.
    cache_prefix: String,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let live_image = match args.next().as_deref() {
        Some("check") => false,
        Some("live-image") => true,
        _ => return Err(USAGE.to_owned()),
    };
    let mut parsed = Args {
        command: Command::Check,
        advisory_db: None,
        cache_prefix: "dg-".to_owned(),
    };
    let mut out = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--advisory-db" if !live_image => parsed.advisory_db = Some(PathBuf::from(value)),
            "--out" if live_image => out = Some(PathBuf::from(value)),
            "--cache-prefix" => parsed.cache_prefix = value,
            _ => return Err(format!("unknown argument {flag:?}\n{USAGE}")),
        }
    }
    if live_image {
        let out = out.ok_or_else(|| format!("live-image needs --out\n{USAGE}"))?;
        parsed.command = Command::LiveImage { out };
    }
    Ok(parsed)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    // Without the session `dagger run` opens, the SDK would download a Dagger
    // CLI from the network: refuse instead. The session token is never read here.
    if std::env::var_os(SESSION_PORT_VAR).is_none() {
        eprintln!(
            "no Dagger session: start this with `dagger run cargo run --locked --manifest-path ci/Cargo.toml -- check`"
        );
        return ExitCode::from(EXIT_UNAVAILABLE);
    }
    match dagger_sdk::connect(move |client| run(client, args)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run(client: dagger_sdk::Query, args: Args) -> eyre::Result<()> {
    match &args.command {
        Command::Check => check(client, args).await,
        Command::LiveImage { out } => {
            let out = out.to_string_lossy().into_owned();
            live_image(&client, &out, args.cache_prefix).await
        }
    }
}

/// The workspace as the gates see it (without build output or VCS data).
fn workspace(client: &dagger_sdk::Query) -> dagger_sdk::Directory {
    client.host().directory_opts(
        WORKSPACE,
        HostDirectoryOpts {
            exclude: Some(vec![
                "target/",
                ".git/",
                "ci/target/",
                "tools/codegen/target/",
            ]),
            gitignore: None,
            include: None,
            no_cache: None,
        },
    )
}

/// Builds the live-test image and exports it with Docker media types, the
/// archive format smolvm documents for local images.
async fn live_image(
    client: &dagger_sdk::Query,
    out: &str,
    cache_prefix: String,
) -> eyre::Result<()> {
    let pipeline = Pipeline {
        client,
        source: workspace(client),
        cache_prefix,
    };
    let opts = ContainerExportOptsBuilder::default()
        .media_types(ImageMediaTypes::DockerMediaTypes)
        .build()?;
    let written = pipeline.live_image()?.export_opts(out, opts).await?;
    println!("wrote {written}");
    Ok(())
}

/// Runs every gate concurrently, prints one line per gate, and fails if any failed.
async fn check(client: dagger_sdk::Query, args: Args) -> eyre::Result<()> {
    let host = client.host();
    let source = workspace(&client);
    let advisory_db = args
        .advisory_db
        .map(|p| host.directory(p.to_string_lossy()));
    let pipeline = Pipeline {
        client: &client,
        source,
        cache_prefix: args.cache_prefix,
    };
    let gates = pipeline.gates(advisory_db)?;
    let results = futures::future::join_all(gates.iter().map(|g| async move {
        (
            g.name,
            g.container
                .sync()
                .await
                .map(drop)
                .map_err(|e| e.to_string()),
        )
    }))
    .await;
    let (text, failed) = report::render(results);
    print!("{text}");
    if failed.is_empty() {
        Ok(())
    } else {
        Err(eyre::eyre!("gates failed: {}", failed.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn test_parse_args_defaults_and_flags() {
        assert_eq!(
            parse(&["check"]),
            Ok(Args {
                command: Command::Check,
                advisory_db: None,
                cache_prefix: "dg-".to_owned()
            })
        );
        assert_eq!(
            parse(&["check", "--advisory-db", "db", "--cache-prefix", "cold-"]),
            Ok(Args {
                command: Command::Check,
                advisory_db: Some(PathBuf::from("db")),
                cache_prefix: "cold-".to_owned()
            })
        );
        assert_eq!(
            parse(&["live-image", "--out", "img.tar"]).map(|a| a.command),
            Ok(Command::LiveImage {
                out: PathBuf::from("img.tar")
            })
        );
    }

    #[test]
    fn test_parse_args_rejects_bad_input() {
        for bad in [
            &[][..],
            &["build"],
            &["check", "--advisory-db"],
            &["check", "--cache-prefix", ""],
            &["check", "--offline", "x"],
            &["check", "--out", "img.tar"],
            &["live-image"],
            &["live-image", "--advisory-db", "db", "--out", "img.tar"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
