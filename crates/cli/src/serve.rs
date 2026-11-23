//! `delegate-guard serve`: run the shared daemon in the foreground (a service
//! manager supervises it; see ADR-0001).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use std::sync::Arc;

use delegate_guard_admin::AdminContext;
use delegate_guard_daemon::{Allowlist, Server, ServerConfig, SharedPolicy, bind_private};
use jiff::Timestamp;

use crate::flags::Flags;
use crate::{EXIT_USAGE, default_state_dir, env_nonempty};

const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_SOCKET_MODE: u32 = 0o600;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The admin socket is for operators only: owner access, never widened.
const ADMIN_SOCKET_MODE: u32 = 0o600;
/// Exit code when the daemon cannot start (`EX_UNAVAILABLE`).
const EXIT_UNAVAILABLE: u8 = 69;

/// The admin side: its socket and who may use it.
struct AdminPlan {
    socket: PathBuf,
    allowed: Allowlist,
}

pub(crate) fn run(args: &[OsString]) -> u8 {
    let (config, admin) = match config(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("delegate-guard serve: {e}");
            return EXIT_USAGE;
        }
    };
    let summary = format!(
        "listening on {} (state {}, extra uids {:?}, mode {:o}{})",
        config.socket.display(),
        config.state_dir.display(),
        config.allowed.extra(),
        config.socket_mode,
        admin
            .as_ref()
            .map_or_else(String::new, |a| format!(", admin {}", a.socket.display()))
    );
    let admin_listener = match &admin {
        Some(plan) => match bind_private(&plan.socket, ADMIN_SOCKET_MODE) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("delegate-guard serve: admin socket: {e}");
                return EXIT_UNAVAILABLE;
            }
        },
        None => None,
    };
    let context = AdminContext {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        started_at: Timestamp::now(),
        hook_socket: config.socket.clone(),
        state_dir: config.state_dir.clone(),
        policy: Arc::clone(&config.policy),
    };
    let server = match Server::bind(config) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("delegate-guard serve: {e}");
            return EXIT_UNAVAILABLE;
        }
    };
    if let (Some(listener), Some(plan)) = (admin_listener, admin) {
        spawn_admin(listener, context, plan.allowed);
    }
    eprintln!("delegate-guard serve: {summary}");
    server.run();
    0
}

/// The admin API runs on its own runtime thread; if it fails, the hook path
/// keeps serving.
fn spawn_admin(
    listener: std::os::unix::net::UnixListener,
    context: AdminContext,
    allowed: Allowlist,
) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("delegate-guard serve: admin runtime: {e}");
                return;
            }
        };
        if let Err(e) = runtime.block_on(delegate_guard_admin::serve(listener, context, allowed)) {
            eprintln!("delegate-guard serve: {e}");
        }
    });
}

const SERVE_FLAGS: [&str; 9] = [
    "socket",
    "policy",
    "state",
    "allow-uids",
    "socket-mode",
    "max-connections",
    "timeout-ms",
    "admin-socket",
    "admin-uids",
];

fn config(args: &[OsString]) -> Result<(ServerConfig, Option<AdminPlan>), String> {
    let flags = Flags::parse(args, &SERVE_FLAGS)?;
    let socket = flags
        .get("socket")
        .filter(|s| !s.is_empty())
        .ok_or("--socket is required")?;
    let policy_path = flags
        .get("policy")
        .map(str::to_owned)
        .or_else(|| env_nonempty("DELEGATE_GUARD_POLICY"))
        .ok_or("--policy is required")?;
    let policy = Arc::new(SharedPolicy::load(
        Path::new(&policy_path),
        Timestamp::now(),
    )?);
    let server = ServerConfig {
        socket: PathBuf::from(socket),
        state_dir: flags
            .get("state")
            .map_or_else(default_state_dir, PathBuf::from),
        policy,
        allowed: Allowlist::new(parse_list(
            flags.get("allow-uids").unwrap_or(""),
            "--allow-uids",
        )?),
        socket_mode: flags
            .get("socket-mode")
            .map_or(Ok(DEFAULT_SOCKET_MODE), parse_mode)?,
        max_connections: parse_positive(
            flags.get("max-connections"),
            DEFAULT_MAX_CONNECTIONS,
            "--max-connections",
        )?,
        io_timeout: flags
            .get("timeout-ms")
            .map_or(Ok(DEFAULT_IO_TIMEOUT), |v| {
                parse_positive(Some(v), 0, "--timeout-ms").map(ms)
            })?,
    };
    Ok((server, admin_plan(&flags)?))
}

fn admin_plan(flags: &Flags) -> Result<Option<AdminPlan>, String> {
    match flags.get("admin-socket").filter(|s| !s.is_empty()) {
        Some(socket) => Ok(Some(AdminPlan {
            socket: PathBuf::from(socket),
            allowed: Allowlist::new(parse_list(
                flags.get("admin-uids").unwrap_or(""),
                "--admin-uids",
            )?),
        })),
        None if flags.get("admin-uids").is_some() => {
            Err("--admin-uids needs --admin-socket".to_owned())
        }
        None => Ok(None),
    }
}

fn ms(n: usize) -> Duration {
    Duration::from_millis(u64::try_from(n).unwrap_or(u64::MAX))
}

fn parse_list(text: &str, name: &str) -> Result<Vec<u32>, String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| format!("{name}: {s:?} is not a uid"))
        })
        .collect()
}

/// Octal, owner-readable-writable at least, never world-accessible.
fn parse_mode(text: &str) -> Result<u32, String> {
    let mode = u32::from_str_radix(text, 8)
        .map_err(|_| format!("--socket-mode: {text:?} is not octal"))?;
    if mode & 0o600 != 0o600 || mode & 0o007 != 0 || mode > 0o777 {
        return Err(format!(
            "--socket-mode {text}: must include 600 and grant nothing to others"
        ));
    }
    Ok(mode)
}

fn parse_positive(text: Option<&str>, default: usize, name: &str) -> Result<usize, String> {
    match text {
        None => Ok(default),
        Some(t) => t
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| format!("{name} must be a positive integer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mode_rejects_world_access() {
        assert_eq!(parse_mode("600"), Ok(0o600));
        assert_eq!(parse_mode("660"), Ok(0o660));
        for bad in ["666", "644", "400", "x", "1777"] {
            assert!(parse_mode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_parse_list_reads_uids() {
        assert_eq!(parse_list("501, 502", "--x"), Ok(vec![501, 502]));
        assert_eq!(parse_list("", "--x"), Ok(vec![]));
        assert!(parse_list("501,root", "--x").is_err());
    }
}
