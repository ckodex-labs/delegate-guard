//! `delegate-guard`: a Claude Code hook that enforces delegation attenuation
//! for subagents. A subagent gets its own grant, the grant is a subset of its
//! parent's, and its budget is carved out of the parent's.
//!
//! ```text
//! delegate-guard hook   --policy FILE [--state DIR]   (reads hook JSON on stdin)
//! delegate-guard verify --session ID [--state DIR]    (checks the receipt chain)
//! delegate-guard status --session ID [--state DIR]    (prints current grants)
//! ```
//!
//! Presentation only: argument parsing, I/O and exit codes. Decisions live in
//! `delegate-guard-hook`.

mod admin;
mod flags;
mod serve;

use std::any::Any;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use delegate_guard_daemon::forward;
use delegate_guard_hook::{EXIT_BLOCK, Input, Outcome, fail_code, handle, load_policy};
use delegate_guard_receipt as receipt;
use delegate_guard_state as state;
use jiff::Timestamp;

use crate::flags::Flags;

const MAX_INPUT: u64 = 8 << 20;
pub(crate) const EXIT_USAGE: u8 = 64;
const USAGE: &str = "usage: delegate-guard hook (--policy FILE [--state DIR] | --socket PATH [--timeout-ms N]) | serve --socket PATH --policy FILE [--state DIR] [--allow-uids N,N] [--socket-mode 600] [--max-connections N] [--timeout-ms N] [--admin-socket PATH [--admin-uids N,N]] | admin (health|status|sessions|verify --session ID|reload) --admin-socket PATH | verify --session ID [--state DIR] | status --session ID [--state DIR]";
/// Client deadline for one round trip to the daemon.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let cmd = args.next();
    let rest: Vec<OsString> = args.collect();
    let code = match cmd.as_ref().and_then(|c| c.to_str()) {
        Some("hook") => run_hook_guarded(&rest),
        Some("serve") => serve::run(&rest),
        Some("admin") => admin::run(&rest),
        Some("verify") => run_verify(&rest),
        Some("status") => run_status(&rest),
        _ => {
            eprintln!("{USAGE}");
            EXIT_USAGE
        }
    };
    ExitCode::from(code)
}

/// Never lets a panic become a non-blocking exit code: Claude Code treats any
/// `PreToolUse` exit other than 2 as "proceed".
fn run_hook_guarded(args: &[OsString]) -> u8 {
    fail_closed_on_panic(|| run_hook(args))
}

/// Runs `body`, mapping a panic to [`EXIT_BLOCK`] with a one-line report.
fn fail_closed_on_panic(body: impl FnOnce() -> u8) -> u8 {
    panic::set_hook(Box::new(|_| {})); // reported below, once
    panic::catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        let _ = writeln!(
            io::stderr(),
            "delegate-guard: panic, failing closed: {}",
            panic_message(&*payload)
        );
        EXIT_BLOCK
    })
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic")
}

fn run_hook(args: &[OsString]) -> u8 {
    let flags = match Flags::parse(args, &["policy", "state", "socket", "timeout-ms"]) {
        Ok(flags) => flags,
        Err(e) => return fail(EXIT_BLOCK, &e),
    };
    let Some(raw) = read_stdin() else {
        return fail(
            EXIT_BLOCK,
            "unreadable or oversized hook input, failing closed",
        );
    };
    let input = match Input::parse(&raw) {
        Ok(i) => i,
        Err(e) => {
            return fail(
                EXIT_BLOCK,
                &format!("malformed hook input, failing closed: {e}"),
            );
        }
    };
    // Only PreToolUse may fail closed with exit 2. On SubagentStop, exit 2
    // would keep the subagent running, so other events degrade to exit 1.
    let code = fail_code(&input.event);
    let out = match flags.get("socket") {
        Some(_) if flags.get("policy").is_some() => failure(
            code,
            "use either --socket (daemon) or --policy (in-process), not both",
        ),
        Some(socket) => via_daemon(&flags, Path::new(socket), &raw, code),
        None => in_process(&flags, &input, code),
    };
    // Write failures cannot change the decision; the exit code carries it.
    if !out.stdout.is_empty() {
        let _ = writeln!(io::stdout(), "{}", out.stdout);
    }
    if !out.stderr.is_empty() {
        let _ = writeln!(io::stderr(), "{}", out.stderr);
    }
    out.exit
}

fn read_stdin() -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    io::stdin().take(MAX_INPUT + 1).read_to_end(&mut raw).ok()?;
    (u64::try_from(raw.len()).is_ok_and(|n| n <= MAX_INPUT)).then_some(raw)
}

fn failure(code: u8, msg: &str) -> Outcome {
    Outcome {
        exit: code,
        stdout: String::new(),
        stderr: format!("delegate-guard: {msg}"),
    }
}

/// Client mode: the daemon decides; any transport failure fails closed.
fn via_daemon(flags: &Flags, socket: &Path, raw: &[u8], code: u8) -> Outcome {
    let timeout = match flags.get("timeout-ms").map(str::parse::<u64>) {
        None => DEFAULT_TIMEOUT,
        Some(Ok(ms)) if ms > 0 => Duration::from_millis(ms),
        Some(_) => return failure(code, "--timeout-ms must be a positive integer"),
    };
    match forward(socket, raw, timeout) {
        Ok(r) => Outcome {
            exit: r.exit,
            stdout: r.stdout,
            stderr: r.stderr,
        },
        Err(e) => failure(code, &format!("daemon unavailable, failing closed: {e}")),
    }
}

/// In-process mode: load the policy and decide here.
fn in_process(flags: &Flags, input: &Input, code: u8) -> Outcome {
    let policy_path = flags
        .get("policy")
        .map(str::to_owned)
        .or_else(|| env_nonempty("DELEGATE_GUARD_POLICY"));
    let Some(policy_path) = policy_path.filter(|p| !p.is_empty()) else {
        return failure(code, "no --policy or --socket given");
    };
    let policy = match load_policy(Path::new(&policy_path)) {
        Ok(p) => p,
        Err(e) => return failure(code, &format!("invalid policy: {e}")),
    };
    if input.session_id.is_empty() {
        return failure(code, "hook input has no session_id");
    }
    let dir = flags
        .get("state")
        .map_or_else(default_state_dir, PathBuf::from);
    handle(&dir, &policy, input, Timestamp::now())
}

fn fail(code: u8, msg: &str) -> u8 {
    let _ = writeln!(io::stderr(), "delegate-guard: {msg}");
    code
}

pub(crate) fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Deliberately outside the project directory: anything an agent can Edit or
/// Write there it could use to rewrite its own grant.
pub(crate) fn default_state_dir() -> PathBuf {
    if let Some(d) = env_nonempty("DELEGATE_GUARD_STATE") {
        return PathBuf::from(d);
    }
    std::env::home_dir().map_or_else(
        || std::env::temp_dir().join("delegate-guard"),
        |h| h.join(".delegate-guard"),
    )
}

fn session_flags(args: &[OsString]) -> Result<(PathBuf, String), String> {
    let flags = Flags::parse(args, &["session", "state"])?;
    let sid = flags
        .get("session")
        .filter(|s| !s.is_empty())
        .ok_or("--session is required")?;
    let dir = flags
        .get("state")
        .map_or_else(default_state_dir, PathBuf::from);
    Ok((dir, sid.to_owned()))
}

fn run_verify(args: &[OsString]) -> u8 {
    let (dir, sid) = match session_flags(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_USAGE;
        }
    };
    let receipts = state::paths(&dir, &sid).receipts;
    match receipt::verify(&receipts) {
        Ok(n) => match receipt::head(&receipts) {
            Ok((_, head)) => {
                println!("OK {n} records, head {head}");
                0
            }
            Err(e) => {
                println!("FAIL reading head: {e}");
                1
            }
        },
        Err(failure) => {
            println!(
                "FAIL after {} valid records: {}",
                failure.valid, failure.error
            );
            1
        }
    }
}

fn run_status(args: &[OsString]) -> u8 {
    let (dir, sid) = match session_flags(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_USAGE;
        }
    };
    match std::fs::read_to_string(state::paths(&dir, &sid).state) {
        Ok(body) => {
            println!("{body}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use delegate_guard_hook::EXIT_ERROR;

    use super::*;

    #[test]
    fn test_fail_closed_on_panic_maps_panic_to_block() {
        assert_eq!(fail_closed_on_panic(|| panic!("boom")), EXIT_BLOCK);
        let owned = String::from("owned");
        assert_eq!(fail_closed_on_panic(move || panic!("{owned}")), EXIT_BLOCK);
    }

    #[test]
    fn test_fail_closed_on_panic_passes_through_exit_code() {
        assert_eq!(fail_closed_on_panic(|| 0), 0);
        assert_eq!(fail_closed_on_panic(|| EXIT_ERROR), EXIT_ERROR);
    }

    /// Integer overflow must panic (and so fail closed) in every profile.
    #[test]
    fn test_overflow_panics_and_fails_closed() {
        let max = std::hint::black_box(i64::MAX);
        assert_eq!(
            fail_closed_on_panic(move || u8::from(max + 1 > 0)),
            EXIT_BLOCK
        );
    }
}
