# ADR-0001: Shared daemon over a Unix socket, pure decision kernel

- Status: accepted (2026-11-22)
- Scope: `crates/*`, hook wiring, service install
- Supersedes: nothing. Extends README Limitation 3 ("an HTTP-hook service under a separate uid … not implemented").

## Context

Today every hook event starts a process that locks, reads, decides, appends a
receipt and rewrites the session file. Three consequences:

1. **Tampering.** Hooks run as the user, so an agent holding `Bash` or `Write` can
   edit its own state or the policy (README Limitation 3).
2. **No shared view.** Each session is a set of files; there is no process that
   can answer "what is every session's state" or reload policy once.
3. **Decision logic is entangled with I/O.** `hook` mixes the rules with file
   reads, receipts and locking, so a second front end (a daemon) would have to
   duplicate or wrap that tangle.

Facts from the hook docs (code.claude.com/docs/en/hooks, read 2026-11-22):

- Handler types: `command`, `http`, `mcp_tool`, `prompt`, `agent`.
- An `http` hook that cannot connect, times out or gets a non-2xx response is a
  **non-blocking error** by default: the tool call proceeds.
- `"onFailure": "block"` (Claude Code v2.1.295+) makes those failures act like
  exit 2. It also applies to `command` hooks (crash, signal, timeout, exit other
  than 0/2). It has no effect on `SubagentStop`.
- Unix-domain-socket URLs are not documented for `http` hooks.

## Decision

### 1. Pure kernel

A `delegate-guard-kernel` crate holds the grant algebra, the session model and
every decision as pure functions: `(&mut Session, &ValidPolicy, input, now) →
verdict + Vec<Fact>`. No file, socket or clock access. Sidecar lookup is passed
in as a port (a closure called only when the kernel needs it). `hook` becomes
the adapter: load state, call the kernel, turn facts into receipts, save.
`Policy` → `ValidPolicy` is the only way to get a policy the kernel accepts.

### 2. One binary, three modes

| Mode | Command | Use |
| --- | --- | --- |
| in-process (today) | `delegate-guard hook --policy P [--state D]` | no daemon installed |
| client | `delegate-guard hook --socket S` | forwards the event to the daemon |
| daemon | `delegate-guard serve --socket S --policy P` | shared by all sessions and agents |

The client is std-only so its start-up cost per tool call stays at that of
today's binary. It owns the exit code, which keeps fail-closed in our hands
rather than in Claude Code's HTTP failure handling.

### 3. Wire protocol

- **Hook path:** frames of `u32` big-endian length + JSON, max 8 MiB, one request
  and one response per connection. Request `{"v":1,"event":<hook payload>}`,
  response `{"v":1,"exit":0|1|2,"stdout":"…","stderr":"…"}`. Unknown `v` → the
  daemon answers exit 2 (PreToolUse) or 1.
- **Admin path:** gRPC (`ckodex.delegateguard.v1.AdminService`, Buf v2, `proto/`) on a
  second socket: `Health`, `GetStatus`, `ListSessions`, `VerifyReceipts`,
  `ReloadPolicy`. The hook path never depends on gRPC.

### 4. Fail-closed contract

| Failure | PreToolUse | SubagentStart / Stop |
| --- | --- | --- |
| socket missing, refused, timeout (connect 1 s, total 5 s default) | client exits 2 | client exits 1 |
| malformed or oversized frame, unknown version | exit 2 | exit 1 |
| client crashes or is killed | `onFailure: "block"` → blocked | non-blocking (by design) |
| daemon internal error, state corrupt for that session | exit 2, other sessions unaffected | exit 1 |
| policy reload invalid | last valid policy stays active; admin reports the error | same |

Settings templates set `"onFailure": "block"` on `PreToolUse` in every mode.

### 5. Trust tiers

| | Tier U: user service | Tier S: system service |
| --- | --- | --- |
| Runs as | the user (launchd agent, `systemd --user`) | dedicated uid `_delegateguard` |
| Hook socket | 0600 in a 0700 per-user runtime dir | 0660, group `delegate-guard`, dir 0750 |
| Caller check | peer uid = daemon uid | peer uid in the configured allowlist |
| State, policy | user-owned (agents can edit them, as today) | service-owned 0600: **agents cannot edit** |
| Sidecar binding | works | needs a read ACL on `~/.claude/projects`; without it, falls back to the meet rule |
| Install | no privileges | admin |

Peer credentials come from `getpeereid` (macOS) / `SO_PEERCRED` (Linux) through
`nix`'s safe wrappers on the hook socket and tokio's `UnixStream::peer_cred` on the
admin socket (`peer_cred` is not stable in std). Both servers admit through one
`Allowlist` (the daemon's uid plus the configured list); each has a test where a
peer the list leaves out gets no answer.

### 6. Concurrency and recovery

The daemon relies on the per-session `flock` alone: each connection's handler
opens the lock file itself, and `flock` locks are per open file description, so
threads in one process exclude each other exactly as separate processes do
(`test_with_concurrent_increments_are_serialized`, `test_daemon_concurrent_budget`).
An extra in-process mutex was planned and dropped as redundant (amended in phase 2).
In-process and daemon modes can therefore share a state directory. Every decision is persisted (fsync) before the reply, so a restart
resumes from disk and the receipt chain continues.

## Threat-model delta

| Threat | In-process | Tier U | Tier S |
| --- | --- | --- | --- |
| agent edits state or policy | possible | possible | **prevented** (file ownership) |
| agent kills the guard | n/a (per event) | blocks all tool calls (fail closed) | needs root |
| agent forges hook events (same uid) | possible (run the binary) | possible (connect) | possible if its uid is allowed |
| other local user drives the guard | no | no (0600 + peer uid) | only allowlisted uids |

Event forgery by a same-uid process is not solved by any tier: Claude Code and
an agent's `Bash` look the same on the socket. The mitigation is Claude Code's
own sandbox, which confines tool processes (to be verified per platform before
it is claimed).

## Alternatives rejected

- **`http` hook on localhost TCP.** Any local process can connect; telling callers
  apart needs a bearer token in an environment variable, which the project's
  zero-ambient-credentials rule forbids. It also leaves fail-closed to
  `onFailure` alone.
- **gRPC on the hook path.** Every tool call would pay tokio + tonic start-up in
  the client; nothing on that path needs streaming or codegen.
- **Daemon replaces in-process mode.** Keeping both lets users adopt the daemon
  per machine and keeps the test suite runnable with no service.

## Amendments

- **Phase 3 (2026-11-22).** The admin server uses tonic's single-service
  `Server::serve_with_incoming` without the `router` feature, which removes axum
  and matchit (and a BSD-3-Clause license) from the tree.
- **Revocation (decided 2026-11-22).** A narrowing policy change narrows or
  revokes issued grants. Implemented as a kernel step (`conform`) run on every
  event before any decision: idempotent for grants that fit the policy, so no
  policy version is tracked, and it only narrows. Effective at each session's
  next event, which is when a grant can next be used; the admin `sessions` view
  shows a session's narrowed state only after that event.
- **Session clock (2026-11-22).** Each process reads the clock before it takes
  the session lock, so serialized events can carry out-of-order times. With
  revocation capping expiry at event time + TTL, a late-arriving older reading
  narrowed grants under an unchanged policy and recorded spurious `revoke`
  receipts (seen as 51–52 records instead of 50 in the contention tests).
  Each session now keeps `last_decision` and decides every event at the later
  of its reading and that time (`Session::observe`); receipts carry the same
  time. A backward wall-clock step can only make grants expire sooner.
- **Service integration (2026-11-23, phase 4).** `scripts/service.sh` installs
  either tier from `packaging/` (launchd agent and daemon plists, systemd user and
  system units). Building Tier S exposed two gaps, closed test-first:
  - *Per-caller namespaces.* Sessions were keyed by `session_id` alone, so one
    admitted caller could send events with another caller's session id and spend
    its budget. Peers other than the daemon's own uid now get `state/uid-<n>/`
    (`test_listed_peer_sessions_are_kept_apart_from_the_owners`). The owner keeps
    the flat layout, so Tier U and in-process mode still share a state directory.
  - *Sidecar ownership.* The sidecar ACL lets the service account read every
    granting caller's `~/.claude/projects`, so a caller could point
    `transcript_path` at another user's sidecar. The daemon now uses a sidecar
    only if the opened file is owned by the peer uid (`find_sidecar_owned_by`,
    `test_find_sidecar_owned_by_requires_the_callers_file`, and end to end in
    `scripts/service-test-system.sh`).

  Tier S also copies the binary to a root-owned path and the hook settings point
  at that copy: a caller who can replace the client can replace the guard. The
  admin `ListSessions` and `VerifyReceipts` do not see `uid-<n>/` yet (TODO in
  `crates/admin/src/service.rs`); `delegate-guard verify --state <state>/uid-<n>`
  covers it.

  **Socket activation is deferred.** Adopting a listening socket from systemd
  (`LISTEN_FDS`) needs `unsafe` fd adoption or a new dependency, and launchd's
  `launch_activate_socket` is FFI. What it buys is that connections queue across
  a daemon restart instead of failing closed. With `Restart=always`
  (`RestartSec=1`) and `KeepAlive` (`ThrottleInterval` 2 s), a restart costs
  fail-closed denials until the daemon is back, which the service tests exercise
  with SIGKILL. Revisit if restarts become routine or start-on-demand is needed.
