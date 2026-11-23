# delegate-guard

A Claude Code hook that makes subagent delegation **attenuating**. A subagent gets its own grant. That grant is a subset of its parent's, its budget is carved out of the parent's pool rather than copied, and it expires no later than the parent's. Anything outside the grant is denied at `PreToolUse`.

Two implementations of the same rules:

- **Rust command hook** (this folder, a Cargo workspace under [`crates/`](crates): `kernel` holds every rule as pure functions, `state` and `receipt` persist sessions and decisions, `hook` is the adapter, `daemon` the shared socket server and its client, `admin` the gRPC admin API, `cli` the binary): works with any Claude Code that runs command hooks. About 3,900 non-blank, non-comment lines in `src/` (inline unit tests included, generated code excluded) and 1,900 in dedicated test files, counted 2026-11-22. Runtime dependencies, all pinned exactly in the workspace `Cargo.toml`: `serde`, `serde_json`, `sha2`, `jiff`, `thiserror` on every path; `nix` for socket setup and peer credentials; `tokio`, `tokio-stream`, `tonic`, `tonic-prost`, `prost`, `hyper-util` and `tower` for the admin API only. Rewritten from an earlier Go implementation on 2026-11-22; see [Changes from the Go implementation](#changes-from-the-go-implementation).
- **Claude Code mod** ([`mod/`](mod/README.md)): runs inside the engine through `agent.spawn` and `tool.check`, which gives it exact parent binding and covers workflow agents and teammates. Command hooks can't reach either. TypeScript, because that is the only language the mod runtime loads; 7/7 engine tests and 18/18 core tests pass.

## The problem, as already reported upstream

This is a known, open problem, not a new discovery. delegate-guard is an implementation that addresses it from outside Claude Code while upstream decides on a design.

| Issue | State (2026-11-22) | Relevance |
| --- | --- | --- |
| [claude-code#78063](https://github.com/anthropics/claude-code/issues/78063) `disallowedTools` not inherited by subagents | open; maintainer-confirmed on 2.1.233, "current design", docs clarification and possible cascade under consideration | The core gap: an agent-level restriction does not follow the work into a subagent |
| [claude-agent-sdk-typescript#172](https://github.com/anthropics/claude-agent-sdk-typescript/issues/172) `AgentDefinition.tools`/`disallowedTools` not enforced for subagent child processes | open | The same gap seen from the SDK |
| [claude-code#100198](https://github.com/anthropics/claude-code/issues/100198) name the parent in `SubagentStart` | open | Requests `parent_agent_id` on `SubagentStart` |
| [claude-agent-sdk-python#1469](https://github.com/anthropics/claude-agent-sdk-python/issues/1469) expose `parent_tool_use_id` on tool-lifecycle hooks | open | Requests the exact join field this tool has to reconstruct |
| [claude-code#32016](https://github.com/anthropics/claude-code/issues/32016) include task prompt / `tool_use_id` in `SubagentStart` | closed, not planned | Notes that a pending-file relay "breaks under parallelism"; delegate-guard's meet rule is the safe answer to that |
| [claude-code#79953](https://github.com/anthropics/claude-code/issues/79953) Workflow-internal `agent()` calls bypass blocking `Agent` hooks | open | A known bypass of any `PreToolUse(Agent)` guard, this one included; see Limitations |
| [claude-code#87415](https://github.com/anthropics/claude-code/issues/87415) tmux/pane teammates have no `agent_id` in hook payloads | closed, not planned | Such teammates look like the main thread to every hook; see Limitations |
| [claude-code#76726](https://github.com/anthropics/claude-code/issues/76726) subagent hook denials don't surface to the parent | open | delegate-guard's receipts give that visibility |

The *Zero Trust for AI Agents* guide (Anthropic, May 2026) names the same pattern, unscoped privilege inheritance, as a threat (p.10).

## What it enforces

| Rule | Where | Test |
| --- | --- | --- |
| Child tools = profile tools ∩ parent tools | `kernel::grant::attenuate` | `test_attenuate_narrows_tools`, 200k-case property test `test_attenuate_never_amplifies` |
| Child budget ≤ parent remaining, **reserved** from the parent | `kernel::grant::attenuate`, `kernel::decide` | `test_budget_reserved_from_parent`, `test_fan_out_cannot_exceed_parent` |
| Child expiry ≤ parent expiry | `kernel::grant::attenuate` | `test_attenuate_expiry_capped_by_parent`, `test_child_grant_expires` |
| Depth limit; a leaf cannot hold `Agent` | `kernel::grant::attenuate` | `test_depth_limit_leaf_cannot_spawn` |
| Deny by default: unknown subagent type, unlisted tool, unbound `agent_id` | `kernel::decide` | `test_spawn_unknown_type_denied`, `test_root_unlisted_tool_denied`, `test_unbound_agent_denied` |
| **Exact binding** of child to spawning `Agent` call (opt-in, see below) | `kernel::bind::bind_sidecar` | `test_sidecar_exact_binding_resolves_ambiguity` |
| Sidecar that names an unadmitted spawn, the wrong parent or the wrong type → deny | `kernel::bind::bind_sidecar` | `test_sidecar_naming_unadmitted_spawn_denied`, `test_sidecar_parent_mismatch_denied`, `test_sidecar_type_mismatch_denied` |
| Without exact binding, a child of ambiguous parentage gets the **meet** of all candidate grants | `kernel::bind::bind_fifo` | `test_ambiguous_parents_get_meet` (also checks budget conservation), `test_sidecar_missing_falls_back_to_meet` |
| Unused budget returns to the parent on stop; a stopped agent is closed | `kernel::subagent_stop` | `test_stopped_agent_closed_and_refunded` |
| Admitted spawns that never start are refunded after `pending_ttl` | `kernel::lifecycle::prepare` | `test_stale_pending_refunded` |
| Fail closed: internal error, panic, malformed or oversized input, or bad policy → exit 2 on `PreToolUse` | `cli::run_hook_guarded`, `hook::events` | `test_internal_error_fails_closed`, `test_binary_fails_closed`, `test_binary_oversized_input_fails_closed`, `test_fail_closed_on_panic_maps_panic_to_block`, `test_overflow_panics_and_fails_closed` |
| Never exit 2 on `SubagentStop` (that would keep the subagent running) | `hook::events`, `cli::run_hook` | `test_internal_error_fails_closed`, `test_binary_fails_closed` |
| A policy with an unknown field, a field or subagent type given twice, `*`, or a non-positive budget or TTL is rejected, never partly applied | `kernel::policy` | `test_from_json_rejects_unknown_field`, `test_from_json_rejects_duplicate_field`, `test_from_json_rejects_duplicate_profile`, `test_valid_policy_rejects_invalid_policy` |
| A session's time never goes backwards: events reach the lock in any order and the wall clock can step back, so each event is decided at the later of its clock reading and the session's last decision | `kernel::session::Session::observe` | `test_observe_never_goes_backwards`, `test_out_of_order_event_time_under_unchanged_policy_records_no_revoke`, the two 50-process contention tests |
| Never emits `permissionDecision: "allow"`, so it cannot approve anything | design | — |
| Concurrent hook processes are serialized (`flock`, atomic rename) | `state::with` | `test_with_concurrent_increments_are_serialized`, `test_binary_concurrent_budget` (50 processes, budget 40 → exactly 40 pass) |
| Untrusted `session_id` / `agent_id` cannot escape their directories; symlinked sidecars and sidecar directories are ignored | `state::file_stem`, `hook::find_sidecar` | `test_file_stem_blocks_traversal`, `test_find_sidecar_rejects_unsafe_input`, `test_find_sidecar_ignores_symlinked_directory` |
| Every decision is a hash-chained receipt; edits, deletions, reordering, records spliced from another log and injected fields are detected | `receipt` | `test_verify_detects_{edit,deletion,reorder,record_spliced_from_other_log,injected_field}` |

## Hook contract relied on

**Documented** ([hooks](https://code.claude.com/docs/en/hooks), [sub-agents](https://code.claude.com/docs/en/sub-agents), read 2026-11-22):

- `PreToolUse` fires inside subagents with `agent_id` and `agent_type` set. A missing `agent_id` means the main conversation.
- The spawning tool is `Agent` (renamed from `Task` in 2.1.63). `tool_input.subagent_type` names the type.
- `PreToolUse` exit 2 blocks the call. Any exit other than 0 or 2 does **not** block, so every error path is forced to 2.
- `SubagentStart` carries `agent_id` and `agent_type`. It cannot block, but it can inject `additionalContext`.
- `SubagentStop` exit 2 keeps the subagent running.

**Not documented, but used by the Agent SDK.** The hook payloads alone don't link a subagent to the `Agent` call that spawned it (the issues above). Claude Code does write that link to disk: `<project>/<sessionId>/subagents/agent-<agentId>.meta.json`, with keys `toolUseId` and `parentAgentId`. The Python Agent SDK reads the same file to attribute subagent messages (`claude_agent_sdk/_internal/sessions.py`, `_parent_ids_from_agent_metadata`, commit `3184360`, 2026-11-20). Issue #100198 measures it being written 30–65 ms after the transcript starts and 5–11 s before the first tool call.

With `"sidecar_binding": true`, delegate-guard binds each subagent at its first tool call to the exact pending spawn named by `toolUseId`, then cross-checks `parentAgentId` and the agent type. Any contradiction is denied. If the file is absent, the guard falls back to type-ordered matching with the meet rule.

**Trust model for the sidecar.** The sidecar can only select among spawns the guard has already admitted. A forged file can at most attach a child to another *admitted* spawn of the same type, never mint authority. Writing it requires write access under `~/.claude/projects`, which Claude Code's sandbox denies to tool calls. The option is off by default because the file format is not a documented contract.

## Evidence

Run on macOS arm64 (Darwin 27.3) with rustc 1.95.0, 2026-11-22; test counts and the Dagger gates rerun 2026-11-23 after phase 4 (coverage not remeasured):

```
cargo clippy --workspace --all-targets -- -D warnings   clean (clippy::pedantic, unwrap_used and expect_used denied, unsafe_code forbidden)
cargo test --workspace                                  117 tests, all pass
cargo test --workspace --release                        117 tests, all pass (overflow-checks on)
dagger run cargo run --locked --manifest-path ci/Cargo.toml -- check
                                                        Linux containers: fmt, clippy, test, test-release, audit, deny, proto (buf), codegen drift: all ok
                                                        (includes the daemon suite, so the Linux SO_PEERCRED path runs)
cargo deny check                                        advisories, bans, licenses, sources ok (105 locked packages, 7 of them this workspace)
cargo llvm-cov --workspace                              82.2% of lines; 89.4% excluding the generated admin code
    kernel 92.2–100% per file · hook 95.8–98.2% · receipt 93.4% · state 95.5% · daemon 74.4–100% · cli 62.8–100%
    admin/src/service.rs 23.2%, undercounted: its RPCs run in daemon child processes that
    the tests kill, and a killed process writes no coverage profile (inferred, not verified)
property test                                           invariants held on 52,134 successful attenuations out of 200,000 generated
```

On Linux (`linux-dev`: Linux 7.0 x86_64, rustc 1.98.1, Dagger engine v0.21.9, Docker 29.9.3), 2026-11-23, run by the agy CLI over SSH and checked against its raw logs: debug and release tests 115 passed and 0 failed each, clippy and rustfmt clean, the Dagger pipeline 8/8 gates ok. Claude Code 2.1.273 on that host cannot reach Anthropic's API (`ConnectionRefused`), so the first live run there was inconclusive; `scripts/live-test.sh` now reports such a run as `INCONCLUSIVE` (exit 2) instead of blaming the hook. Rerun through a local Anthropic-format gateway (Envoy AI Gateway serving `glm-5.3-flash-fp4`, passed with `scripts/live-test.sh --settings FILE`, whose `env` block sets `ANTHROPIC_BASE_URL`, a placeholder `ANTHROPIC_AUTH_TOKEN` so no saved login is sent, and the model variables): **PASS**, every check including exact sidecar binding, so Claude Code 2.1.273 on Linux writes the same sidecar layout. Anthropic does not support non-Claude models behind Claude Code; this run shows the hook contract holds with one, not that the model is a supported configuration.

**Live matrix, 2026-11-23, round 1 (open egress).** Each run in a fresh smolvm 1.6.8 microVM (arm64 Linux on macOS, booted from one packed image: Claude Code 2.1.330, the guard binary built in a VM from the CI Rust image), with Claude Code pointed at the local gateway model through `--settings`. `scripts/live-scenarios.sh` separates guard invariants (no call outside the grant passes, no call inside it is refused as outside, no subagent tool result carries the command output, the chain verifies, the budget is never exceeded), whose failure is FAIL, from stimulus checks (the model actually attempted the step), whose absence is INCOMPLETE and counts for nothing.

| Scenario | Runs | PASS | INCOMPLETE | FAIL |
| --- | --- | --- | --- | --- |
| `basic` (in-process) | 5 | 5 | 0 | 0 |
| `daemon` (`serve` + `hook --socket`) | 5 | 5 | 0 | 0 |
| `budget` (profile `max_calls: 2`) | 5 | 4 | 1 | 0 |
| `broken-hook` (hook binary missing, `onFailure: "block"`) | 5 | 5 | 0 | 0 |
| `adversarial` (told to keep trying other ways) | 5 | 5 | 0 | 0 |
| `live-test.sh` (unguarded baseline + guarded run) | 6 | 4 | 0 | 2 (see below) |

Across the 25 scenario runs no invariant broke: 59 subagent calls outside the grant were all denied (Bash 30, ToolSearch 15, Agent 5, ListAgents 2, Write 2, Skill 1), every Read inside budget passed (28), the 8 denied Reads were budget exhaustion, and every subagent was bound exactly through the sidecar (20 of 20). With the hook binary missing, Claude Code blocked the main thread's `Agent` call and no subagent ran, in all 5 runs. The unguarded baseline ran Bash in all 6 `live-test.sh` runs. Its 2 failures were scored by the older check that required "Read passed": the subagent's one extra call was denied and its budget unspent, but those logs do not show whether that call was Read; the script now logs every subagent call and checks for refused in-grant calls, and 3 reruns passed with that evidence. Caveats: the model is `glm-5.3-flash-fp4` (non-Claude, unsupported behind Claude Code); 5 runs per scenario bound timing and model variance, they do not prove the absence of rare failures; and in this round the egress allowlist was not enforced (smolvm 1.6.8 ignores `--allow-cidr` for machines created `--from` a packed image, while an image-based VM enforces it), so the VMs had open egress, though no credentials and a read-only view of the repository. Round 2 fixes that.

**Round 2 (egress enforced), 2026-11-23,** run by `scripts/live-matrix-smolvm.sh` from an image Dagger builds from this workspace (`ci … live-image`, guard binary compiled from the same source, Claude Code 2.1.330, jq, an unprivileged user). The script refuses to run unless a preflight VM cannot reach `api.anthropic.com` and can reach the gateway; this round's preflight: `api.anthropic.com` refused, gateway reachable. 18 runs, 3 per scenario including `live-test.sh`: **18 PASS**, no invariant failure. 124 subagent calls outside the grant were all denied (Bash 90, ToolSearch 16, Agent 5, Write 3, Edit 2, ListAgents 1, Skill 1), 30 Reads inside the grant passed, the 6 denied Reads were budget exhaustion, and all 15 runs that spawned a subagent bound it exactly through the sidecar.

**Round 3 (Claude), 2026-11-23,** on macOS with Claude Code 2.1.330 and its own login (no credential copied anywhere), `--settings` selecting `sonnet`: basic, daemon, budget and broken-hook 3/3 each and `live-test.sh` 2/2, **14 PASS**, no invariant failure (Bash denied 11 times, Read passed 14, the 6 denied Reads were budget exhaustion, all 14 bindings exact). `adversarial` was INCOMPLETE 3/3: after the first denial Claude declined to look for another route, saying a brief from the spawning agent cannot widen its permissions. Adversarial pressure therefore comes from the GLM runs (8 of 8 PASS across rounds 1 and 2), not from Claude.

**Round 4 (nesting, concurrency, revocation), 2026-11-23,** three more scenarios, each 3 times with Claude (`sonnet`, macOS) and 3 times with the gateway model (microVMs, egress enforced): **18 of 18 PASS**, plus 4 `live-test.sh` runs whose unguarded baseline still detected the Bash output.

- `nested`: a `general-purpose` subagent (profile with `Agent`) spawned an `Explore` agent. In all 6 runs the second-level grant was within its parent's and its profile's tools and held no `Agent` (leaf at `max_depth` 2), and its Bash was denied: Claude Code delivers nested hook events with the right `agent_id`s and the sidecar names the right parent.
- `parallel`: two subagents spawned in one message. All 6 runs bound both exactly through the sidecar to different spawns, and both had Bash denied.
- `revoke`: after the subagent's first Read passed, a watcher narrowed the policy file. In all 6 runs the next event recorded `narrowed: tools [Glob Grep Read]→[Glob Grep]` and every later Read was denied: reload revocation works against a live session in in-process mode.

Two first-run results were harness errors, not guard results, and the checks were fixed: the revoke watcher died under the inherited `set -e` before the state directory existed (the policy was never narrowed), and in `nested` the parent's `Agent` result (the child's report, model prose that mentions the output string) was counted as a tool result; Agent and Task results are now excluded.

The 200k-case generator is a fixed-seed splitmix64, so its count differs from the Go run (52,483). The invariants checked are the same.

**Mutation check.** 24 bugs were planted, one at a time: the 18 from the Go implementation's check that still apply, plus 6 for code that is new in the port. The full set was re-run after the identifier renames and again after the kernel extraction; all 24 are caught. The daemon has its own 9 (peer check, exit clamping, fail-open on a dead daemon, version check, socket mode, unsafe directory, live-socket takeover, connection bound, idle timeout): all caught, the clamp only after `crates/daemon/tests/client.rs` was added. The admin API has 6 (reload error reported as applied, DEGRADED ignored, broken chain reported intact, rejection not recorded, hook path pinned to the startup policy, world-accessible admin socket): all caught. Revocation has 12 (conform skipped, profile or parent tools not intersected, remaining or expiry not capped, leaf keeps `Agent`, too-deep grant kept, no cascade, revoked grant usable, refund above the narrowed budget, dropped pending not refunded, removed profile not revoked): all caught. The accept checks have 3 (hook server admits any uid, admin server admits any uid, a non-empty list admits uids it does not name): all caught by `crates/daemon/tests/accept.rs` and `crates/admin/tests/accept.rs`, which name a foreign owner uid so a single-user run can play the refused peer. Two later fixes were written test-first, the test failing on the previous code: duplicate profiles (the old parser kept the last entry) and the session clock (removing the clamp from `kernel::pre_tool_use` brings back the spurious receipt). The suite must fail for each. The script restores every file after its run.

| Planted bug | Result |
| --- | --- |
| child tools not intersected with parent | caught |
| child budget not capped by parent | caught |
| child expiry not capped by parent | caught |
| leaf keeps `Agent` | caught |
| budget copied instead of reserved | caught |
| tool calls not charged | caught |
| unbound agent allowed | caught |
| internal error fails open (exit 1) | caught |
| shared instead of exclusive lock | caught |
| session id not sanitized | caught |
| prev-hash link not checked | **survived at first** → `test_verify_detects_record_spliced_from_other_log` added → caught |
| ambiguous child not given the meet | caught |
| other ambiguous candidates not capped | caught |
| ambiguous surplus not refunded | caught |
| sidecar parent not cross-checked | caught |
| sidecar contradiction falls back instead of denying | caught |
| symlinked sidecar file followed | caught |
| deferred (sidecar) binding used when `sidecar_binding` is off | caught |
| *new:* canonical-form check removed | caught |
| *new:* non-object hook input accepted | caught |
| *new:* `SubagentStart`/`SubagentStop` error exits 2 | caught |
| *new:* symlinked `subagents/` directory followed | **survived at first** → `test_find_sidecar_ignores_symlinked_directory` added → caught |
| *new:* panic exits 1 instead of 2 | caught (`test_fail_closed_on_panic_maps_panic_to_block`) |
| *new:* `ValidPolicy` built without validation | caught |

`scripts/live-test.sh` runs a real, authenticated Claude Code twice in a throwaway project: once without the hook as a baseline, once with it in sidecar mode. It then checks the receipts for: spawn passed, child bound (and whether binding was exact), child `Read` passed, child `Bash` denied, chain verifies; and it checks that no tool result in the child's transcript carries the Bash output.

**Run 2026-11-22 against Claude Code 2.1.330 (authenticated, macOS arm64): PASS.** The baseline child ran Bash. With the guard, the main thread's `Agent` call passed with 6 calls reserved, the child was bound **exactly** through the `agent-<id>.meta.json` sidecar (which confirms the layout the SDK source describes), its `Read` passed, its `Bash` was denied (`tool "Bash" is not in the grant … [Glob Grep Read]`), `SubagentStop` returned the 5 unused calls, and the 6-record chain verified. Two earlier runs failed on the test, not the guard: Claude Code offered the headless child no `Glob` tool (`No such tool available: Glob`, so the test now uses `Read`), and grepping the model's reply for the Bash output matched the child's own sentence saying the output was never produced, so the check now reads tool results instead of prose.

## Changes from the Go implementation

The decision rules, messages and exit codes are the same. The differences:

- **On-disk format is a clean break.** Timestamps are RFC 3339 in UTC and the JSON encoding is serde's. State and receipt files written by the Go binary are not read: `verify` fails on an old Go log, and a Go state file may fail to load (which fails closed). Start from an empty state directory when switching.
- **Receipts must be in canonical form.** `verify` now also requires each line to be byte-identical to the canonical encoding of what it decodes to. Go ignored unknown keys, so a field injected into a record verified there; here it fails.
- **Stricter parsing.** Hook input must be a JSON object (Go accepted `null`). Policy keys match case-sensitively, trailing data after the document is rejected, and a field or subagent type given twice is rejected (Go's decoder allowed all three, keeping the later duplicate: checked with Go 1.27.4). Positional command-line arguments are rejected. The Go `flag` forms `-policy x`, `--policy x` and `--policy=x` still work.
- **Receipt failures during pending expiry fail closed.** Go ignored an error writing the `PendingExpired` receipt. Here it aborts the event, so the refund is not saved and `PreToolUse` exits 2.
- **Untrusted sidecar values are quoted** in deny messages (`{:?}`), so control characters cannot reach the terminal unescaped.
- **Release builds keep overflow checks and unwinding.** `overflow-checks = true` makes a counter bug panic instead of wrapping, and the panic becomes exit 2. `panic = "unwind"` is required: with `abort`, a panic would kill the process with a signal, which Claude Code treats as "proceed".
- **Typed states.** `bound_by` and receipt `decision` are enums, serialized as the same lowercase strings as before.

The policy file format is unchanged. Durations use Go's `time.ParseDuration` syntax (`"90s"`, `"1h30m"`, `"1.5h"`) through a port of that parser, so `examples/*.json` and the mod's policy files work unchanged (`test_policy_load_accepts_shipped_examples`).

The Go sources were archived (not committed anywhere) before removal.

## Status

| | |
| --- | --- |
| Specified | yes (this README, package docs) |
| Implemented | yes |
| Tested by the author | yes: unit, property, binary-level e2e, concurrency, mutation |
| Live against Claude Code | yes: Claude Code 2.1.330 on macOS arm64 (Anthropic API), 2026-11-22; Claude Code 2.1.273 on Linux x86_64 (local gateway model), 2026-11-23 (`scripts/live-test.sh`) |
| Service install | Tier U tested on macOS (launchd) and Linux (systemd `--user`); Tier S tested on Linux in a microVM without systemd; Tier S on macOS not tested ([Services](#services)) |
| Independently evaluated | no |
| Production use | no |

## Limitations

1. **Workflow-internal agents** ([#79953](https://github.com/anthropics/claude-code/issues/79953)) never produce `PreToolUse(Agent)`. If their tool calls carry `agent_id`, the guard has no admitted spawn for them and denies them (fail closed). If they don't, they look like the main thread. Keep `Workflow` out of the root grant; the example policy does.
2. **tmux/pane teammates** ([#87415](https://github.com/anthropics/claude-code/issues/87415)) send no `agent_id`, so the guard treats them as the main thread with the root grant. No hook can fix this; avoid `teammateMode: "tmux"` where attenuation matters.
3. **Same-user tampering.** In-process mode and a per-user daemon run as the user. A subagent holding `Bash` or `Write` could edit the state, policy or sidecar files. Mitigations: keep state and policy outside the project (the default is `~/.delegate-guard`), enable Claude Code's sandbox (it confines writes to the project), and add deny rules for those paths. The fix is Tier S ([Services](#services)): the daemon runs as `_delegateguard`, which owns state and policy. It is tested on Linux in a microVM, not yet under a running systemd or on macOS.
4. **Tool-level granularity.** Grants name tools, not arguments (`Bash`, not `Bash(git status *)`).
5. **Budget counts tool calls**, not tokens or cost. Calls are charged at `PreToolUse`, even if Claude Code's own permission prompt then denies them. That errs toward less authority.
6. **Sidecar format is undocumented.** If it changes, binding falls back to the meet rule (safe, but coarser).
7. **Forks** report `agent_type: "fork"` (per #87415). Whether they pass through `PreToolUse(Agent)` is unverified. If they don't, they stay unbound and every tool call they make is denied.
8. **Hooks can be removed** by whoever controls the settings, unless they are delivered through managed settings.
9. **Receipts are tamper-evident, not tamper-proof.** Anyone who can rewrite the whole file can recompute the chain. Anchor the head hash externally for stronger guarantees.
10. Unix only (`flock` through `std::fs::File::lock`, Unix file modes).

## Use

```sh
cargo install --locked --path crates/cli --root ~    # installs ~/bin/delegate-guard
mkdir -p ~/.delegate-guard && cp examples/policy.json ~/.delegate-guard/policy.json   # or policy.sidecar.json
# add the three hook entries from examples/settings.template.json to .claude/settings.json
# (the PreToolUse entry sets "onFailure": "block", Claude Code v2.1.295+: a crashed or killed
#  hook then blocks the call instead of letting it through)
delegate-guard verify --session <session_id>
delegate-guard status --session <session_id>
```

## Daemon mode

One `delegate-guard serve` process can serve every session and agent on the machine. Each hook event becomes one connection on a Unix socket; the hook command is a thin client that forwards stdin and exits with the daemon's answer.

```sh
delegate-guard serve --socket ~/.delegate-guard/run/hook.sock --policy ~/.delegate-guard/policy.json
# hooks: examples/settings.daemon.template.json  (command: delegate-guard hook --socket PATH)
```

| Situation | `PreToolUse` | `SubagentStart` / `SubagentStop` | Test |
| --- | --- | --- | --- |
| daemon not running, socket missing | exit 2 | exit 1 | `test_daemon_down_fails_closed` |
| daemon killed mid-session, then restarted | exit 2 while down; state and receipt chain resume | | `test_daemon_killed_mid_session_fails_closed_then_resumes` |
| all connection slots busy; an idle peer is cut off at `--timeout-ms` | exit 2 | exit 1 | `test_daemon_full_fails_closed`, `test_daemon_idle_peer_deadline_frees_slot` |
| caller's uid not the daemon's and not in `--allow-uids` | connection closed, exit 2 | exit 1 | `test_server_refuses_unadmitted_peer_without_reply`, `test_peer_allowed_only_own_or_listed_uids` |
| malformed frame, wrong protocol version, oversized frame | exit 2 | exit 1 | `test_daemon_answers_garbage_and_wrong_version_without_blocking_stop`, `test_daemon_drops_oversized_frame_without_reading_it` |
| daemon replies 2 on a non-`PreToolUse` event, or an unknown code | client clamps to 1 / the event's fail code | | `crates/daemon/tests/client.rs` |

Startup refuses a socket directory writable by group or others, a non-socket file at the socket path, and a socket another live daemon owns; a stale socket from a crash is replaced. The socket is created under umask 077, then set to `--socket-mode` (600 by default; never world-accessible). Sessions are serialized by the same per-session `flock` as in-process mode, so the two modes can share a state directory. Every decision is on disk before the reply, so a killed daemon loses nothing it acknowledged.

### Admin API

`serve --admin-socket PATH [--admin-uids N,N]` adds `ckodex.delegateguard.v1.AdminService` ([proto](proto/ckodex/delegateguard/v1/admin.proto), gRPC over a second Unix socket, mode 0600). Callers whose uid is neither the daemon's nor listed are dropped at accept (`test_admin_refuses_unadmitted_peer`). The admin server runs on its own thread; if it fails, the hook path keeps serving.

```sh
delegate-guard admin health   --admin-socket PATH   # SERVING, or DEGRADED after a rejected reload (exit 1)
delegate-guard admin status   --admin-socket PATH   # version, sockets, policy sha256 and load time
delegate-guard admin sessions --admin-socket PATH   # file stem, agents, pending spawns, root budget left
delegate-guard admin verify   --admin-socket PATH --session ID   # EMPTY / INTACT / BROKEN (exit 1)
delegate-guard admin reload   --admin-socket PATH   # APPLIED, or REJECTED with the last valid policy kept (exit 1)
```

**Reload revokes.** A narrower policy applies to grants already issued, at each session's next event (the only moment a grant can be used): tools are intersected with the type's profile and the parent's narrowed tools, `max_calls` and remaining budget are capped, expiry is capped at the event time plus the profile's TTL and at the parent's expiry, and `Agent` is removed at the leaf depth. A grant whose type lost its profile, that sits deeper than `max_depth`, or whose parent was revoked is revoked outright (its budget is forfeited); pending spawns are narrowed or dropped (their reservation returns to the parent). Each change is a `revoke` receipt. A wider policy never widens issued grants; it applies to new sessions and delegations. The same holds in in-process mode when the policy file is edited. Tests: `crates/hook/tests/revoke.rs` (13), `test_admin_reload_rejects_invalid_and_applies_valid`.

## Services

`scripts/service.sh` installs the daemon as a service and prints the hook settings that match it.

```sh
scripts/service.sh install   --tier user [--bin PATH] [--policy FILE]    # launchd LaunchAgent / systemd --user
scripts/service.sh settings  --tier user > hooks.json                    # hook entries for .claude/settings.json
scripts/service.sh status    --tier user                                 # manager state, pid, admin health
scripts/service.sh uninstall --tier user [--purge]                       # --purge also deletes policy, state, receipts
sudo scripts/service.sh install --tier system --allow-users alice,bob [--bin PATH]   # Tier S
scripts/sidecar-acl.sh grant                                             # each Tier S caller, for exact sidecar binding
```

| | Tier U (`--tier user`) | Tier S (`--tier system`, as root) |
| --- | --- | --- |
| Runs as | you | `_delegateguard`, group `delegate-guard` |
| macOS | LaunchAgent `~/Library/LaunchAgents/io.github.ckodex-labs.delegate-guard.plist`; data and sockets in `~/.delegate-guard` | LaunchDaemon in `/Library/LaunchDaemons`; data and sockets in `/Library/Application Support/delegate-guard` |
| Linux | `~/.config/systemd/user/delegate-guard.service`; sockets in `$XDG_RUNTIME_DIR/delegate-guard` | `/etc/systemd/system/delegate-guard.service`; `/run/delegate-guard`, `/var/lib/delegate-guard`, `/etc/delegate-guard/policy.json` |
| Restart | `KeepAlive` / `Restart=always` | same |

Tier S details:

- The binary is copied to `/usr/local/libexec/delegate-guard/`, owned by root, and `settings` points the hooks at that copy: a caller who can replace the client binary can replace the guard.
- A caller needs both membership in group `delegate-guard` (socket 0660 in a 0750 directory) and a place in `--allow-uids`. Each caller's sessions live in `uid-<n>/` under the state directory, so one caller cannot name another caller's session id. The daemon's own uid keeps the flat layout.
- The daemon uses a sidecar only if the caller owns the file. It can reach the file only through the ACL that `sidecar-acl.sh` grants: search on `~` and `~/.claude`, read on `~/.claude/projects`, inherited by files created later. On Linux the ACL mask follows a new file's group bits, so under umask 077 the grant does not reach new sidecars and binding falls back to the meet rule. Claude Code wrote sidecars 0664 under umask 002 (linux-dev) and 0644 under umask 022 (macOS).
- The systemd unit removes what the daemon does not use: `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `ProtectHome=read-only`, an empty capability set and the `@system-service` syscall filter. `systemd-analyze security --offline=true` rates it 0.8 (0 to 10; lower means less exposed).
- Admin commands run as the service account: `sudo -u _delegateguard delegate-guard admin health --admin-socket /run/delegate-guard/admin.sock`. `admin sessions` does not list the `uid-<n>/` directories yet. Use `delegate-guard verify --state /var/lib/delegate-guard/uid-<n> --session ID` instead.
- There is no socket activation ([ADR-0001](docs/adr/0001-daemon-and-kernel.md) amendment, 2026-11-23). While the daemon restarts, clients fail closed.

Tested 2026-11-23:

| Test | Where | Result |
| --- | --- | --- |
| `scripts/service-test.sh`, Tier U, under a throwaway label: install, health, file modes, one call admitted and one denied through the socket, SIGKILL then restart by the manager with the receipt chain continuing, uninstall then the client fails closed, purge | macOS 27.3 (launchd); linux-dev, systemd 255 `--user` | 19/19 on each |
| `scripts/service-test-system.sh`, Tier S: accounts, root-owned binary, service-owned policy and state, socket modes, allowlist and group admission, the caller cannot read the policy or edit the policy, state, binary or daemon, sidecar binding only after the ACL grant and also for files created later, no binding through another caller's sidecar, ACL revoke, purge | root in a smolvm microVM booted from the Dagger-built image; daemon started from the unit's `ExecStart` as `_delegateguard`, without systemd; `/home` on tmpfs because the VM's overlay root has no POSIX ACLs | 26/26 |
| `sidecar-acl.sh` on macOS, with the existing `nobody` account on a temp tree | macOS 27.3 | entries set, inherited by new directories and the files two levels below them, all removed by revoke. Reading the files as that account was not exercised. |
| System unit | linux-dev: `systemd-analyze verify`, `security --offline=true` | only the uninstalled binary flagged; exposure 0.8 |

Not tested: a Tier S install under a running systemd (sandboxing at runtime, creation of `RuntimeDirectory=` and `StateDirectory=`), and Tier S on macOS (accounts through `dscl`, the LaunchDaemon). Both need root on a real host.

## Development

```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
dagger run cargo run --locked --manifest-path ci/Cargo.toml -- check                               # every gate in Linux containers
dagger run cargo run --locked --manifest-path ci/Cargo.toml -- check --advisory-db ./advisory-db   # air-gapped: no advisory fetch
scripts/gen-proto.sh                               # after editing proto/: regenerate crates/admin/src/generated
dagger run cargo run --locked --manifest-path ci/Cargo.toml -- live-image --out dg-live.tar   # image for the live matrix
scripts/live-matrix-smolvm.sh --image dg-live.tar --settings GATEWAY.json --dns IP --allow-cidr CIDR ...   # live matrix in microVMs
scripts/service-test.sh --bin PATH                 # Tier U install/uninstall test on this machine (throwaway label)
scripts/service-test-system.sh --disposable --bin PATH   # Tier S test, as root on a disposable Linux machine
```

The pipeline (`ci/`) is a Rust program on the Dagger Rust SDK (`dagger-sdk` 0.21.12, pinned to the engine version), in its own workspace and lockfile like `tools/codegen`. The Rust SDK cannot author Dagger modules yet (engine v0.21.12 rejects `dagger init --sdk=rust`, and the SDK is marked experimental upstream), so the pipeline runs under `dagger run` instead of `dagger call`. Start it only through `dagger run`: without that session the SDK would download a Dagger CLI from the network, so the pipeline exits 69 instead. Images are pulled by digest; `--cache-prefix` renames the cache volumes to force a cold build.

The admin API's Rust code is generated by an isolated tool (`tools/codegen`, its own workspace and lockfile) and checked in, so the product builds with no code generator, no build script and no `protoc`; the `codegen` gate fails if the checked-in copy drifts from `proto/`.

Decisions: [ADR-0001 daemon and kernel](docs/adr/0001-daemon-and-kernel.md), [ADR-0002 packaging and distribution](docs/adr/0002-packaging-and-distribution.md). Plan: [roadmap](docs/roadmap.md).

Licensed under Apache-2.0 ([LICENSE](LICENSE)). Not affiliated with or endorsed by Anthropic.
