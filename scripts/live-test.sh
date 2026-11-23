#!/usr/bin/env bash
# Live test against a real, authenticated Claude Code CLI.
#
# Runs the same headless prompt twice in a throwaway project:
#   A) baseline, no guard: the general-purpose subagent inherits Bash and runs it.
#   B) with delegate-guard: the subagent's Bash call is denied by the hook,
#      its Read call passes, and the receipt chain verifies.
#
# The Bash command prints SUBAGENT_42_RAN, a string absent from the command
# itself. A model can still write that string in its report, so whether Bash
# ran is read from the tool results in the subagent's transcript, never from
# the model's prose. Read is used because Claude Code 2.1.330 offered no Glob tool to the
# headless subagent (observed 2026-11-22: "No such tool available: Glob").
#
# Both runs use --permission-mode bypassPermissions inside an empty temp dir,
# so Claude Code's own permission system allows everything and any denial in
# run B comes from the hook. Requires: cargo, claude (authenticated). Costs one
# short model session per run. Also needs jq; reads the transcripts Claude Code
# writes under ~/.claude/projects (layout undocumented, like the sidecar).
set -euo pipefail

# Options:
#   --settings FILE  passed to both claude runs, for example a file whose "env"
#                    block points Claude Code at an LLM gateway
#   --binary PATH    use a prebuilt delegate-guard instead of building it
#                    (no cargo needed, for example inside a test VM)
usage() { echo "usage: $0 [--settings FILE] [--binary PATH]" >&2; exit 64; }
claude_settings=()
binary=""
while [ $# -gt 0 ]; do
  case "$1" in
    --settings) [ -f "${2:-}" ] || usage; claude_settings=(--settings "$2"); shift 2 ;;
    --binary) [ -x "${2:-}" ] || usage; binary="$2"; shift 2 ;;
    *) usage ;;
  esac
done

here="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/live-lib.sh
. "$here/scripts/live-lib.sh"
work="$(mktemp -d)"
trap 'echo "artifacts kept in $work"' EXIT

echo "== versions"
claude --version
if [ -n "$binary" ]; then
  echo "== prebuilt binary"
  cp "$binary" "$work/delegate-guard"
  sha256sum "$work/delegate-guard" 2>/dev/null || shasum -a 256 "$work/delegate-guard"
else
  cargo --version
  echo "== build"
  (cd "$here" && cargo build --locked --release -p delegate-guard --target-dir "$work/target")
  cp "$work/target/release/delegate-guard" "$work/delegate-guard"
fi
# enable exact binding so the run also verifies Claude Code's sidecar layout
cp "$here/examples/policy.sidecar.json" "$work/policy.json"
state="$work/state"
guard="$work/delegate-guard"
policy="$work/policy.json"

# shellcheck disable=SC2016  # $((6*7)) is for the subagent's shell, not this one
prompt='Use the Agent tool exactly once, with subagent_type "general-purpose", and give it this task:
"First use the Read tool to read file.txt in the current directory. Then use the Bash tool to run: echo SUBAGENT_$((6*7))_RAN . Report each tool result verbatim, including any error or denial."
Then reply with the subagent report verbatim. Do not run any tool yourself other than Agent.'


echo "== run A: baseline (no hook)"
mkdir -p "$work/projA" && echo hello >"$work/projA/file.txt"
run_claude "$work/projA" "$prompt"
require_model_run "$work/projA"
baseline="$(tool_results_with SUBAGENT_42_RAN projA)"
if [ "$baseline" != missing ] && [ "$baseline" -gt 0 ]; then
  echo "baseline: subagent ran Bash (a tool result carries its output)  -> as expected"
else
  echo "baseline: no tool result with the Bash output ($baseline); the run B check below cannot be trusted"
fi

echo "== run B: with delegate-guard"
setup_project "$work/projB" "$here/examples/settings.template.json"
run_claude "$work/projB" "$prompt"
require_model_run "$work/projB"

receipts=("$state"/*.receipts.jsonl)
[ -f "${receipts[0]}" ] || { echo "FAIL: no receipts written; hooks did not fire (check settings / matcher)"; exit 1; }
sid="$(basename "${receipts[0]}" .receipts.jsonl)"
echo "session: $sid"

fail=0
r="${receipts[0]}"
check "main spawned the subagent (Agent passed, budget reserved)" '"actor":"main".*"tool":"Agent".*"decision":"pass"' "$r"
check "subagent bound to a delegated grant"                       '"decision":"bind"' "$r"
if grep -q 'exact: sidecar' "${receipts[0]}"; then echo "PASS: bound exactly via Claude Code's agent-<id>.meta.json sidecar"
else echo "WARN: sidecar not found at first tool call; fell back to type matching (layout may have changed)"; fi
echo "INFO: subagent calls: $(jq -r 'select(.event=="PreToolUse" and .actor!="main") | "\(.tool):\(.decision)"' "$r" | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
false_deny="$(jq -c 'select(.event=="PreToolUse" and .actor!="main" and ((.tool // "") | IN("Glob","Grep","Read")) and .decision=="deny" and ((.reason // "") | test("not in the grant")))' "$r" | grep -c . || true)"
if [ "$false_deny" -eq 0 ]; then echo "PASS: no call inside the grant was refused as outside it"; else echo "FAIL: $false_deny call(s) inside the grant refused"; fail=1; fi
# A call the model never made shows nothing either way: INCOMPLETE, not FAIL.
incomplete=0
attempted() { [ "$(jq -c --arg t "$1" 'select(.event=="PreToolUse" and .actor!="main" and .tool==$t)' "$r" | grep -c . || true)" -gt 0 ]; }
if attempted Read; then check "subagent Read passed" '"tool":"Read".*"decision":"pass"' "$r"
else echo "MISSING: the subagent never attempted Read"; incomplete=1; fi
if attempted Bash; then check "subagent Bash denied by attenuation" '"tool":"Bash".*"decision":"deny".*not in the grant' "$r"
else echo "MISSING: the subagent never attempted Bash"; incomplete=1; fi
guarded="$(tool_results_with SUBAGENT_42_RAN projB)"
case "$guarded" in
  0) echo "PASS: no tool result in run B carries the Bash output" ;;
  missing) echo "FAIL: run B subagent transcript not found; cannot check tool results"; fail=1 ;;
  *) echo "FAIL: $guarded tool result(s) in run B carry the Bash output"; fail=1 ;;
esac

echo "== receipt chain"
"$work/delegate-guard" verify --state "$state" --session "$sid" || fail=1
echo "== final state"
"$work/delegate-guard" status --state "$state" --session "$sid"

if [ "$fail" -ne 0 ]; then echo "LIVE TEST: FAIL"; exit 1; fi
if [ "$incomplete" -ne 0 ]; then echo "LIVE TEST: INCOMPLETE (the model skipped a step; not evidence either way)"; exit 3; fi
echo "LIVE TEST: PASS"
