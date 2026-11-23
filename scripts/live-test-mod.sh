#!/usr/bin/env bash
# Live test of the delegate-guard mod against a real, authenticated Claude Code.
#
# Runs the same headless prompt twice in a throwaway project:
#   A) baseline, no mod: the general-purpose subagent inherits Bash and runs it.
#   B) with --plugin-dir mod: the subagent's Bash call is refused by the mod,
#      and the refusal text reaches the transcript.
# Both runs use bypassPermissions in an empty temp dir, so any refusal in B is
# the mod's. Costs one short model session per run.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'echo "artifacts kept in $work"' EXIT

claude --version
claude plugin validate "$here/mod" | tail -1

prompt='Use the Agent tool exactly once, with subagent_type "general-purpose", and give it this task:
"First use the Glob tool with pattern * . Then use the Bash tool to run: echo SUBAGENT_BASH_RAN . Report each tool result verbatim, including any error or denial."
Then reply with the subagent report verbatim. Do not run any tool yourself other than Agent.'

run() { # $1 = project dir, rest = extra flags
  local dir=$1; shift
  (cd "$dir" && claude -p "$prompt" --permission-mode bypassPermissions --output-format json --max-turns 8 "$@") >"$dir.out.json" 2>"$dir.err" || true
}

mkdir -p "$work/A" "$work/B"; echo hello >"$work/A/f.txt"; echo hello >"$work/B/f.txt"
echo "== run A: baseline"; run "$work/A"
echo "== run B: with the mod"; run "$work/B" --plugin-dir "$here/mod"

fail=0
if grep -q SUBAGENT_BASH_RAN "$work/A.out.json"; then echo "baseline: subagent ran Bash -> inherited capability, as expected"; else echo "baseline: Bash output not observed (inspect $work/A.out.json)"; fi
if grep -q SUBAGENT_BASH_RAN "$work/B.out.json"; then echo "FAIL: Bash ran under the mod"; fail=1; else echo "PASS: Bash output absent under the mod"; fi
if grep -q 'delegate-guard: tool \\"Bash\\" is not in the grant\|delegate-guard: tool "Bash" is not in the grant' "$work/B.out.json"; then echo "PASS: refusal reason reached the transcript"; else echo "WARN: refusal text not found in the final report (the model may have paraphrased it); inspect $work/B.out.json"; fi
[ "$fail" -eq 0 ] && echo "LIVE MOD TEST: PASS" || { echo "LIVE MOD TEST: FAIL"; exit 1; }
