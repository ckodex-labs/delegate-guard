# shellcheck shell=bash
# shellcheck disable=SC2154,SC2034  # work, claude_settings, guard, ... are set by the sourcing script; fail is read there
# Helpers shared by live-test.sh and live-scenarios.sh. Sourced, not run.
# Callers set: work (the run's temp dir), claude_settings (array, may be empty),
# and for setup_project: guard, policy, state, socket.

# run_claude DIR PROMPT [MAX_TURNS]: one headless Claude Code session in DIR;
# output in DIR.out.json and DIR.err. Claude Code's own permission system
# allows everything (bypassPermissions), so any denial comes from the hook.
run_claude() {
  (cd "$1" && claude -p "$2" --permission-mode bypassPermissions --output-format json \
    --max-turns "${3:-8}" ${claude_settings[@]+"${claude_settings[@]}"}) </dev/null >"$1.out.json" 2>"$1.err" || true
}

# require_model_run DIR: a run that never reached the model proves nothing
# about the hook, so stop as inconclusive (exit 2) instead of reporting a
# guard failure.
require_model_run() {
  if [ "$(jq -r '.is_error // false' "$1.out.json" 2>/dev/null)" = true ] || ! jq -e . "$1.out.json" >/dev/null 2>&1; then
    echo "INCONCLUSIVE: $(basename "$1"): Claude Code did not complete a model turn: $(jq -r '.result // "no JSON result"' "$1.out.json" 2>/dev/null | head -c 300)"
    echo "  see $1.out.json and $1.err"
    exit 2
  fi
}

# transcript_dir PROJECT: Claude Code's transcript directory for the project
# dir $work/PROJECT (empty if none). The layout is undocumented, like the sidecar.
transcript_dir() {
  find "$HOME/.claude/projects" -maxdepth 1 -type d -name "*$(basename "$work" | tr . -)-$1" | head -n 1
}

# tool_results_with TOKEN PROJECT [all]: how many tool results (what tools
# returned, not what the model wrote) contain TOKEN, in the subagents'
# transcripts, or with "all" also the main one. The result of an Agent (or
# Task) call is the spawned agent's report, which is model prose, so it is not
# counted. Prints "missing" if there is no such transcript.
tool_results_with() {
  local dir pattern='*/subagents/*.jsonl'
  [ "${3:-}" = all ] && pattern='*.jsonl'
  dir="$(transcript_dir "$2")"
  if [ -z "$dir" ] || [ -z "$(find "$dir" -path "$pattern" | head -n 1)" ]; then echo missing; return; fi
  find "$dir" -path "$pattern" -exec jq -c -s --arg t "$1" '
    ([.[] | select(.type=="assistant") | .message.content[]? | select(.type=="tool_use" and (.name=="Agent" or .name=="Task")) | .id]) as $reports
    | .[] | select(.type=="user") | .message.content[]? | select(.type=="tool_result")
    | select((.tool_use_id as $i | $reports | index($i)) == null)
    | (.content|tostring) | select(contains($t))' {} + |
    wc -l | tr -d ' '
}

# check DESC REGEX FILE: PASS if FILE has a line matching REGEX, else FAIL
# and fail=1.
check() { if grep -Eq "$2" "$3"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }

# setup_project DIR TEMPLATE: a throwaway project with file.txt and the hook
# settings rendered from TEMPLATE.
setup_project() {
  mkdir -p "$1/.claude" && echo hello >"$1/file.txt"
  sed -e "s#__GUARD__#${guard:-}#g" -e "s#__POLICY__#${policy:-}#g" -e "s#__STATE__#${state:-}#g" -e "s#__SOCKET__#${socket:-}#g" \
    "$2" >"$1/.claude/settings.json"
}
