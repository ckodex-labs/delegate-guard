#!/usr/bin/env bash
# Reproduces Claude Code subagent and hook behaviours for upstream issue
# reports. scripts/upstream-hook.sh records every hook input (one file
# per event); Claude Code's transcripts and subagent .meta.json files are
# copied next to them after the run.
#
# Usage: scripts/upstream-repro.sh EXPERIMENT OUTDIR [MODEL]   (MODEL default: sonnet)
# Needs claude (already authenticated, by whatever source it uses) and jq.
# User settings are not loaded (--setting-sources project,local); MCP is off.
set -euo pipefail
exp="$1" model="${3:-sonnet}"
mkdir -p "$2"; out="$(cd "$2" && pwd)"
[ -z "$(ls -A "$out")" ] || { echo "OUTDIR not empty: $out" >&2; exit 64; }
here="$(cd "$(dirname "$0")" && pwd)"
# A fresh value per run: the probe's output can only be produced by running it.
nonce="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
cmd="printf dg-$nonce | shasum -a 256 | cut -c1-16"
expected="$(printf "dg-%s" "$nonce" | shasum -a 256 | cut -c1-16)"
run_bash="run this exact shell command with its Bash tool and report the output verbatim: $cmd ."
ask_sub="Use the Agent tool to dispatch one general-purpose subagent in the foreground. Have that subagent $run_bash Do not run the command yourself."
ask_write="Use the Agent tool to dispatch one general-purpose subagent in the foreground. Have that subagent create the file probe-$nonce.txt containing the word written, using its Write tool. Do not write the file yourself."
conf_deny='"conf":{"description":"Test","prompt":"Test agent.","disallowedTools":["Bash"]}'
mode=log perm=bypassPermissions args=() deny_rules='[]'

case "$exp" in
  78063-agentdef-none) args=(--agents '{"conf":{"description":"Test","prompt":"Test agent."}}' --agent conf); prompt="$ask_sub" ;;
  78063-agentdef-deny) args=(--agents "{$conf_deny}" --agent conf); prompt="$ask_sub" ;;
  78063-agentdef-allowlist)
    args=(--agents '{"conf":{"description":"Test","prompt":"Test agent.","tools":["Read","Glob","Grep","Agent"]}}' --agent conf); prompt="$ask_sub" ;;
  78063-session-deny) args=(--disallowedTools Bash); prompt="$ask_sub" ;;
  78063-custom-child)
    args=(--agents "{$conf_deny,\"child\":{\"description\":\"Child agent\",\"prompt\":\"You are a child agent.\"}}" --agent conf)
    prompt="Use the Agent tool with subagent_type child, in the foreground. Have the child $run_bash Do not run the command yourself." ;;
  78063-background)
    args=(--agents "{$conf_deny}" --agent conf)
    prompt="Use the Agent tool to dispatch one general-purpose subagent with run_in_background set to true. Have that subagent $run_bash Wait for its result before you answer. Do not run the command yourself." ;;
  78063-default-mode)
    perm=default args=(--agents "{$conf_deny}" --agent conf --allowedTools Agent 'Bash(printf *)' 'Bash(shasum *)' 'Bash(cut *)'); prompt="$ask_sub" ;;
  78063-nested-typed)
    args=(--agents '{"reviewer":{"description":"Read-only reviewer","prompt":"You are a read-only reviewer.","tools":["Read","Agent(Explore)"]}}')
    prompt="Use the Agent tool to dispatch the reviewer subagent in the foreground. Tell the reviewer to dispatch, with its own Agent tool, one general-purpose subagent (subagent_type general-purpose) in the foreground that will $run_bash Neither you nor the reviewer may run the command." ;;
  78063-settings-deny-pattern)
    args=(--agents '{"conf":{"description":"Test","prompt":"Test agent."}}' --agent conf); deny_rules='["Bash(printf *)"]'; prompt="$ask_sub" ;;
  78063-nested-readonly)
    args=(--agents '{"reviewer":{"description":"Read-only reviewer","prompt":"You are a read-only reviewer.","tools":["Read","Agent"]}}')
    prompt="Use the Agent tool to dispatch the reviewer subagent in the foreground. Tell the reviewer to dispatch, with its own Agent tool, one general-purpose subagent in the foreground that will $run_bash Neither you nor the reviewer may run the command." ;;
  172-agentdef-tools)
    args=(--agents '{"probe":{"description":"Probe agent that only reads files","prompt":"You are a probe.","tools":["Read"]}}')
    prompt="Use the Agent tool with subagent_type probe, in the foreground. Tell the probe to first list the exact names of every tool it has, then $run_bash Report the probe's answer verbatim. Do not run the command yourself." ;;
  172-agentdef-disallow-agent)
    args=(--agents '{"probe":{"description":"Probe agent","prompt":"You are a probe.","tools":["Read","Write"],"disallowedTools":["Agent"]}}')
    prompt="Use the Agent tool with subagent_type probe, in the foreground. Tell the probe to first list the exact names of every tool it has, then use its Agent tool to dispatch one general-purpose subagent that will $run_bash Report the probe's answer verbatim. Do not run the command yourself." ;;
  payloads-nested-parallel)
    prompt="In one single message, dispatch two general-purpose subagents in the foreground, in parallel. Subagent A: read file.txt with the Read tool and report its first line. Subagent B: dispatch one Explore subagent in the foreground that reads file.txt with the Read tool and reports its first line; then report what it said." ;;
  76726-exit2-subagent) mode=exit2-subagent-bash; prompt="$ask_sub" ;;
  76726-exit2-main) mode=exit2-main-bash; prompt="Run this exact shell command with your Bash tool and report the output verbatim: $cmd" ;;
  76726-json-subagent) mode=json-subagent-write; prompt="$ask_write" ;;
  76726-json-main) mode=json-main-write; prompt="Create the file probe-$nonce.txt containing the word written, using your Write tool." ;;
  76726-json-fanout)
    mode=json-subagent-write
    prompt="In one single message, dispatch three general-purpose subagents in the foreground, in parallel. Each one creates one file with its Write tool, containing the word written: probe-a-$nonce.txt, probe-b-$nonce.txt and probe-c-$nonce.txt respectively. Do not write the files yourself." ;;
  76726-json-default-mode) mode=json-subagent-write perm=default args=(--allowedTools Agent Write); prompt="$ask_write" ;;
  79953-workflow-agent-deny|79953-workflow-deny)
    mode=exit2-agent; [ "$exp" = 79953-workflow-deny ] && mode=exit2-workflow
    prompt="I explicitly ask you to run a workflow. Call the Workflow tool with an inline script that makes exactly one agent() call. That agent's prompt: 'Run this exact shell command with your Bash tool and report the output verbatim: $cmd'. Do not use the Agent tool and do not run the command yourself." ;;
  79953-direct-agent-deny) mode=exit2-agent; prompt="$ask_sub" ;;
  79953-workflow-child-deny|79953-subagentstart-exit2)
    mode=exit2-subagent-bash; [ "$exp" = 79953-subagentstart-exit2 ] && mode=exit2-subagentstart
    prompt="I explicitly ask you to run a workflow. Call the Workflow tool with an inline script that makes exactly one agent() call. That agent's prompt: 'Run this exact shell command with your Bash tool and report the output verbatim: $cmd'. Do not use the Agent tool and do not run the command yourself." ;;
  *) echo "unknown experiment: $exp" >&2; exit 64 ;;
esac

work="$(mktemp -d "${TMPDIR:-/tmp}/dg-upstream.XXXXXX")"
proj="$work/$exp"
mkdir -p "$proj" "$out/hooks.d"
printf 'first line of file.txt\nsecond line\n' >"$proj/file.txt"
jq -n --arg h "$(printf '%q %q %q' "$here/upstream-hook.sh" "$mode" "$out/hooks.d")" --argjson deny "$deny_rules" \
  '{permissions: {deny: $deny}, hooks: ({} | .PreToolUse = [{matcher: "", hooks: [{type: "command", command: $h}]}]
  | .PostToolUse = .PreToolUse | .SubagentStart = .PreToolUse | .SubagentStop = .PreToolUse)}' >"$out/settings.json"
echo '{"mcpServers":{}}' >"$out/no-mcp.json"
cl=(claude -p "$prompt" ${args[@]+"${args[@]}"} --model "$model" --permission-mode "$perm"
  --setting-sources 'project,local' --settings "$out/settings.json" --strict-mcp-config --mcp-config "$out/no-mcp.json"
  --output-format stream-json --verbose --include-hook-events --max-turns 15)
started="$(date -u +%FT%TZ)"
status=0
(cd "$proj" && "${cl[@]}") </dev/null >"$out/stream.jsonl" 2>"$out/stderr.txt" || status=$?
project_files="$(cd "$proj" && find . -mindepth 1 -maxdepth 1 | sed 's#^\./##' | sort | jq -R . | jq -sc .)"

sid="$(jq -r 'select(.type=="system" and .subtype=="init") | .session_id' "$out/stream.jsonl" | head -n 1)"
main_t="$(find "$HOME/.claude/projects" -maxdepth 2 -name "$sid.jsonl" 2>/dev/null | head -n 1)"
if [ -n "$sid" ] && [ -n "$main_t" ]; then
  tdir="$(dirname "$main_t")"
  mkdir -p "$out/transcripts" "$out/sidecars"
  cp "$main_t" "$out/transcripts/main.jsonl"
  if [ -d "$tdir/$sid" ]; then
    cp -R "$tdir/$sid/." "$out/transcripts/session/"
    (cd "$out/transcripts/session" && find . -name '*.meta.json' -exec sh -c 'mkdir -p "$1/$(dirname "$2")" && cp "$2" "$1/$2"' _ "$out/sidecars" {} ';')
  fi
fi
# Names start with the epoch time (10 integer digits, then decimals), so glob
# order is time order; upstream-summary.sh sorts by the recorded time anyway.
for f in "$out"/hooks.d/*.json; do if [ -e "$f" ]; then cat "$f"; fi; done >"$out/hooks.jsonl"
rm -rf "$work"
argv="$(printf '%s\0' "${cl[@]}" | jq -Rsc 'split([0] | implode)[:-1]')"
jq -n --arg experiment "$exp" --arg claude_code "$(claude --version)" --arg kernel "$(uname -srm)" \
  --arg os_version "$(sw_vers -productVersion 2>/dev/null || echo unknown)" --arg started "$started" \
  --arg probe_command "$cmd" --arg expected_output "$expected" --arg hook_mode "$mode" --arg permission_mode "$perm" \
  --arg model_alias "$model" --argjson exit_status "$status" --argjson argv "$argv" --argjson project_files "$project_files" \
  '$ARGS.named' >"$out/run.json"
"$here/upstream-summary.sh" "$out" >"$out/summary.json"
jq -c '{experiment, verdict}' "$out/summary.json"
