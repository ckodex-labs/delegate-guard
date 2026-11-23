#!/usr/bin/env bash
# Hook for scripts/upstream-repro.sh. Writes one file per event into LOGDIR
# (no shared file, so parallel hook processes cannot interleave), holding the
# raw hook input, the time, and a snapshot of the subagent's .meta.json
# sidecar as it exists at that moment. Then applies MODE.
# Usage: upstream-hook.sh MODE LOGDIR
set -u
mode="$1" logdir="$2"
in="$(cat)"
now="$(jq -n now)"
agent="$(jq -r '.agent_id // ""' <<<"$in")"
sidecar=null
if [ -n "$agent" ]; then
  tp="$(jq -r '.transcript_path // ""' <<<"$in")" sid="$(jq -r '.session_id // ""' <<<"$in")"
  base="$(dirname "$tp")"
  f="$(find "$base/$sid/subagents" "$base" -maxdepth 3 -name "agent-$agent.meta.json" 2>/dev/null | head -n 1)"
  if [ -n "$f" ]; then sidecar="$(jq -c '{exists: true, keys: keys, toolUseId, parentAgentId}' "$f" 2>/dev/null || echo '{"exists":true,"unreadable":true}')"
  else sidecar='{"exists":false}'; fi
fi
jq -c --argjson t "$now" --argjson s "$sidecar" '{t: $t, p: ., sidecar_at_hook: $s}' <<<"$in" >"$logdir/$now-$$.json"
event="$(jq -r '.hook_event_name' <<<"$in")"
if [ "$mode" = exit2-subagentstart ] && [ "$event" = SubagentStart ]; then
  echo "upstream-repro hook: SubagentStart refused" >&2; exit 2
fi
[ "$event" = PreToolUse ] || exit 0
tool="$(jq -r '.tool_name // ""' <<<"$in")"
deny2() { echo "upstream-repro hook: $1" >&2; exit 2; }
denyjson() {
  jq -nc --arg r "upstream-repro hook: $1" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}
case "$mode" in
  exit2-subagent-bash) if [ "$tool" = Bash ] && [ -n "$agent" ]; then deny2 "Bash denied inside a subagent"; fi ;;
  exit2-main-bash) if [ "$tool" = Bash ] && [ -z "$agent" ]; then deny2 "Bash denied in the main thread"; fi ;;
  exit2-agent) if [ "$tool" = Agent ] || [ "$tool" = Task ]; then deny2 "Agent denied"; fi ;;
  exit2-workflow) if [ "$tool" = Workflow ]; then deny2 "Workflow denied"; fi ;;
  json-subagent-write) if [ "$tool" = Write ] && [ -n "$agent" ]; then denyjson "Write denied inside a subagent"; fi ;;
  json-main-write) if [ "$tool" = Write ] && [ -z "$agent" ]; then denyjson "Write denied in the main thread"; fi ;;
esac
exit 0
