#!/usr/bin/env bash
# Recomputes the verdict, denial, sidecar and id fields of every published
# summary from the public files alone, and fails if any differs from the
# summary.json beside it. Also checks that every hook that started reported
# back, and that every non-zero hook exit is the exit 2 the run's hook_mode
# calls for. Then checks SHA256SUMS. Prints one line per run.
# Usage: scripts/upstream-verify.sh PUB
set -euo pipefail
pub="$1"
here="$(cd "$(dirname "$0")" && pwd)"
fail=0
hooks_ok() {
  jq -rs --arg m "$(jq -r .hook_mode "$1/run.json")" '
    ({"exit2-subagentstart": "^SubagentStart:", "exit2-subagent-bash": "^PreToolUse:Bash$", "exit2-main-bash": "^PreToolUse:Bash$",
      "exit2-agent": "^PreToolUse:(Agent|Task)$", "exit2-workflow": "^PreToolUse:Workflow$"}[$m] // "^$") as $allow
    | [.[] | select(.subtype == "hook_started")] as $s | [.[] | select(.subtype == "hook_response")] as $r
    | ($s | length) == ($r | length)
      and all($r[] | select(.exit_code != 0); .exit_code == 2 and (.hook_name | test($allow)))
      and ($m != "exit2-subagentstart" or all($r[] | select(.hook_event == "SubagentStart"); .exit_code == 2))' "$1/stream.tool-calls.jsonl"
}
while IFS= read -r f; do
  dir="$(dirname "$f")"
  fields='{verdict, denials, sidecar_at_subagent_start, sidecar_at_first_tool, sidecars_final, session_id_is_main, prompt_ids}'
  got="$("$here/upstream-summary.sh" "$dir" | jq -cS "$fields")"
  want="$(jq -cS "$fields" "$f")"
  if [ "$got" != "$want" ]; then echo "DIFF ${dir#"$pub/"}"; fail=1
  elif [ "$(hooks_ok "$dir")" != true ]; then echo "HOOK ${dir#"$pub/"}"; fail=1
  else echo "ok   ${dir#"$pub/"}"; fi
done < <(find "$pub" -name summary.json | sort)
(cd "$pub" && shasum -a 256 -c SHA256SUMS >/dev/null) || { echo "SHA256SUMS mismatch" >&2; fail=1; }
exit "$fail"
