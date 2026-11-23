#!/usr/bin/env bash
# Copies the shareable part of scripts/upstream-repro.sh runs from RAW to PUB
# (which must not exist yet): run.json, summary.json, hook inputs, sidecar
# files, and the tool-call lines of the main stream and of every subagent
# transcript. The init line keeps version, model, tools, permission mode and
# plugin sources; hook_response lines keep the hook's exit code and output. Local paths are rewritten; the copy fails closed if the
# user name, host name or a home path survives.
# Usage: scripts/upstream-scrub.sh RAW PUB
set -euo pipefail
raw="$(cd "$1" && pwd)" pub="$2"
[ ! -e "$pub" ] || { echo "PUB already exists: $pub" >&2; exit 64; }
repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
user="$(id -un)" host="$(hostname -s)"
# Literal (\Q..\E) replacements, most specific first; then the mangled
# project-directory forms Claude Code derives from those paths.
paths() {
  perl -pe 'BEGIN { ($repo, $home, $tmp) = splice(@ARGV, 0, 3); ($mh = $home) =~ s#[/.]#-#g; ($mt = $tmp) =~ s#[/.]#-#g }
    s#\Q$repo\E#<repo>#g; s#\Q$tmp\E/?#\$TMPDIR/#g;
    s#(/private)?/var/folders/[^/"]+/[^/"]+/T/#\$TMPDIR/#g; s#(/private)?/tmp/#\$TMPDIR/#g;
    s#/claude-\d+/#/claude-<uid>/#g; s#(regain access on )[^."]+#${1}<redacted>#g; s#\Q$home\E#~#g; s#\Q$mt\E-?#-TMPDIR-#g; s#-private-var-folders-[^/"]+?-T-#-TMPDIR-#g; s#\Q$mh\E#-HOME#g' \
    "$repo" "$HOME" "$tmp" "$@"
}
tool_lines='select(.type=="assistant" or .type=="user")
  | {type, parent_tool_use_id, content: [(.message.content // [])[]? | select(type=="object" and (.type=="tool_use" or .type=="tool_result"))]}
  | select(.content | length > 0)'
find "$raw" -name run.json | sort | while IFS= read -r f; do
  src="$(dirname "$f")" rel="${f#"$raw/"}"; rel="$(dirname "$rel")"; dst="$pub/$rel"
  mkdir -p "$dst"
  for x in run.json summary.json hooks.jsonl settings.json; do paths "$src/$x" >"$dst/$x"; done
  jq -c 'if .type=="system" and .subtype=="init" then {type, subtype, session_id, claude_code_version, model, permissionMode, tools, plugins: [.plugins[]?.source]}
    elif .type=="system" and .subtype=="hook_started" then {type, subtype, hook_name, hook_event}
    elif .type=="system" and .subtype=="hook_response" then {type, subtype, hook_name, hook_event, exit_code, outcome, stdout, stderr}
    elif .type=="result" then {type, subtype, is_error, num_turns, permission_denials, result}
    else ('"$tool_lines"') end' "$src/stream.jsonl" | paths >"$dst/stream.tool-calls.jsonl"
  if [ -d "$src/sidecars" ]; then (cd "$src/sidecars" && find . -name '*.meta.json' | while IFS= read -r m; do
    mkdir -p "$dst/sidecars/$(dirname "$m")"; paths "$m" >"$dst/sidecars/$m"; done); fi
  if [ -d "$src/transcripts/session/subagents" ]; then (cd "$src/transcripts/session/subagents" && find . -name '*.jsonl' | while IFS= read -r t; do
    mkdir -p "$dst/subagent-tool-calls/$(dirname "$t")"; jq -c "$tool_lines" "$t" | paths >"$dst/subagent-tool-calls/$t"; done); fi
  echo "$rel"
done
if [ -f "$raw/../README.md" ]; then cp "$raw/../README.md" "$pub/README.md"; fi
# grep exits 1 for no match; anything else is a leak (0) or a scan error (2+).
scan() {
  local rc=0; grep -rIl -F "$@" || rc=$?
  if [ "$rc" -ne 1 ]; then echo "LEAK or scan error (grep exit $rc) in the files above, if any" >&2; exit 1; fi
}
scan -e "$user" -e "$host" -e "/Users/" -e "/home/" -e "claude-$(id -u)" "$pub"
# The scripts are source, not data; they contain the path patterns above as
# literals, so they are copied after the data scan and checked for names only.
mkdir -p "$pub/scripts"
cp "$repo"/scripts/upstream-{repro,hook,summary,scrub,verify}.sh "$pub/scripts/"
scan -e "$user" -e "$host" "$pub/scripts"
sums="$(cd "$pub" && find . -type f | sort | xargs shasum -a 256)"
printf '%s\n' "$sums" >"$pub/SHA256SUMS"
