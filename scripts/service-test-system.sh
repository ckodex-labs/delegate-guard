#!/usr/bin/env bash
# shellcheck disable=SC2329  # helpers are called through check and trap
# Tier S on Linux, end to end, as root in a disposable machine (a microVM or
# container with no service manager is enough): the install provisions accounts,
# binary, policy and unit; the daemon is then started exactly as the unit's
# ExecStart says, as the service account, in the directories systemd would
# create for RuntimeDirectory= and StateDirectory=.
#
#   scripts/service-test-system.sh --disposable --bin PATH
#
# It creates users caller1, caller2, member and outsider and deletes them again.
# Exit 0 PASS, 1 FAIL, 64 usage.
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
disposable=0 bin=''
while [ $# -gt 0 ]; do
  case $1 in
    --disposable) disposable=1; shift ;;
    --bin) bin=$2; shift 2 ;;
    *) sed -n '3,12p' "$0" >&2; exit 64 ;;
  esac
done
[ "$disposable" = 1 ] && [ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ] ||
  { echo "run as root on a disposable Linux machine, with --disposable" >&2; exit 64; }
[ -x "$bin" ] || { echo "--bin PATH is required" >&2; exit 64; }

svc=_delegateguard grp=delegate-guard
guard=/usr/local/libexec/delegate-guard/delegate-guard
socket=/run/delegate-guard/hook.sock state=/var/lib/delegate-guard policy=/etc/delegate-guard/policy.json
work=$(mktemp -d)
fail=0 daemon=''
check() { local d=$1; shift; if "$@"; then echo "PASS: $d"; else echo "FAIL: $d"; fail=1; fi; }
refused() { ! "$@" 2>/dev/null; }
as() { local u=$1; shift; runuser -u "$u" -- "$@"; }
owner_mode() { [ "$(stat -c '%U:%G %a' "$2")" = "$1" ]; }
uid_of() { id -u "$1"; }
cleanup() {
  [ -n "$daemon" ] && kill "$daemon" 2>/dev/null
  "$here/scripts/service.sh" uninstall --tier system --purge >/dev/null 2>&1
  for u in caller1 caller2 member outsider; do userdel -r "$u" >/dev/null 2>&1; done
  rm -rf "$work"
}
trap cleanup EXIT

# hook USER SESSION EVENT TOOL AGENT TYPE TRANSCRIPT [TOOL_INPUT]: one hook call
# as USER through the Tier S socket; prints nothing, returns the client's exit.
hook() {
  jq -nc --arg s "$2" --arg e "$3" --arg t "$4" --arg a "$5" --arg y "$6" --arg p "$7" \
    --argjson i "${8:-null}" '{session_id:$s, hook_event_name:$e, tool_name:$t, agent_id:$a,
      agent_type:$y, transcript_path:$p, tool_input:$i, tool_use_id:"toolu_1"}' |
    as "$1" "$guard" hook --socket "$socket" >/dev/null 2>"$work/hook.err"
}

# spawn USER SESSION TRANSCRIPT: main spawns Explore (Agent call toolu_1), the
# subagent a1 starts and calls Read; prints how a1 was bound.
spawn() {
  hook "$1" "$2" PreToolUse Agent "" "" "$3" '{"subagent_type":"Explore","prompt":"x"}' || return 1
  hook "$1" "$2" SubagentStart "" a1 Explore "$3"
  hook "$1" "$2" PreToolUse Read a1 Explore "$3"
  "$guard" status --session "$2" --state "$state/uid-$(uid_of "$1")" | jq -r '.agents.a1.bound_by // "unbound"'
}

# sidecar USER SESSION: the transcript and sidecar Claude Code would write for
# USER's session, created as USER (so with USER's umask and ownership).
sidecar() {
  local dir="/home/$1/.claude/projects/p"
  as "$1" sh -c "mkdir -p '$dir/$2/subagents' && : > '$dir/$2.jsonl' &&
    printf '%s' '{\"toolUseId\":\"toolu_1\",\"agentType\":\"Explore\"}' > '$dir/$2/subagents/agent-a1.meta.json'"
  echo "$dir/$2.jsonl"
}

echo "== provision"
# The sidecar grant needs POSIX ACLs on /home; a microVM's overlay root has none.
touch /home/.acl-probe
if ! setfacl -m u:root:r /home/.acl-probe 2>/dev/null; then
  mount -t tmpfs -o mode=0755 tmpfs /home
  echo "NOTE: /home has no POSIX ACL support ($(stat -f -c %T /)); mounted a tmpfs on /home"
fi
rm -f /home/.acl-probe
for u in caller1 caller2 member outsider; do useradd -m -s /bin/sh "$u" && chmod 0700 "/home/$u"; done
"$here/scripts/service.sh" install --tier system --allow-users caller1,caller2 --bin "$bin" \
  --policy "$here/examples/policy.sidecar.json" --no-start
check "install writes the unit" test -f /etc/systemd/system/delegate-guard.service
groupadd -f "$grp" && usermod -a -G "$grp" member # in the group, not in --allow-uids
# What systemd creates for RuntimeDirectory=/StateDirectory= (modes from the unit).
install -d -o "$svc" -g "$grp" -m 0750 /run/delegate-guard
install -d -o "$svc" -g "$grp" -m 0700 "$state"
exec_line=$(sed -n 's/^ExecStart=//p' /etc/systemd/system/delegate-guard.service)
eval "set -- $exec_line"
(umask 077 && exec setpriv --reuid="$svc" --regid="$grp" --init-groups -- "$@") >"$work/daemon.log" 2>&1 &
daemon=$!
for _ in $(seq 50); do [ -S "$socket" ] && break; sleep 0.2; done
check "the daemon runs as $svc" test "$(ps -o uid= -p "$daemon" | tr -d ' ')" = "$(id -u "$svc")"

echo "== files and modes"
check "binary is root-owned 0755" owner_mode "root:root 755" "$guard"
check "policy is $svc-owned 0600" owner_mode "$svc:$grp 600" "$policy"
check "state directory is $svc-owned 0700" owner_mode "$svc:$grp 700" "$state"
check "socket directory is 0750, group $grp" owner_mode "$svc:$grp 750" /run/delegate-guard
check "hook socket is 0660, group $grp" owner_mode "$svc:$grp 660" "$socket"

echo "== callers"
check "an allowlisted caller is admitted" hook caller1 s1 PreToolUse Read "" "" ""
hook caller1 s1 PreToolUse WebFetch "" "" ""
check "a call outside the root grant is denied (exit 2)" test $? -eq 2
check "the caller's session is kept under uid-$(uid_of caller1)/" test -f "$state/uid-$(uid_of caller1)/s1.json"
check "a group member outside --allow-uids fails closed" refused hook member s1 PreToolUse Read "" "" ""
check "a user outside the group fails closed" refused hook outsider s1 PreToolUse Read "" "" ""

echo "== tamper resistance (as the caller an agent would run as)"
check "the caller cannot edit the policy" refused as caller1 sh -c ": >> $policy"
check "the caller cannot read the policy" refused as caller1 cat "$policy"
check "the caller cannot list or edit state" refused as caller1 ls "$state"
check "the caller cannot replace the guard binary" refused as caller1 sh -c ": >> $guard"
check "the caller cannot signal the daemon" refused as caller1 kill -0 "$daemon"

echo "== sidecar binding through the ACL helper"
t1=$(sidecar caller1 sa)
check "without the ACL, binding falls back (no sidecar read)" test "$(spawn caller1 sa "$t1")" != sidecar
check "the ACL grant succeeds" as caller1 env HOME=/home/caller1 "$here/scripts/sidecar-acl.sh" grant
t2=$(sidecar caller1 sb) # written after the grant: reached only through inheritance
check "with the ACL, a sidecar created later binds exactly" test "$(spawn caller1 sb "$t2")" = sidecar
check "the ACL opens nothing outside ~/.claude/projects" refused as "$svc" ls /home/caller1
check "another caller cannot bind through caller1's sidecar" test "$(spawn caller2 sb "$t2")" != sidecar
check "the ACL revoke succeeds" as caller1 env HOME=/home/caller1 "$here/scripts/sidecar-acl.sh" revoke
check "revoke leaves no entry for $svc" sh -c "! getfacl -Rp /home/caller1 2>/dev/null | grep -q '$svc'"

echo "== uninstall"
kill "$daemon"; wait "$daemon" 2>/dev/null; daemon=''
"$here/scripts/service.sh" uninstall --tier system --purge
check "the unit and binary are removed" test ! -e /etc/systemd/system/delegate-guard.service -a ! -e "$guard"
check "policy and state are removed" test ! -e "$policy" -a ! -e "$state"
check "the service account and group are removed" sh -c "! id $svc >/dev/null 2>&1 && ! getent group $grp >/dev/null"

if [ "$fail" = 0 ]; then echo "TIER S TEST: PASS"; else echo "TIER S TEST: FAIL"; cat "$work/daemon.log"; fi
exit "$fail"
