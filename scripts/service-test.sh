#!/usr/bin/env bash
# shellcheck disable=SC2329  # helpers are called through check and trap
# End-to-end test of a Tier U service install on this machine (launchd agent on
# macOS, systemd --user on Linux), under a throwaway label and data directory
# so an existing install is not touched.
#
#   scripts/service-test.sh [--bin PATH]
#
# Checks: install and health; file modes; a hook call admitted and one denied
# through the socket; SIGKILL of the daemon, restart by the service manager and
# receipts continuing across it; uninstall, after which the client fails closed;
# --purge removing the data. Exit 0 PASS, 1 FAIL.
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
bin=$(command -v delegate-guard || true)
while [ $# -gt 0 ]; do
  case $1 in
    --bin) bin=$2; shift 2 ;;
    *) sed -n '2,11p' "$0" >&2; exit 64 ;;
  esac
done
[ -x "$bin" ] || { echo "no delegate-guard binary; pass --bin" >&2; exit 64; }
name=dg-svc-test-$$
work=$(mktemp -d)
root=$work/root
fail=0
svc() { "$here/scripts/service.sh" "$1" --tier user --name "$name" --root "$root" --bin "$bin" "${@:2}"; }
cleanup() { svc uninstall --purge >/dev/null 2>&1; rm -rf "$work"; }
trap cleanup EXIT

check() { # DESC CONDITION...
  local desc=$1
  shift
  if "$@"; then echo "PASS: $desc"; else echo "FAIL: $desc"; fail=1; fi
}
mode() { if [ "$(uname -s)" = Darwin ]; then /usr/bin/stat -f %Lp "$1"; else stat -c %a "$1"; fi; }
is_mode() { [ "$(mode "$2")" = "$1" ]; }
event() { # TOOL ID
  printf '{"session_id":"svc-test","hook_event_name":"PreToolUse","tool_name":"%s","tool_use_id":"%s","transcript_path":"/nonexistent/t.jsonl"}' "$1" "$2"
}
hook() { event "$1" "$2" | "$bin" hook --socket "$socket" 2>"$work/hook.err"; }
pid() { svc status 2>/dev/null | awk '$1 == "pid" {print $2}'; }
healthy_with_new_pid() { # OLD
  local i now
  for ((i = 0; i < 75; i++)); do
    now=$(pid)
    if [ -n "$now" ] && [ "$now" != "$1" ] && svc status >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  return 1
}

echo "== install ($(uname -s), label io.github.ckodex-labs.$name)"
check "install succeeds and the daemon reports healthy" svc install
svc status
socket=$(svc settings | jq -r '.hooks.PreToolUse[0].hooks[0].command' | awk '{print $NF}')
check "settings point at the live hook socket" test -S "$socket"
check "the settings keep onFailure=block on PreToolUse" \
  test "$(svc settings | jq -r '.hooks.PreToolUse[0].hooks[0].onFailure')" = block
check "hook socket is 0600" is_mode 600 "$socket"
check "socket directory is 0700" is_mode 700 "$(dirname "$socket")"
check "state directory is 0700" is_mode 700 "$root/state"
check "policy is 0600" is_mode 600 "$root/policy.json"

echo "== hook calls through the service"
hook Read t1
check "Read (in the root grant) is admitted" test $? -eq 0
hook WebFetch t2
check "WebFetch (outside the root grant) is denied with exit 2" test $? -eq 2
check "the denial names delegate-guard" grep -q delegate-guard "$work/hook.err"

echo "== crash and restart"
old=$(pid)
kill -9 "$old"
check "the service manager restarts the daemon after SIGKILL" healthy_with_new_pid "$old"
hook Read t3
check "a call after the restart is admitted" test $? -eq 0
"$bin" verify --session svc-test --state "$root/state" >"$work/verify.out" 2>&1
check "the receipt chain verifies across the restart" test $? -eq 0
cat "$work/verify.out"

echo "== uninstall"
svc uninstall
unit=$(svc status 2>/dev/null | awk '$1 == "unit" {print $2}')
check "the unit file is removed" test ! -e "$unit"
check "status reports unhealthy" sh -c '! "$@" >/dev/null 2>&1' _ "$here/scripts/service.sh" status --tier user --name "$name" --root "$root" --bin "$bin"
hook Read t4
check "with the daemon gone the client fails closed (exit 2)" test $? -eq 2
check "data is kept without --purge" test -f "$root/policy.json"
svc uninstall --purge >/dev/null
check "--purge removes the data directory" test ! -e "$root"

if [ "$fail" = 0 ]; then echo "SERVICE TEST: PASS"; else echo "SERVICE TEST: FAIL"; fi
exit "$fail"
