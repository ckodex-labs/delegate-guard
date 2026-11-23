#!/usr/bin/env bash
# Install, remove or inspect the delegate-guard daemon as a service.
#
#   scripts/service.sh install|uninstall|status|settings --tier user|system [options]
#
# --tier user    Tier U: runs as you (launchd LaunchAgent, systemd --user). No
#                privileges. Policy, state and sockets under --root.
# --tier system  Tier S, as root: runs as _delegateguard. The binary is copied to
#                a root-owned path; state and policy are owned by the service
#                account, so agents running as a caller cannot edit them. Callers
#                are named with --allow-users and added to group delegate-guard.
#
#   --bin PATH          delegate-guard binary (default: the one on PATH)
#   --policy FILE       policy installed when none is there yet (default examples/policy.json)
#   --name NAME         service name (default delegate-guard); label io.github.ckodex-labs.NAME
#   --root DIR          Tier U data directory (default ~/.delegate-guard)
#   --allow-users U,U   Tier S callers (required for install)
#   --no-start          write the files but do not load or start the service
#   --purge             uninstall: also delete policy, state and receipts (and Tier S accounts)
#
# settings prints the Claude Code hook settings for the installed daemon.
# Exit: 0 ok (status: healthy), 1 failed or unhealthy, 64 usage.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
readonly SERVICE_USER=_delegateguard SERVICE_GROUP=delegate-guard LABEL_PREFIX=io.github.ckodex-labs
readonly HEALTH_TRIES=75 # x 0.2 s

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 64; }
die() { echo "service.sh: $*" >&2; exit 1; }
need() { [ $# -ge 2 ] || { echo "service.sh: $1 needs a value" >&2; usage; }; }

action=${1:-}
[ $# -gt 0 ] && shift
tier='' bin='' policy_src="$here/examples/policy.json" name=delegate-guard root='' allow_users=''
no_start=0 purge=0 allow_uids=''
while [ $# -gt 0 ]; do
  case $1 in
    --tier) need "$@"; tier=$2; shift 2 ;;
    --bin) need "$@"; bin=$2; shift 2 ;;
    --policy) need "$@"; policy_src=$2; shift 2 ;;
    --name) need "$@"; name=$2; shift 2 ;;
    --root) need "$@"; root=$2; shift 2 ;;
    --allow-users) need "$@"; allow_users=$2; shift 2 ;;
    --no-start) no_start=1; shift ;;
    --purge) purge=1; shift ;;
    -h | --help) usage ;;
    *) echo "service.sh: unknown option $1" >&2; usage ;;
  esac
done
case $action in install | uninstall | status | settings) ;; *) usage ;; esac
case $tier in user | system) ;; *) echo "service.sh: --tier user|system is required" >&2; usage ;; esac
[[ $name =~ ^[a-z][a-z0-9-]{0,39}$ ]] || die "--name must match [a-z][a-z0-9-]{0,39}"
os=$(uname -s)
case $os in Darwin | Linux) ;; *) die "unsupported OS $os (macOS and Linux only)" ;; esac
label="$LABEL_PREFIX.$name"

# Paths end up in plists and unit files: refuse anything that would need escaping.
safe() {
  case $1 in *[!A-Za-z0-9\ _@+=:,./-]* | '') die "unsupported characters in path: $1" ;; esac
}

absolute() { (cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename "$1")"); }

# layout: every path for this tier and platform.
layout() {
  if [ "$tier" = user ]; then
    root=${root:-$HOME/.delegate-guard}
    policy=$root/policy.json state=$root/state
    if [ "$os" = Darwin ]; then
      run_dir=$root/run log=$root/daemon.log unit=$HOME/Library/LaunchAgents/$label.plist
    else
      run_dir=${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is not set (no user session?)}/$name log=journal
      unit=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$name.service
    fi
    daemon_bin=${bin:-$(command -v delegate-guard || true)}
    [ -n "$daemon_bin" ] || die "no delegate-guard on PATH; pass --bin"
    daemon_bin=$(absolute "$daemon_bin")
  else
    [ -z "$root" ] || die "--root applies to --tier user only"
    daemon_bin=/usr/local/libexec/$name/delegate-guard
    if [ "$os" = Darwin ]; then
      local base="/Library/Application Support/$name"
      run_dir=$base/run state=$base/state policy=$base/policy.json log=$base/log/daemon.log
      unit=/Library/LaunchDaemons/$label.plist
    else
      run_dir=/run/$name state=/var/lib/$name policy=/etc/$name/policy.json log=journal
      unit=/etc/systemd/system/$name.service
    fi
  fi
  socket=$run_dir/hook.sock admin=$run_dir/admin.sock
  for p in "$daemon_bin" "$run_dir" "$state" "$policy"; do safe "$p"; done
}

render() { # TEMPLATE OUT
  sed -e "s|__LABEL__|$label|g" -e "s|__NAME__|$name|g" -e "s|__BIN__|$daemon_bin|g" \
    -e "s|__SOCKET__|$socket|g" -e "s|__ADMIN_SOCKET__|$admin|g" -e "s|__POLICY__|$policy|g" \
    -e "s|__STATE__|$state|g" -e "s|__LOG__|$log|g" -e "s|__ALLOW_UIDS__|$allow_uids|g" \
    -e "s|__SERVICE_USER__|$SERVICE_USER|g" -e "s|__SERVICE_GROUP__|$SERVICE_GROUP|g" "$1" >"$2"
}

# admin: the admin socket is owner-only, so a Tier S check runs as the service account.
admin() {
  if [ "$tier" = user ]; then
    "$daemon_bin" admin "$@" --admin-socket "$admin"
  elif [ "$os" = Linux ]; then
    runuser -u "$SERVICE_USER" -- "$daemon_bin" admin "$@" --admin-socket "$admin"
  else
    sudo -u "$SERVICE_USER" "$daemon_bin" admin "$@" --admin-socket "$admin"
  fi
}

show_log() {
  if [ "$log" != journal ]; then tail -n 20 "$log" >&2 || true
  elif [ "$tier" = user ]; then journalctl --user -u "$name" -n 20 --no-pager >&2 || true
  else journalctl -u "$name" -n 20 --no-pager >&2 || true; fi
}

wait_healthy() {
  local i
  for ((i = 0; i < HEALTH_TRIES; i++)); do
    admin health >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "service.sh: the daemon did not become healthy; recent log:" >&2
  show_log
  return 1
}

install_policy() { # [OWNER GROUP]
  if [ -f "$policy" ]; then echo "keeping existing policy $policy"; return; fi
  [ -f "$policy_src" ] || die "no policy at $policy_src"
  install -m 0600 ${1:+-o "$1" -g "$2"} "$policy_src" "$policy"
}

# shellcheck source=scripts/service-lib.sh
. "$here/scripts/service-lib.sh"

layout
case $action in
  install) if [ "$tier" = user ]; then install_user; else install_system; fi ;;
  uninstall) if [ "$tier" = user ]; then uninstall_user; else uninstall_system; fi ;;
  status) status ;;
  settings) sed -e "s|__GUARD__|$daemon_bin|g" -e "s|__SOCKET__|$socket|g" \
    "$here/examples/settings.daemon.template.json" ;;
esac
