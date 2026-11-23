#!/usr/bin/env bash
# Let a Tier S daemon read Claude Code's subagent sidecar files.
#
#   scripts/sidecar-acl.sh grant|revoke|show [--service-user NAME] [--home DIR]
#
# Run it as the Claude Code user: you own these files, so no root is needed.
# grant gives the service account (default _delegateguard) search on HOME and
# HOME/.claude, and read on HOME/.claude/projects, including files Claude Code
# creates later. Nothing else in HOME becomes readable. Without the grant, a
# Tier S daemon cannot see sidecars and binds by the meet rule instead.
#
# Linux uses POSIX ACLs (setfacl). A named entry is capped by the ACL mask, which
# follows a new file's group bits: under umask 077 Claude Code creates 0600
# files and the grant does not reach them (measured modes: 0664 at umask 002,
# 0644 at umask 022). macOS uses extended ACLs (chmod +a), which the mode bits
# do not cap.
# Exit: 0 ok, 1 failed, 64 usage.
set -euo pipefail

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 64; }
action=${1:-}
[ $# -gt 0 ] && shift
svc=_delegateguard home=$HOME
while [ $# -gt 0 ]; do
  case $1 in
    --service-user) [ $# -ge 2 ] || usage; svc=$2; shift 2 ;;
    --home) [ $# -ge 2 ] || usage; home=$2; shift 2 ;;
    *) usage ;;
  esac
done
case $action in grant | revoke | show) ;; *) usage ;; esac
id -u "$svc" >/dev/null 2>&1 || { echo "sidecar-acl.sh: no such user: $svc" >&2; exit 1; }
projects=$home/.claude/projects
os=$(uname -s)

linux_grant() {
  setfacl -m "u:$svc:--x" "$home" "$home/.claude"
  setfacl -R -m "u:$svc:rX" "$projects"
  find "$projects" -type d -exec setfacl -d -m "u:$svc:rX" {} +
}

linux_revoke() {
  setfacl -x "u:$svc" "$home" "$home/.claude"
  setfacl -R -x "u:$svc" "$projects"
  find "$projects" -type d -exec setfacl -d -x "u:$svc" {} +
}

readonly MAC_DIR="list,search,readattr,readextattr,readsecurity"
readonly MAC_FILE="read,readattr,readextattr,readsecurity"

# Two entries per directory: one for directories, one carried down for files.
# The file entry also needs directory_inherit, or a directory created later
# (Claude Code makes <session>/subagents/ per session) passes nothing to its files.
mac_grant() {
  chmod +a "user:$svc allow search" "$home" "$home/.claude"
  find "$projects" -type d -exec chmod +a "user:$svc allow $MAC_DIR,directory_inherit" {} + \
    -exec chmod +a "user:$svc allow $MAC_FILE,file_inherit,directory_inherit,only_inherit" {} +
  find "$projects" -type f -exec chmod +a "user:$svc allow $MAC_FILE" {} +
}

# mac_strip PATH: delete every entry naming the service user, own or inherited.
# ls -le is how macOS shows ACL entries; only those lines are parsed, never names.
# shellcheck disable=SC2012
mac_strip() {
  local index
  for index in $(ls -led "$1" | awk -v who="user:$svc" '$2 == who {sub(":", "", $1); print $1}' | sort -rn); do
    chmod -a# "$index" "$1"
  done
}

mac_revoke() {
  mac_strip "$home"
  mac_strip "$home/.claude"
  find "$projects" -print0 | while IFS= read -r -d '' path; do mac_strip "$path"; done
}

# shellcheck disable=SC2010  # counts ACL entry lines of ls -le, not file names
show() {
  local path
  for path in "$home" "$home/.claude" "$projects"; do
    if [ "$os" = Darwin ]; then
      printf '%s: %s\n' "$path" "$(ls -led "$path" | grep -c "user:$svc") entries for $svc"
    else
      printf '%s: %s\n' "$path" "$(getfacl -p "$path" 2>/dev/null | grep -E "^(default:)?user:$svc:" | tr '\n' ' ')"
    fi
  done
}

case $action in
  grant)
    install -d -m 0700 "$projects"
    if [ "$os" = Darwin ]; then mac_grant; else linux_grant; fi
    show ;;
  revoke)
    if [ "$os" = Darwin ]; then mac_revoke; else linux_revoke; fi
    show ;;
  show) show ;;
esac
