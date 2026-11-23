# shellcheck shell=bash
# shellcheck disable=SC2154  # layout variables are set by service.sh, which sources this
# Service-manager and account operations for scripts/service.sh. Sourced, not run.

sc() { if [ "$tier" = user ]; then systemctl --user "$@"; else systemctl "$@"; fi; }
domain() { if [ "$tier" = user ]; then echo "gui/$(id -u)"; else echo system; fi; }

start_service() {
  if [ "$os" = Darwin ]; then
    launchctl bootout "$(domain)/$label" 2>/dev/null || true
    launchctl bootstrap "$(domain)" "$unit"
  else
    sc daemon-reload
    sc enable "$name.service"
    sc restart "$name.service"
  fi
}

stop_service() {
  if [ "$os" = Darwin ]; then
    launchctl bootout "$(domain)/$label" 2>/dev/null || true
  else
    sc disable --now "$name.service" 2>/dev/null || true
  fi
}

reload_units() {
  [ "$os" = Linux ] && command -v systemctl >/dev/null || return 0
  sc daemon-reload || echo "service.sh: warning: daemon-reload failed" >&2
}

service_state() {
  if [ "$os" = Darwin ]; then
    launchctl print "$(domain)/$label" 2>/dev/null | awk '$1 == "state" {print $3; exit}' | grep . || echo "not loaded"
  else
    sc is-active "$name.service" 2>/dev/null || true
  fi
}

main_pid() {
  if [ "$os" = Darwin ]; then
    launchctl print "$(domain)/$label" 2>/dev/null | awk '$1 == "pid" {print $3; exit}'
  else
    sc show -p MainPID --value "$name.service" 2>/dev/null | grep -v '^0$' || true
  fi
}

lint_unit() {
  if [ "$os" = Linux ] && ! command -v systemd-analyze >/dev/null; then
    echo "systemd-analyze not found: $unit not verified"
    return
  fi
  if [ "$os" = Darwin ]; then plutil -lint "$unit" >/dev/null
  elif [ "$tier" = user ]; then systemd-analyze --user verify "$unit"
  else systemd-analyze verify "$unit"; fi
}

finish_install() {
  lint_unit
  if [ "$no_start" = 1 ]; then echo "wrote $unit (not started)"; return; fi
  start_service
  wait_healthy
  echo "installed $label; hook socket $socket"
  echo "hook settings: scripts/service.sh settings --tier $tier --name $name"
}

install_user() {
  install -d -m 0700 "$root" "$state"
  install_policy
  install -d "$(dirname "$unit")"
  if [ "$os" = Darwin ]; then
    install -d -m 0700 "$run_dir"
    render "$here/packaging/launchd/agent.plist.in" "$unit"
  else
    render "$here/packaging/systemd/user.service.in" "$unit"
  fi
  finish_install
}

uninstall_user() {
  stop_service
  rm -f "$unit"
  reload_units
  if [ "$purge" = 1 ]; then
    rm -rf "$state"
    rm -f "$policy" "$socket" "$admin"
    [ "$log" = journal ] || rm -f "$log"
    [ "$os" = Linux ] || rmdir "$run_dir" 2>/dev/null || true
    rmdir "$root" 2>/dev/null || echo "left $root: it holds files this script did not create"
  else
    echo "kept $root (policy, state, receipts); --purge deletes them"
  fi
  echo "uninstalled $label"
}

ensure_accounts() {
  if [ "$os" = Linux ]; then
    getent group "$SERVICE_GROUP" >/dev/null || groupadd --system "$SERVICE_GROUP"
    id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --gid "$SERVICE_GROUP" \
      --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
    return
  fi
  if ! dscl . -read "/Groups/$SERVICE_GROUP" >/dev/null 2>&1; then
    dseditgroup -o create -i "$(free_id)" -r "delegate-guard callers" "$SERVICE_GROUP"
  fi
  if ! dscl . -read "/Users/$SERVICE_USER" >/dev/null 2>&1; then
    local id gid
    id=$(free_id)
    gid=$(dscl . -read "/Groups/$SERVICE_GROUP" PrimaryGroupID | awk '{print $2}')
    dscl . -create "/Users/$SERVICE_USER"
    dscl . -create "/Users/$SERVICE_USER" UniqueID "$id"
    dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$gid"
    dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$SERVICE_USER" RealName "delegate-guard daemon"
    dscl . -create "/Users/$SERVICE_USER" Password '*'
    dscl . -create "/Users/$SERVICE_USER" IsHidden 1
  fi
}

# free_id: the lowest id in 200..400 used by no user and no group (macOS).
free_id() {
  local used i
  used=$({ dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')
  for ((i = 200; i <= 400; i++)); do
    grep -qx "$i" <<<"$used" || { echo "$i"; return; }
  done
  die "no free id in 200..400"
}

# callers: resolve --allow-users to uids and admit each to the socket group.
callers() {
  local u uid
  allow_uids=''
  for u in $(tr ',' ' ' <<<"$allow_users"); do
    uid=$(id -u "$u" 2>/dev/null) || die "no such user: $u"
    [ "$uid" != 0 ] || die "root cannot be a caller"
    if [ "$os" = Linux ]; then usermod -a -G "$SERVICE_GROUP" "$u"
    else dseditgroup -o edit -a "$u" -t user "$SERVICE_GROUP"; fi
    allow_uids=$allow_uids${allow_uids:+,}$uid
  done
}

install_system() {
  [ "$(id -u)" = 0 ] || die "--tier system must run as root"
  [ -n "$allow_users" ] || die "--allow-users is required for --tier system"
  local src=${bin:-$(command -v delegate-guard || true)}
  [ -n "$src" ] && [ -x "$src" ] || die "no delegate-guard binary; pass --bin"
  ensure_accounts
  callers
  # Root-owned binary: a caller who could replace it could replace the guard.
  install -d -o root -m 0755 "$(dirname "$daemon_bin")"
  install -o root -m 0755 "$src" "$daemon_bin"
  if [ "$os" = Darwin ]; then
    install -d -o root -m 0755 "$(dirname "$state")"
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$run_dir"
    install -d -o "$SERVICE_USER" -m 0700 "$state" "$(dirname "$log")"
    install_policy "$SERVICE_USER" "$SERVICE_GROUP"
    render "$here/packaging/launchd/daemon.plist.in" "$unit"
  else
    # /run/NAME and /var/lib/NAME come from RuntimeDirectory= and StateDirectory=.
    install -d -o root -m 0755 "$(dirname "$policy")"
    install_policy "$SERVICE_USER" "$SERVICE_GROUP"
    render "$here/packaging/systemd/system.service.in" "$unit"
  fi
  chmod 0644 "$unit"
  finish_install
}

uninstall_system() {
  [ "$(id -u)" = 0 ] || die "--tier system must run as root"
  stop_service
  rm -f "$unit"
  reload_units
  rm -f "$daemon_bin"
  rmdir "$(dirname "$daemon_bin")" 2>/dev/null || true
  if [ "$purge" != 1 ]; then
    echo "kept policy, state, receipts and the $SERVICE_USER account; --purge deletes them"
  elif [ "$os" = Linux ]; then
    rm -rf "$state" "$run_dir" "$(dirname "$policy")"
    userdel "$SERVICE_USER" 2>/dev/null || true
    groupdel "$SERVICE_GROUP" 2>/dev/null || true
  else
    rm -rf "$(dirname "$state")"
    dscl . -delete "/Users/$SERVICE_USER" 2>/dev/null || true
    dseditgroup -o delete "$SERVICE_GROUP" 2>/dev/null || true
  fi
  echo "uninstalled $label"
}

status() {
  local health
  echo "label   $label"
  if [ -f "$unit" ]; then echo "unit    $unit"; else echo "unit    $unit (not installed)"; fi
  echo "state   $(service_state)"
  echo "pid     $(main_pid)"
  echo "socket  $socket"
  if health=$(admin health 2>&1); then
    echo "health  $health"
    return 0
  fi
  echo "health  unavailable: $health"
  return 1
}
