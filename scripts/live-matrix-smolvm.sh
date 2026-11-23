#!/usr/bin/env bash
# The live test matrix in smolvm microVMs: every run in a fresh VM booted from
# a local image archive, so nothing is pulled at boot and the egress allowlist
# stays closed. Build the image first (Dagger, from this workspace):
#
#   dagger run cargo run --locked --manifest-path ci/Cargo.toml -- live-image --out dg-live.tar
#
# then, with a Claude Code settings file whose "env" block points at an
# Anthropic-format gateway (see README) and that gateway's addresses:
#
#   scripts/live-matrix-smolvm.sh --image dg-live.tar --settings gw.json \
#     --dns RESOLVER_IP --allow-cidr RESOLVER_IP/32 --allow-cidr GATEWAY_IP/32 --runs 5
#
# Before any test it boots a VM and refuses to go on unless api.anthropic.com
# is unreachable and the gateway is reachable from inside it. Each run executes
# scripts/live-scenarios.sh (or live-test.sh for the scenario "live-test") as
# an unprivileged user with a fresh home. Exit 0 when no run FAILed, 1 when one
# did or the preflight failed, 64 on bad usage. No credential enters the VMs.
set -euo pipefail

usage() {
  echo "usage: $0 --image FILE --settings FILE --allow-cidr CIDR [--allow-cidr CIDR]... [--dns IP]" >&2
  echo "          [--runs N] [--jobs N] [--scenarios 'basic daemon budget adversarial broken-hook nested parallel revoke live-test'] [--logs DIR]" >&2
  exit 64
}
image="" settings="" dns="" runs=5 jobs=3 logs=""
scenarios="basic daemon budget adversarial broken-hook nested parallel revoke live-test"
net=()
while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="${2:-}"; shift 2 ;;
    --settings) settings="${2:-}"; shift 2 ;;
    --dns) dns="${2:-}"; net+=(--dns "$dns"); shift 2 ;;
    --allow-cidr) [ -n "${2:-}" ] || usage; net+=(--allow-cidr "$2"); shift 2 ;;
    --runs) runs="${2:-}"; shift 2 ;;
    --jobs) jobs="${2:-}"; shift 2 ;;
    --scenarios) scenarios="${2:-}"; shift 2 ;;
    --logs) logs="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ -f "$image" ] && [ -f "$settings" ] || usage
case "$runs$jobs" in *[!0-9]* | "") usage ;; esac
printf '%s\n' "${net[@]}" | grep -q -- --allow-cidr || { echo "at least one --allow-cidr is required: the VMs must not have open egress" >&2; exit 64; }
if ! command -v smolvm >/dev/null || ! command -v jq >/dev/null; then echo "needs smolvm and jq" >&2; exit 64; fi
gateway="$(jq -er '.env.ANTHROPIC_BASE_URL' "$settings")" || { echo "$settings has no env.ANTHROPIC_BASE_URL" >&2; exit 64; }

repo="$(cd "$(dirname "$0")/.." && pwd)"
image="$(cd "$(dirname "$image")" && pwd)/$(basename "$image")"
conf="$(cd "$(dirname "$settings")" && pwd)"
conf_file="$(basename "$settings")"
logs="${logs:-$(mktemp -d)}"
mkdir -p "$logs"
: >"$logs/results.txt"
prefix="dg-lm-$$"

# The in-VM command: copy what the tests read to a place the unprivileged
# user can read, give it a fresh home, and run as that user.
in_vm() {
  local inner; inner="$(printf '%s' "$1" | sed "s/'/'\\\\''/g")" # quote for sh: each ' becomes '\''
  printf '%s' "mkdir -p /opt/dg-run && cp -r /repo/scripts /repo/examples /opt/dg-run/ && cp /conf/$conf_file /opt/dg-run/settings.json && chmod -R a+rX /opt/dg-run && rm -rf /tmp/home && install -d -o tester -g tester -m 700 /tmp/home && runuser -u tester -- env HOME=/tmp/home bash -c '$inner'"
}
boot() { # $1 = machine name
  smolvm machine delete --name "$1" -f >/dev/null 2>&1 || true
  smolvm machine create --name "$1" --image "$image" "${net[@]}" -v "$conf:/conf:ro" -v "$repo:/repo:ro" >/dev/null 2>&1 &&
    smolvm machine start --name "$1" >/dev/null 2>&1
}
teardown() { smolvm machine stop --name "$1" >/dev/null 2>&1 || true; smolvm machine delete --name "$1" -f >/dev/null 2>&1 || true; }

echo "== preflight: egress from inside a VM"
probe="node -e 'const t=(u)=>fetch(u,{signal:AbortSignal.timeout(8000)}).then(r=>console.log(\"OPEN\",u,r.status)).catch(e=>console.log(\"BLOCKED\",u,(e.cause&&e.cause.code)||e.name));t(\"https://api.anthropic.com/\").then(()=>t(\"$gateway\"))'"
boot "$prefix-preflight" || { echo "preflight VM did not start"; exit 1; }
pre="$(smolvm machine exec --name "$prefix-preflight" --timeout 2m -- sh -c "$(in_vm "$probe")" 2>/dev/null | grep -E '^(OPEN|BLOCKED) ' || true)"
teardown "$prefix-preflight"
echo "$pre"
echo "$pre" | grep -q '^BLOCKED https://api.anthropic.com/' || { echo "REFUSED: api.anthropic.com is reachable from the VM; egress is not restricted"; exit 1; }
echo "$pre" | grep -q "^OPEN $gateway" || { echo "REFUSED: the gateway is not reachable from the VM"; exit 1; }

command_for() { # $1 = scenario
  case "$1" in
    live-test) in_vm "bash /opt/dg-run/scripts/live-test.sh --binary /opt/dg/bin/delegate-guard --settings /opt/dg-run/settings.json" ;;
    *) in_vm "bash /opt/dg-run/scripts/live-scenarios.sh --scenario $1 --binary /opt/dg/bin/delegate-guard --settings /opt/dg-run/settings.json" ;;
  esac
}
verdict_for() { case "$1" in 0) echo PASS ;; 1) echo FAIL ;; 2) echo INCONCLUSIVE ;; 3) echo INCOMPLETE ;; *) echo "ERROR($1)" ;; esac; }

queue=()
for s in $scenarios; do for i in $(seq "$runs"); do queue+=("$s:$i"); done; done
echo "== $((${#queue[@]})) runs, $jobs at a time; logs in $logs"
n=0
while [ "$n" -lt "${#queue[@]}" ]; do
  batch=("${queue[@]:$n:$jobs}")
  pids=() names=()
  for item in "${batch[@]}"; do # boot one at a time: concurrent creates race on smolvm's database
    name="$prefix-${item/:/-}"
    if boot "$name"; then
      scenario="${item%%:*}"
      ( set +e; smolvm machine exec --name "$name" --timeout 25m -- sh -c "$(command_for "$scenario")" >"$logs/$name.log" 2>&1
        echo "$scenario $(verdict_for $?) $name" >>"$logs/results.txt" ) &
      pids+=($!) names+=("$name")
    else
      echo "${item%%:*} ERROR(boot) $name" >>"$logs/results.txt"
      teardown "$name"
    fi
  done
  for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || true; done
  for name in ${names[@]+"${names[@]}"}; do teardown "$name"; done
  n=$((n + jobs))
  echo "  $(wc -l <"$logs/results.txt" | tr -d ' ')/${#queue[@]} done"
done

echo "== results (scenario: verdict count)"
sort "$logs/results.txt" | awk '{print $1, $2}' | uniq -c | awk '{printf "  %-12s %-13s %s\n", $2, $3, $1}'
echo "== subagent calls, all runs (tool:decision count)"
grep -h '^INFO: subagent calls:' "$logs"/*.log 2>/dev/null | grep -oE '[0-9]+ [A-Za-z_]+:[a-z]+' |
  awk '{c[$2]+=$1} END {for (k in c) printf "  %-22s %d\n", k, c[k]}' | sort
if grep -q ' FAIL ' "$logs/results.txt"; then echo "MATRIX: FAIL"; exit 1; fi
echo "MATRIX: no guard failure"