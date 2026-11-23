#!/usr/bin/env bash
# Regenerates the admin API's Rust code from proto/ (or, with --check, fails if
# the checked-in copy is stale). The generator is an isolated workspace.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
dest="$here/crates/admin/src/generated"
gen() { cargo run --quiet --locked --manifest-path "$here/tools/codegen/Cargo.toml" -- "$here/proto" "$1"; }
if [ "${1:-}" = "--check" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  gen "$tmp"
  diff -r "$tmp" "$dest" && echo "generated code is up to date"
else
  gen "$dest"
fi
