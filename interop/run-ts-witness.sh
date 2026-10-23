#!/usr/bin/env bash
# run-ts-witness.sh — runs the verifiable-receipts witness CLI
# (packages/verifiable-receipts/bin/witness.mjs) without building the
# package: it copies the CLI into a temporary directory next to a
# dist/transparency.js that re-exports src/transparency.ts, which Node
# loads with type stripping. The checkout itself is not modified.
#
# Usage: run-ts-witness.sh <checkout> <witness.mjs args...>
set -euo pipefail
repo="$1"; shift
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/dist"
cp "$repo/packages/verifiable-receipts/bin/witness.mjs" "$work/bin/witness.mjs"
printf 'export * from %s;\n' "\"$repo/packages/verifiable-receipts/src/transparency.ts\"" > "$work/dist/transparency.js"
printf '{"type":"module"}\n' > "$work/package.json"
set +e
node "$work/bin/witness.mjs" "$@"
code=$?
exit "$code"
