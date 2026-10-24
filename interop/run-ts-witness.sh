#!/usr/bin/env bash
# run-ts-witness.sh — runs the verifiable-receipts witness CLI
# (packages/verifiable-receipts/bin/witness.mjs) without building the
# package: it copies the CLI scripts into a temporary directory, and the
# TypeScript sources with ts-src.mjs, next to a dist/ in which each
# dist/<name>.js re-exports src/<name>.ts, which Node loads with type
# stripping. The CLI may import any module of dist/ (witness.mjs imports
# transparency.js and hash.js). The checkout itself is not modified.
#
# Usage: run-ts-witness.sh <checkout> <witness.mjs args...>
set -euo pipefail
repo="$1"; shift
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pkg="$repo/packages/verifiable-receipts"
mkdir -p "$work/bin" "$work/dist" "$work/src"
cp "$pkg"/bin/*.mjs "$work/bin/"
node "$(dirname "$0")/ts-src.mjs" "$repo" "$work/src"
for ts in "$work"/src/*.ts; do
  name="$(basename "$ts" .ts)"
  printf 'export * from "../src/%s.ts";\n' "$name" > "$work/dist/$name.js"
done
printf '{"type":"module"}\n' > "$work/package.json"
set +e
node "$work/bin/witness.mjs" "$@"
code=$?
exit "$code"
