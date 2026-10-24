#!/usr/bin/env bash
# run-ts-witness.sh — runs the verifiable-receipts witness CLI
# (packages/verifiable-receipts/bin/witness.mjs) without building the
# package: it copies the CLI scripts and the TypeScript sources into a
# temporary directory, with the sources' "./name.js" imports renamed to
# "./name.ts", next to a dist/transparency.js that re-exports
# src/transparency.ts, which Node loads with type stripping. The checkout
# itself is not modified.
#
# Usage: run-ts-witness.sh <checkout> <witness.mjs args...>
set -euo pipefail
repo="$1"; shift
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pkg="$repo/packages/verifiable-receipts"
mkdir -p "$work/bin" "$work/dist" "$work/src"
cp "$pkg"/bin/*.mjs "$work/bin/"
for f in "$pkg"/src/*.ts; do
  sed -E 's#(from[[:space:]]+"\./[A-Za-z0-9_.-]+)\.js"#\1.ts"#g' "$f" > "$work/src/$(basename "$f")"
done
printf 'export * from "../src/transparency.ts";\n' > "$work/dist/transparency.js"
printf '{"type":"module"}\n' > "$work/package.json"
set +e
node "$work/bin/witness.mjs" "$@"
code=$?
exit "$code"
