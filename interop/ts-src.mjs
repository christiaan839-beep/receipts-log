// ts-src.mjs — copies the verifiable-receipts TypeScript sources
// (packages/verifiable-receipts/src/*.ts) into a temporary directory so
// Node can load them with type stripping and no build. The sources
// import each other as "./name.js", the name of the compiled file; the
// copies name "./name.ts" instead. The checkout is not modified, and the
// directory is removed when the process exits.
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export function tsSources(repo) {
  const src = join(repo, "packages/verifiable-receipts/src");
  const work = mkdtempSync(join(tmpdir(), "vr-src-"));
  process.on("exit", () => rmSync(work, { recursive: true, force: true }));
  writeFileSync(join(work, "package.json"), '{"type":"module"}\n');
  for (const name of readdirSync(src)) {
    if (!name.endsWith(".ts")) continue;
    const text = readFileSync(join(src, name), "utf8").replace(/(from\s+"\.\/[\w.-]+)\.js"/g, '$1.ts"');
    writeFileSync(join(work, name), text);
  }
  return (name) => pathToFileURL(join(work, name)).href;
}
