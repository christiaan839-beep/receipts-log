// ts-src.mjs — copies the verifiable-receipts TypeScript sources
// (packages/verifiable-receipts/src/*.ts) into a directory so Node can
// load them with type stripping and no build. The sources import each
// other as "./name.js", the name of the compiled file; the copies name
// "./name.ts" instead, and a copy that still names a "./name.js" is an
// error. The checkout is not modified.
//
// As a script: node ts-src.mjs <checkout> <dir> copies into <dir>.
// As a module: tsSources(checkout) copies into a new temporary directory,
// removed when the process exits normally, and returns a function from
// a source's name to its file URL.
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// A relative "./name.js" specifier after from or import, including
// import("./name.js") and side-effect imports, in either quote style.
const relativeJs = /((?:from|import)\s*\(?\s*)(["'])\.\/([\w.-]+)\.js\2/g;
const leftover = /(["'])\.\/[\w.-]+\.js\1/;

export function copySources(repo, dir) {
  const src = join(repo, "packages/verifiable-receipts/src");
  writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
  for (const name of readdirSync(src)) {
    if (!name.endsWith(".ts")) continue;
    const text = readFileSync(join(src, name), "utf8").replace(relativeJs, "$1$2./$3.ts$2");
    const left = text.match(leftover);
    if (left) throw new Error(`ts-src.mjs: ${name} still names ${left[0]} after the rewrite`);
    writeFileSync(join(dir, name), text);
  }
}

export function tsSources(repo) {
  const work = mkdtempSync(join(tmpdir(), "vr-src-"));
  process.on("exit", () => rmSync(work, { recursive: true, force: true }));
  copySources(repo, work);
  return (name) => pathToFileURL(join(work, name)).href;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [repo, dir] = process.argv.slice(2);
  if (!repo || !dir) {
    console.error("usage: node ts-src.mjs <checkout> <dir>");
    process.exit(2);
  }
  copySources(repo, dir);
}
