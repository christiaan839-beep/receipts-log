// ts-log-server.mjs — a log server built on the verifiable-receipts
// TypeScript TransparencyLog (src/log-store.ts), serving the routes its
// witness CLI expects. It is the counterpart in the interop tests: the
// Go witness must accept this log's tree heads and proofs.
//
// Usage: node ts-log-server.mjs <checkout> <ed25519-private.pem> <logId>
// Prints "listening <port>" once ready. Extra test routes:
//   POST /test/append  {"data": "<string>"}   append one leaf
//   POST /test/reset   {"leaves": ["..."]}    replace the log (a fork)
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createServer } from "node:http";
import { createPrivateKey, sign } from "node:crypto";

const [repo, keyPath, logId] = process.argv.slice(2);
const src = join(repo, "packages/verifiable-receipts/src");
// log-store.ts imports "./transparency.js", the name of the compiled
// file. Load a copy whose import names the .ts source instead, so the
// package needs no build; the checkout is not modified.
const work = mkdtempSync(join(tmpdir(), "ts-log-"));
process.on("exit", () => rmSync(work, { recursive: true, force: true }));
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => process.exit(0));
const transparencyUrl = pathToFileURL(join(src, "transparency.ts")).href;
writeFileSync(
  join(work, "log-store.ts"),
  readFileSync(join(src, "log-store.ts"), "utf8").replace('"./transparency.js"', JSON.stringify(transparencyUrl)),
);
const { TransparencyLog, InMemoryLogStore } = await import(pathToFileURL(join(work, "log-store.ts")).href);
const { canonicalizeSth } = await import(transparencyUrl);
const key = createPrivateKey(readFileSync(keyPath, "utf8"));

let log = new TransparencyLog(logId, new InMemoryLogStore());
const cosignatures = [];

async function body(req) {
  let s = "";
  for await (const c of req) s += c;
  return JSON.parse(s || "{}");
}

function send(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/api/transparency/sth") {
      const sth = log.currentSth();
      const canonical = canonicalizeSth(sth);
      const signature = "v2=" + sign(null, Buffer.from(canonical, "utf8"), key).toString("base64");
      return send(res, 200, { ...sth, signature, canonical });
    }
    if (req.method === "GET" && url.pathname === "/api/transparency/proof") {
      if (url.searchParams.get("kind") !== "consistency") return send(res, 400, { error: "kind" });
      const oldSize = Number(url.searchParams.get("old"));
      const newSize = Number(url.searchParams.get("new"));
      return send(res, 200, { kind: "consistency", logId, oldSize, newSize, proof: log.proveConsistency(oldSize, newSize) });
    }
    if (req.method === "POST" && url.pathname === "/api/transparency/witness") {
      cosignatures.push(await body(req));
      return send(res, 200, { ok: true, recorded: true, witnessCount: cosignatures.length });
    }
    if (req.method === "POST" && url.pathname === "/test/append") {
      const { data } = await body(req);
      log.append(data);
      return send(res, 200, { size: log.size() });
    }
    if (req.method === "POST" && url.pathname === "/test/reset") {
      const { leaves } = await body(req);
      log = new TransparencyLog(logId, new InMemoryLogStore());
      for (const l of leaves) log.append(l);
      return send(res, 200, { size: log.size() });
    }
    if (req.method === "GET" && url.pathname === "/test/cosignatures") return send(res, 200, cosignatures);
    send(res, 404, { error: "not found" });
  } catch (err) {
    send(res, 500, { error: String(err?.message ?? err) });
  }
});
server.listen(0, "127.0.0.1", () => process.stdout.write(`listening ${server.address().port}\n`));
