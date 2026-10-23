// ts-tool.mjs — runs the verifiable-receipts TypeScript transparency
// module (src/transparency.ts, loaded with Node's type stripping) over a
// JSON job read from stdin, and prints the results as JSON.
//
// Usage: node ts-tool.mjs <verifiable-receipts checkout> < job.json
//
// Job: {
//   leaves:      [hex leaf hash, ...]                 tree to rebuild
//   inclusion:   [{leafHashHex, leafIndex, treeSize, auditPath, rootHashHex}]
//   consistency: [{oldSize, newSize, oldRootHex, newRootHex, proof}]
//   sths:        [{v, logId, treeSize, rootHash, timestamp, signature}]
//   logPublicKeyPem: "..."                            verifies the STHs
// }
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey, verify } from "node:crypto";

const repo = process.argv[2];
const t = await import(join(repo, "packages/verifiable-receipts/src/transparency.ts"));
const job = JSON.parse(readFileSync(0, "utf8"));
const leaves = job.leaves ?? [];
const out = {};

out.roots = [];
for (let n = 0; n <= leaves.length; n++) out.roots.push(t.treeRoot(leaves.slice(0, n)));

out.inclusionProofs = [];
for (let n = 1; n <= leaves.length; n++)
  for (let i = 0; i < n; i++)
    out.inclusionProofs.push({ i, n, proof: t.inclusionProof(i, leaves.slice(0, n)) });

out.consistencyProofs = [];
for (let n = 1; n <= leaves.length; n++)
  for (let m = 0; m <= n; m++)
    out.consistencyProofs.push({ m, n, proof: t.consistencyProof(m, leaves.slice(0, n)) });

out.inclusion = (job.inclusion ?? []).map((p) =>
  t.verifyInclusionProof(p.leafHashHex, p.leafIndex, p.treeSize, p.auditPath, p.rootHashHex),
);
out.consistency = (job.consistency ?? []).map((p) =>
  t.verifyConsistencyProof(p.oldSize, p.newSize, p.oldRootHex, p.newRootHex, p.proof),
);

const key = job.logPublicKeyPem ? createPublicKey(job.logPublicKeyPem) : null;
out.sths = (job.sths ?? []).map((s) => {
  const canonical = t.canonicalizeSth(s);
  let signatureOk = null;
  if (key && typeof s.signature === "string" && s.signature.startsWith("v2=")) {
    signatureOk = verify(null, Buffer.from(canonical, "utf8"), key, Buffer.from(s.signature.slice(3), "base64"));
  }
  return { canonical, signatureOk };
});

process.stdout.write(JSON.stringify(out));
