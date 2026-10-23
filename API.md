# receipts-log HTTP API

All responses are JSON (`Content-Type: application/json`) except
`GET /v1/public-key`. Errors have the shape `{"error": "<message>"}`. Hashes are
64 lowercase hex characters. Sizes and indices are decimal integers no larger
than 2^53 − 1. Every response carries `X-Request-Id`, `X-Content-Type-Options:
nosniff` and `Cache-Control: no-store` (the public key is cacheable for five
minutes). The read routes (`GET /v1/entries/{index}`, `/v1/sth`,
`/v1/proof/inclusion`, `/v1/proof/consistency`, `/v1/public-key`,
`/v1/cosignatures`, and the `/api/transparency/` read routes) also send
`Access-Control-Allow-Origin: *`, so a browser-based verifier on any origin can
read them. They serve public data and take no credentials. The write routes and
`/healthz` are same-origin only.

The wire formats are those of verifiable-receipts' transparency log
(`docs/specs/transparency-log.md`): RFC 6962 leaf and node hashes, RFC 9162
inclusion and consistency proofs, and its signed tree head. The routes under
`/api/transparency/` are the ones the verifiable-receipts witness CLI
(`bin/witness.mjs`) calls.

## Data model

**Leaf.** A receipt is logged under `SHA-256(0x00 || canonical)`, where
`canonical` is the UTF-8 bytes of the receipt's `canonical` string. Two
receipts with the same `canonical` are the same entry.

**Signed tree head (STH).**

```json
{
  "v": 1,
  "logId": "example-log",
  "treeSize": 3,
  "rootHash": "<hex>",
  "timestamp": "2026-10-23T12:00:00.000Z",
  "signature": "v2=<base64 Ed25519 signature>",
  "canonical": "{\"logId\":\"example-log\",\"rootHash\":\"<hex>\",\"timestamp\":\"2026-10-23T12:00:00.000Z\",\"treeSize\":3,\"v\":1}"
}
```

The signature covers the UTF-8 bytes of `canonical`: the keys `logId`,
`rootHash`, `timestamp`, `treeSize`, `v` in that order, written as JavaScript's
`JSON.stringify` writes them. `canonical` is included so clients need not
rebuild it; a verifier should rebuild it from the other fields and compare.
`timestamp` is in the form of `Date.prototype.toISOString` and never decreases.

## Limits

| Limit | Value |
| --- | --- |
| Receipt body (`POST /v1/entries`) | `-max-entry-bytes`, default 1 MiB (413 above it) |
| Cosignature body | 64 KiB |
| Query string | 2048 bytes (414 above it) |
| Request headers | 16 KiB |
| Concurrent requests | `-max-in-flight`, default 256 (503 with `Retry-After: 1` above it) |
| Timeouts | header 5 s, read 20 s, write 40 s, idle 90 s |

## Routes

### `POST /v1/entries`

Submit a receipt. The body is the receipt JSON object (`Content-Type:
application/json`, or no content type). The log admits it when its signature
verifies under one of the configured issuer keys, by the rules of
verifiable-receipts' `VerifyV2Receipt` (Ed25519 `v2=` signature over
`canonical`, optional `contentHash`, every other top-level field equal to the
same field in the parsed canonical) or `VerifyGuardianAttestation`. The entry is
written durably and a new STH is signed before the response is sent.

| Status | Meaning |
| --- | --- |
| 201 | Appended |
| 200 | Already logged (same `canonical`); the existing entry is returned |
| 400 | Not a JSON object, no `canonical`, or a `canonical`, `contentHash` or `signature` that is not a string |
| 413 | Body too large |
| 415 | Content type other than `application/json` |
| 422 | Signature does not verify under any issuer key (the reason is in `error`) |
| 503 | The log is read-only after a storage failure, holds 2^53 − 1 entries, or is busy |

```json
{"index": 0, "leafHash": "<hex>", "duplicate": false, "sth": { <STH as above> }}
```

### `GET /v1/entries/{index}`

```json
{"index": 0, "leafHash": "<hex>", "receipt": { <the receipt as submitted, compact JSON> }}
```

400 when `index` is not a decimal integer; 404 when it is not below the latest
tree size.

### `GET /v1/sth` and `GET /api/transparency/sth`

The latest STH (shape above). The server re-signs it every `-sth-interval`
(default one hour) when nothing is appended, so its timestamp shows the log is
live.

### `GET /v1/proof/inclusion`

Query: exactly one of `index=<n>` or `leafHash=<hex>`, and optionally
`treeSize=<n>` (default: the latest tree size). Also served as
`GET /api/transparency/proof?kind=inclusion&...`.

```json
{
  "kind": "inclusion",
  "logId": "example-log",
  "leafHashHex": "<hex>",
  "leafIndex": 1,
  "treeSize": 4,
  "auditPath": ["<hex>", "<hex>"],
  "rootHashHex": "<hex>"
}
```

The fields are named as in verifiable-receipts' conformance fixtures, so the
response can be passed to its TypeScript `verifyInclusionProof`, Python
`verify_inclusion_proof` or Go `VerifyInclusionProof` as is. `rootHashHex` is
the root at `treeSize`; check it against an STH you trust, not against this
response. 400 for a bad query or an index or size beyond the latest tree, 404
for a `leafHash` that is not in the latest tree.

### `GET /v1/proof/consistency`

Query: `old=<m>` and optionally `new=<n>` (default: the latest tree size), with
`m <= n`. Also served as `GET /api/transparency/proof?kind=consistency&old=<m>&new=<n>`.
400 for a bad query, `m > n`, or `n` beyond the latest tree.

```json
{
  "kind": "consistency",
  "logId": "example-log",
  "oldSize": 3,
  "newSize": 7,
  "oldRootHex": "<hex>",
  "newRootHex": "<hex>",
  "proof": ["<hex>", "..."]
}
```

The proof is empty when `old` is 0 or `old` equals `new`. Verify it with
verifiable-receipts' `verifyConsistencyProof(oldSize, newSize, oldRoot,
newRoot, proof)` using roots from STHs you trust.

### `GET /v1/public-key`

The log's Ed25519 public key as SPKI PEM (`application/x-pem-file`). Fetching it
over the same channel as the STHs proves nothing; distribute it out of band.

### `POST /v1/cosignatures` and `POST /api/transparency/witness`

A witness submits its signature over an STH:

```json
{"witnessId": "w1", "sthCanonical": "<canonical STH string>", "signature": "v2=<base64>", "publicKeyUrl": "https://..."}
```

The log records it when `witnessId` is configured (`-witness-key NAME=FILE`),
the signature verifies under that witness's key, `sthCanonical` is in canonical
form, and it names this log and a root this log had at that tree size.
Cosignatures are stored durably; a repeated submission is not stored twice.

```json
{"ok": true, "recorded": true, "firstForThisSth": true, "witnessCount": 1}
```

| Status | Meaning |
| --- | --- |
| 200 | Recorded, or already recorded (`recorded: false`) |
| 400 | Malformed body or non-canonical `sthCanonical` |
| 403 | Unknown witness |
| 409 | The tree head is not one this log produced |
| 413 | Body larger than 64 KiB |
| 415 | Content type other than `application/json` |
| 422 | The witness signature does not verify |
| 503 | The log is read-only after a storage failure, or busy |

### `GET /v1/cosignatures?treeSize=<n>`

`treeSize` is required (400 without it). The response lists the cosignatures
recorded for tree heads of that size:

```json
{"treeSize": 7, "cosignatures": [{"witnessId": "w1", "treeSize": 7, "rootHash": "<hex>", "timestamp": "...", "sthCanonical": "...", "signature": "v2=...", "publicKeyUrl": "...", "receivedAt": "..."}]}
```

### `GET /healthz`

`200 {"ok": true, "treeSize": n}`, or `503 {"ok": false, "readOnly": true}`
after a storage failure.

Other paths answer 404 and other methods on known paths 405, both as JSON.
