# receipts-log HTTP API

All responses are JSON (`Content-Type: application/json`) except
`GET /v1/public-key`. Errors have the shape `{"error": "<message>"}`. Hashes are
64 lowercase hex characters. Sizes and indices are decimal integers no larger
than 2^53 − 1. Every response carries `X-Request-Id`, `X-Content-Type-Options:
nosniff` and `Cache-Control: no-store` (the public key is cacheable for five
minutes). The read routes (`GET /v1/entries/{index}`, `/v1/sth`,
`/v1/proof/inclusion`, `/v1/proof/consistency`, `/v1/public-key`,
`/v1/cosignatures`, and the `/api/transparency/` read routes) also send
`Access-Control-Allow-Origin: *`, including on the server's own 503, 414 and 500
responses to them, so a browser-based verifier on any origin can read them. They
serve public data and take no credentials. The write routes and `/healthz` are
same-origin only.

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
`timestamp` is in the form of `Date.prototype.toISOString` and never decreases. The log checks every
signature it makes under the strict Ed25519 profile of VAOS 2.0 §7.3, by which
the verifiable-receipts witness CLI checks tree heads.

## Limits

| Limit | Value |
| --- | --- |
| Receipt body (`POST /v1/entries`) | `-max-entry-bytes`, default 1 MiB (413 above it) |
| Receipt nesting (`POST /v1/entries`) | 64 levels in the receipt (400 above it) and 64 in the text of its `canonical` (422 above it) |
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

A `contentHash` that is absent or `null` is not checked. Any other value must
be a string equal to `sha256:` + the hex SHA-256 of `canonical` (the prefix is
optional), so `""` is refused with 422. A log run by an older build may
hold receipts admitted before this rule; `receipts-log check -issuer-key` lists
them (see the README).

Nesting is limited to 64 levels (VAOS 2.0 §7.2). The receipt object is one
level and each array or object inside it one more; the depth is counted on the
body's text before it is decoded, so a key given twice counts in both places,
though a decoder keeps only the last. A deeper receipt is refused with 400 and
`receipt nesting deeper than 64` in `error`, at any depth. The text of
`canonical` is held to the same limit after its signature is checked: a deeper
one is refused with 422 and `canonical nesting deeper than 64`.

The two get different statuses because they fail at different steps. The
receipt's depth is a property of the request text: the log reads the body with
`ParseReceipt`, which refuses it before any key is tried, so the request is
malformed (400), like a body that is not JSON. The canonical is a string
inside a well-formed receipt; its depth is checked by the verifier after the
signature, so a deep canonical is a verification outcome (422), like a
signature that does not verify.

The signature is checked under the strict Ed25519 profile of VAOS 2.0 §7.3:
before `crypto/ed25519` checks the equation, the signature's R must be a
canonical encoding of a point of order L (not of small order, the identity
included, and not of mixed order) and its S below L. The issuer keys
themselves are checked when the log starts: it refuses an Ed25519 key that is
not a canonical encoding of a point of order L (of small order, non-canonical,
off the curve or of mixed order). Under a small-order key one signature can
verify every receipt; under a mixed-order key verifiers disagree.

| Status | Meaning |
| --- | --- |
| 201 | Appended |
| 200 | Already logged (same `canonical`); the first entry logged for that `canonical` is returned, and its `contentHash` may differ from the submitted one |
| 400 | Not a JSON object, no `canonical` (a `canonical` that is not a string counts as none), or nested deeper than 64 |
| 413 | Body too large |
| 415 | Content type other than `application/json` |
| 422 | The receipt does not verify under any issuer key (the reason is in `error`) |
| 503 | The log is read-only after a storage failure, holds 2^53 − 1 entries, or is busy |

```json
{"index": 0, "leafHash": "<hex>", "duplicate": false, "sth": { <STH as above> }}
```

A 422 `error` is `receipt signature does not verify under any configured
issuer key: ` followed by the first key's reason, which is the
verifiable-receipts verifiers' reason, among them:

| Reason | The receipt |
| --- | --- |
| `missing signature` | has no `signature`, or one that is not a string |
| `signature is not v2 (expected 'v2=<base64>')` | has a signature without the `v2=` prefix |
| `signature base64 invalid` | has a signature that is not padded standard base64 (CR and LF included) |
| `signature base64 invalid: not canonical` | has a signature that decodes but re-encodes differently |
| `contentHash must be a string` | has a `contentHash` that is neither a string nor `null` |
| `contentHash mismatch with canonical bytes` | has a `contentHash` string that is not the canonical's hash |
| `signature R is not a canonical encoding` | has a signature whose R encodes a y of p or more |
| `signature R is not a point on the curve` | has a signature whose R has no x on the curve |
| `signature R is a small-order point` | has a signature whose R is of small order, the identity included |
| `signature R is not in the prime-order subgroup` | has a signature whose R is of mixed order |
| `signature does not verify under the supplied public key` | is not signed by the key, or has a signature whose S is L or more |
| `canonical nesting deeper than 64` | has a `canonical` whose text nests deeper than 64 |

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
the signature verifies under that witness's key (under the strict Ed25519
profile of VAOS 2.0 §7.3, as for receipts), `sthCanonical` is in canonical
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
| 422 | The witness signature does not verify; `error` is `witness signature does not verify: ` and the reason, one of the signature reasons of `POST /v1/entries` or `signature is not v2`, `signature is not base64 of 64 bytes`, `signature is not canonical base64` |
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
