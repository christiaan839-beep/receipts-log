# receipts-log

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/christiaan839-beep/receipts-log/badge)](https://scorecard.dev/viewer/?uri=github.com/christiaan839-beep/receipts-log)

receipts-log is a transparency-log server and witness for receipts in the
[verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
format. It is written in Go with the standard library only.

## Why

A signed receipt proves that an issuer signed some bytes. It does not prove
that the issuer published the receipt, or that the issuer shows every party the
same history. A transparency log closes that gap: each receipt becomes a leaf in
an append-only Merkle tree, the log signs its tree heads, and independent
witnesses cosign a tree head only after checking that it extends the last one
they signed. A log that drops, rewrites or forks history then fails a
consistency proof that any witness or auditor can check.

## What it does

- Admits a receipt only when its Ed25519 `v2=` signature verifies under a
  configured issuer key, as a VAOS 2.0 receipt or as a Guardian attestation,
  by the rules of the verifiable-receipts Go verifier (copied into
  `internal/vaos`).
- Logs each receipt under `SHA-256(0x00 || canonical)`, the leaf hash of the
  verifiable-receipts transparency-log spec; a receipt submitted twice is one
  entry.
- Builds the RFC 6962 / RFC 9162 Merkle tree, and serves entries, signed tree
  heads, inclusion proofs and consistency proofs.
- Signs tree heads with an Ed25519 log key in the verifiable-receipts STH format
  (`v2=` signature over the `JSON.stringify` canonical string).
- Stores entries in an append-only, checksummed file that is fsynced before
  each acknowledgement, and verifies the whole store against the signed
  checkpoint every time it opens.
- Records witness cosignatures from configured witnesses.
- Includes a witness (`receipts-log witness`) that fetches the latest tree head,
  checks its signature and its consistency with the last head it signed,
  cosigns it and submits the cosignature.

## Interoperability

The formats match verifiable-receipts byte for byte. `interop/interop_test.go`
checks this against a checkout of that repository:

- receipts signed by its Python signer are admitted;
- every inclusion proof this server serves verifies with its TypeScript, Python
  and Go verifiers, and every consistency proof with its TypeScript verifier
  (the Python and Go packages have no consistency verifier); tampered proofs
  fail in each;
- its TypeScript `treeRoot`, `inclusionProof` and `consistencyProof` produce
  the same roots and proofs as this server from the same leaves, and this
  repository's verifiers accept them;
- its `canonicalizeSth` produces the same canonical string, including for log
  IDs with quotes, control characters, U+2028 and non-ASCII text, and node's
  Ed25519 verifies this server's tree-head signatures;
- its witness CLI (`bin/witness.mjs`), given this log's ID and public key,
  accepts this server's tree heads (no field beyond those the signature
  covers, and SHA-256 of no bytes as the empty tree's root), witnesses them,
  accepts its consistency proofs, refuses another log ID and exits 1 on a
  fork;
- this repository's witness witnesses a log built on its TypeScript
  `TransparencyLog` and detects a fork of it;
- the conformance fixtures in `testdata/conformance` and the verifier copy in
  `internal/vaos` match the checkout.

Run it with node 22.6 or later, python3 with `cryptography`, and a checkout:

```sh
make interop VERIFIABLE_RECEIPTS_DIR=../verifiable-receipts
```

## Run

Build and create keys. Keys are generated locally and never committed; the
private key file is written with mode 0600 and never overwritten.

```sh
make build
dist/receipts-log keygen -out log.key -pub log.pub
```

The issuer's public key is its `ed25519.pem` (served at
`/.well-known/sovereign-receipts/ed25519.pem`). Start the log:

```sh
dist/receipts-log serve \
  -data ./data -log-id example-log -log-key log.key \
  -issuer-key issuer.pem -witness-key w1=w1.pub -addr :8080
```

Every command refuses a public key file (issuer, witness or log key) that holds
an Ed25519 point of small order or a non-canonical encoding (VAOS 2.0 §7.3):
under the identity key, for one, a single signature verifies every message.

The `serve` flags that name files, identifiers, the address and the log level
also read environment variables (`RECEIPTS_LOG_DATA`, `RECEIPTS_LOG_ID`,
`RECEIPTS_LOG_KEY_FILE`, `RECEIPTS_LOG_ISSUER_KEYS`,
`RECEIPTS_LOG_WITNESS_KEYS`, `RECEIPTS_LOG_ADDR`, …); `receipts-log serve -h`
names each one. `-max-entry-bytes`, `-max-in-flight` and `-sth-interval` are
flags only. Logs are JSON lines on stderr, one per request plus lifecycle
events. `-tls-cert` and `-tls-key` serve HTTPS directly; otherwise put the
server behind a TLS-terminating proxy.

Client commands:

```sh
dist/receipts-log append -url http://localhost:8080 -file receipt.json
dist/receipts-log sth    -url http://localhost:8080 -log-public-key log.pub
dist/receipts-log prove  -url http://localhost:8080 -file receipt.json -log-public-key log.pub
dist/receipts-log check  -data ./data -log-id example-log -log-public-key log.pub \
  [-issuer-key issuer.pem]
```

`prove` fetches the signed tree head, checks its signature, fetches the
inclusion proof for the receipt's leaf and verifies it. `check` verifies a data
directory offline without changing it: every record's checksum and leaf hash,
and the checkpoint's signature, log ID and root. With `-issuer-key` (repeatable,
the same files as `serve`) it also verifies every stored receipt, including any
past the checkpoint, exactly as the server admits receipts now (the entry size
limit apart). `check` takes issuer keys only from `-issuer-key`; it ignores
`RECEIPTS_LOG_ISSUER_KEYS`. With `-issuer-key` the report always has
`issuerKeys` and `nonconformingCount` (0 when every receipt passes), and has
`nonconforming` when the count is not 0: the index, leaf hash and refusal
reason of each, the first 1000 in index order, with `"pastCheckpoint": true` on
an entry no signed checkpoint covers yet. Without `-issuer-key` none of these
fields appears. Exit codes: 0 intact (and, with
`-issuer-key`, every receipt passes), 1 the store is corrupt or the checkpoint
does not verify (reported first, whatever the receipts), 2 usage or
configuration error, 3 the store is intact but holds receipts that admission
now refuses.

**After upgrading**, run `check -issuer-key …` against each data directory, with
the issuer keys the server is configured with. The log is append-only, so a
receipt admitted under older rules stays in it; the server still opens and
serves such a store. For example, receipts-log builds before the sync with
verifiable-receipts fd2390b admitted a receipt whose `contentHash` is `""`;
`check` reports it with the reason `receipt signature does not verify under any
configured issuer key: contentHash mismatch with canonical bytes`. Builds
before the sync with verifiable-receipts 24f5c47 admitted receipts nested
deeper than 64 levels, counted on the text, which `check` reports with the
reason `receipt is not a valid receipt object: vaos: receipt nesting deeper
than 64`, or `receipt signature does not verify under any configured issuer
key: canonical nesting deeper than 64` when only its canonical is that deep.
A receipt that verifies under none of the keys given (for instance an issuer
key you no longer configure) is reported too, with the reason a submission of
it gets today, the 422 `error` of `POST /v1/entries`.

Run a witness, once or as a daemon (default interval one hour):

```sh
dist/receipts-log keygen -out w1.key -pub w1.pub
dist/receipts-log witness -url http://localhost:8080 -key w1.key -witness-id w1 \
  -log-public-key log.pub -once -json
```

The witness keeps its state in `~/.sovereign-witness/<witness-id>.json` (as the
verifiable-receipts witness does) or in `-state`. Exit codes: 0 witnessed or no
change, 1 fork detected (the daemon stops; investigate before doing anything
else), 2 usage, configuration or network error. An unreadable state file is an
error, not a first run.

### Container

```sh
make docker
docker run -p 8080:8080 -v receipts-data:/data \
  -v "$PWD/keys:/keys:ro" \
  -e RECEIPTS_LOG_ID=example-log -e RECEIPTS_LOG_KEY_FILE=/keys/log.key \
  -e RECEIPTS_LOG_ISSUER_KEYS=/keys/issuer.pem \
  receipts-log:dev
```

The image is distroless (`gcr.io/distroless/static-debian12:nonroot`), runs as
uid 65532 and keeps its data in the `/data` volume. Mount the log key read-only
from a secret store; it must be readable by uid 65532.

## API

`API.md` documents every route. In brief:

| Route | Purpose |
| --- | --- |
| `POST /v1/entries` | Submit a receipt |
| `GET /v1/entries/{index}` | Read an entry |
| `GET /v1/sth` | Latest signed tree head |
| `GET /v1/proof/inclusion?index=…\|leafHash=…[&treeSize=…]` | Inclusion proof |
| `GET /v1/proof/consistency?old=…[&new=…]` | Consistency proof |
| `GET /v1/public-key` | Log public key (PEM) |
| `POST /v1/cosignatures`, `GET /v1/cosignatures?treeSize=…` | Witness cosignatures |
| `GET /api/transparency/sth`, `/proof`, `POST /witness` | Routes the verifiable-receipts witness CLI uses |
| `GET /healthz` | Liveness and read-only state |

## Storage

The data directory holds `entries.dat` (append-only records: length, leaf hash,
receipt JSON, CRC-32C), `checkpoint.json` (the latest signed tree head,
replaced atomically), `cosignatures.jsonl` and a `LOCK` file (an exclusive
`flock`, so two processes cannot open one directory).

An append writes one record with `O_APPEND`, fsyncs it, signs a new tree head,
writes it to `checkpoint.json` (temporary file, fsync, rename, directory
fsync), and only then answers the client. Every acknowledged entry is therefore
inside the checkpoint. On open the server reads every record, checks its CRC
and that its leaf hash matches its receipt, rebuilds the tree, and checks the
checkpoint's signature, log ID and root against it. A damaged record past the
checkpoint is an append that was never acknowledged; it is truncated and logged.
Any other damage, a missing checkpoint, or a checkpoint signed by another key
stops the server. After a failed write or fsync the server turns read-only and
must be restarted, which re-verifies the store.

## Security model

- **Trust.** Clients trust the log's public key, obtained out of band. They do
  not need to trust the log operator: a signed tree head commits the operator to
  a history, and consistency proofs show whether later heads extend it.
- **Witnesses** detect a log that rewrites or forks history after they have
  seen a tree head. Detection of a split view needs witnesses (or clients) to
  compare the heads they see; this project records cosignatures but does not
  gossip.
- **Admission.** Only receipts that verify under a configured issuer key enter
  the log, so the log cannot be filled with unsigned data. The leaf commits to
  the receipt's `canonical` string; envelope fields outside it are stored but
  are not covered by the tree.
- **Keys.** The log key signs only tree heads. The server warns when the key
  file is readable by group or others. No key or secret is in this repository;
  tests generate keys at run time.
- **Input handling.** Request bodies, headers and query strings are size
  limited; requests have header, read, write and idle timeouts; concurrency is
  bounded; handler panics are contained and logged. The decoders for stored
  records, receipts, tree heads, proofs, keys and HTTP requests are fuzzed.
- **Integrity at rest.** CRCs catch accidental corruption. Deliberate tampering
  with the data directory is caught on open by the signed checkpoint, and after
  that by witnesses.

## Limits

- Receipts must carry `v2=` (Ed25519) signatures. `v3=` (Ed25519 + ML-DSA-65)
  receipts are refused, since verifying ML-DSA-65 needs a library outside the
  Go standard library. Tree heads are signed `v2=` only.
- The tree (two hashes per entry), a leaf-hash index and the entry offsets are
  held in memory, and opening reads the whole entries file, so memory use and
  start-up time grow with the log.
- Appends are serialised and each costs three fsyncs (the entry, the new
  checkpoint and its directory), so append throughput is bounded by the disk's
  fsync latency.
- Tree sizes stop at 2^53 − 1 so the TypeScript verifier can reproduce every
  canonical string.
- There is no rate limiting per client, no authentication on submission (the
  issuer signature is the admission control), and no gossip between witnesses.
- Entries are stored as submitted, re-encoded as compact JSON, and served to
  anyone. The issuer must not submit receipts whose `canonical` holds personal
  data that may not be published.

## Development

```sh
make check     # gofmt, go vet, staticcheck, tests with the race detector
make fuzz      # every fuzz target for FUZZTIME (default 15s) each
make interop   # cross-checks against a verifiable-receipts checkout
```

CI (`.github/workflows/ci.yml`) runs gofmt, go vet, the race-enabled tests and
the build on Go 1.22 (the `go.mod` minimum), 1.26 and 1.27; staticcheck on
1.26; every fuzz target for 10 s on 1.27; the interop tests against a pinned
verifiable-receipts commit; and a container build. Its actions are pinned to
commit SHAs and its token is read-only.

## Licence

Apache-2.0, the licence of verifiable-receipts; see `LICENSE`. The files in
`internal/vaos` and `testdata/conformance` are copied from verifiable-receipts
under the same licence; `internal/vaos/README.md` lists the changes.
