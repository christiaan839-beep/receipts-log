# Changelog

Notable changes to receipts-log. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

To be released as v0.2.0. v0.1.0 was tagged but never released, so v0.2.0 is
the first release; it includes everything listed under 0.1.0.

### Security

- Every Ed25519 signature the log or the witness checks, of a receipt, a tree
  head or a cosignature, is checked under the strict profile of VAOS 2.0 §7.3
  (amended 30 October 2026), by the verifiable-receipts Go verifier now copied
  into `internal/vaos` at verifiable-receipts 4d9943a (`VerifyEd25519`, with
  `math/big` point arithmetic in `edwards25519.go`, and its pre-checks
  `Ed25519PublicKeyProblem` and `Ed25519SignatureProblem`). Before `crypto/ed25519`
  sees a signature, the key and the signature's R must be canonical encodings
  of points of order L and S must be below L. 0.1.0 admitted a receipt whose R
  is the identity (S = k·a under an ordinary key), which Node.js 24.22 and 26
  refuse, and accepted issuer and witness keys of mixed order, under which
  verifiers disagree. New reasons in the 422 `error` of `POST /v1/entries`:
  `signature R is not a canonical encoding`, `signature R is not a point on
  the curve`, `signature R is a small-order point`, `signature R is not in the
  prime-order subgroup`.
- Issuer, witness and log public keys that are off the curve (`public key is
  not a point on the curve`) or of mixed order (`public key is not in the
  prime-order subgroup`) are refused when they are loaded, as keys of small
  order already were: `serve`, `witness`, `check`, `prove` and `sth` exit 2.
  `translog.Open` also refuses a log signing key whose public half does not
  match its seed.
- `sth.Sign` and the witness sign through the new `sth.SignBytes`, which checks
  each signature under the strict profile before returning it, so no tree head
  or cosignature is published that a strict verifier rejects.
- Admission checks a receipt's R and S once, not once per issuer key and again
  for the Guardian attestation view: refusing a forged signature (about 150
  bytes, no key needed) costs about one subgroup check, 0.89 ms with 8 issuer
  keys instead of 11.3 ms (0.70 ms instead of 1.4 ms with one; Apple M4). Each key then
  costs one `crypto/ed25519` check, and `VerifyGuardianAttestation` runs only
  under a key the signature verifies under, and only for a receipt with
  `rules` or `totalMs`. The reason a client gets is the same as before with
  one issuer key, for every input.
- A stored cosignature is served only as evidence of this log. When the
  server opens a data directory it skips, with a warning, a record whose
  `sthCanonical` is not a head of this log (another log, a fork, a size never
  reached) or whose `treeSize`, `rootHash` or `timestamp` differ from that
  head, and still opens. `GET /v1/cosignatures?treeSize=` selects by the size
  the signed `sthCanonical` names, not the record's own field: before, a
  record could be served under a size its signature does not cover.
  `check -witness-key` now applies every rule of `POST /v1/cosignatures` to
  stored records, the tree-head check included, and reports a record whose
  fields disagree with its head as `cosignature record disagrees with its
  signed tree head`.
- `API.md` "Limits" gives the verification cost of each request and
  recommends a per-client rate limit in a reverse proxy in front of a public
  log.

### Changed

- A refused cosignature's 422 `error` now carries the reason:
  `witness signature does not verify: <reason>`.
- A store written by an older build still opens and serves; `check
  -issuer-key` lists the receipts the strict profile refuses as nonconforming
  (exit 3), with these reasons (README, "After upgrading").
- With several issuer keys, the 422 `error` of `POST /v1/entries` (and a
  reason in `check -issuer-key`) is chosen as verify-receipts-action chooses
  it: a reason about the receipt itself first, then one about R, then
  `signature does not verify under any of the N issuer keys`. It was the first
  key's reason. With one key it is unchanged.
- `POST /v1/cosignatures` checks that the tree head is this log's (409) before
  the signature (422), so a foreign head no longer costs a subgroup check; a
  foreign head with a bad signature now gets 409.
- `serve` and `check` refuse a `-witness-key` NAME given twice (exit 2).

### Added

- `check -witness-key NAME=FILE` (repeatable, as for `serve`) verifies every
  stored cosignature under its witness's key, as the server checks one
  submitted today, and lists those it refuses in `nonconformingCosignatures`
  (with `witnessKeys`, `cosignatures` and `nonconformingCosignatureCount`);
  exit 4 when only cosignatures fail. The server loads stored cosignatures
  without verifying them, so a cosignature an older build recorded with an R
  that is the identity is still served; `check` now reports it.

## [0.1.0] — 2026-10-30

Tagged, never released; its changes ship in 0.2.0.

The first release: a transparency log and witness for verifiable receipts, in
Go with the standard library only.

### Added

- `receipts-log serve`: admits a receipt only when its Ed25519 `v2=` signature
  verifies under a configured issuer key, as a VAOS 2.0 receipt or a Guardian
  attestation, by the rules of the verifiable-receipts Go verifier (copied into
  `internal/vaos`, at verifiable-receipts 24f5c47).
- Each receipt is one leaf, `SHA-256(0x00 || canonical)`, of an RFC 6962 /
  RFC 9162 Merkle tree. The server returns entries, Ed25519-signed tree heads,
  inclusion proofs and consistency proofs (`API.md`), and records cosignatures
  from configured witnesses. Read routes allow any origin, for browser
  verifiers.
- An append-only, checksummed store, fsynced before each acknowledgement and
  checked against the signed checkpoint every time it opens.
- `receipts-log witness`: fetches the latest tree head, checks its signature
  and its consistency with the last head it signed, cosigns it and submits the
  cosignature.
- `receipts-log check` checks a store offline, and optionally re-verifies every
  stored receipt; `keygen`, `pubkey`, `append`, `prove`, `sth` and `version`
  cover the rest of the command line.
- Release archives for Linux and macOS (amd64, arm64) with `SHA256SUMS`, a
  container image at `ghcr.io/christiaan839-beep/receipts-log`, and signed
  build provenance for both (`RELEASING.md`).
