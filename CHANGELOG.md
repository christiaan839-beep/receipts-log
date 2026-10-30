# Changelog

Notable changes to receipts-log. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-30

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
