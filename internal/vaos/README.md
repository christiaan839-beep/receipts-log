# internal/vaos

`verify.go` and `transparency.go` are copies of the Go verifier in
[verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
(`packages/verifiable-receipts-go`, commit `fd2390b5cd30fb3c31c41810195ab7ec5ed51702`),
licensed Apache-2.0. The only change is a provenance notice at the top of
each file.

That commit's `VerifyV2Receipt` gives every signature one valid string form:
it decodes the base64 strictly (non-zero padding bits are refused) and checks
that the decoded bytes re-encode to the exact text, which refuses CR and LF
that Go's decoder otherwise skips. The fixtures
`v2-invalid-noncanonical-base64.json` and `v2-invalid-crlf-base64.json` are
copied into `testdata/conformance/fixtures/`, and the log's admission tests
run every `v2-*.json` fixture. Its `VerifyInclusionProof` takes only
64-lowercase-hex hashes (transparency-log spec §3.6), the rule
`internal/merkle.ParseHash` also applies, and the `inclusion-*.json`
fixtures cover it.

That commit's `VerifyV2Receipt` also checks a `contentHash` that is present
as a string, even `""`, against the canonical's hash; an absent or `null`
`contentHash` is not checked. `Receipt.UnmarshalJSON` records which it read,
so the log must pass the parsed `Receipt` itself to the verifier, not one
built by hand. The fixtures `v2-invalid-empty-contenthash.json` and
`v2-valid-null-contenthash.json` cover it, and `contenthash_test.go`, copied
from the same commit with the same notice, checks the rule through a JSON
round trip; `fixtures_test.go` points it at this repository's fixtures.

The log server uses `VerifyV2Receipt` and `VerifyGuardianAttestation` to admit
receipts, so admission follows the published verifier's rules. The tests use
`VerifyInclusionProof` as an independent check on the proofs this log serves.
`interop/interop_test.go` compares these files and the fixtures with a
checkout of verifiable-receipts.
