# internal/vaos

`verify.go` and `transparency.go` are copies of the Go verifier in
[verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
(`packages/verifiable-receipts-go`, commit `03b38ee2d28080a2a4aa0810dbb1dfcd447379fd`),
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

The log server uses `VerifyV2Receipt` and `VerifyGuardianAttestation` to admit
receipts, so admission follows the published verifier's rules. The tests use
`VerifyInclusionProof` as an independent check on the proofs this log serves.
`interop/interop_test.go` compares these files and the fixtures with a
checkout of verifiable-receipts.
