# internal/vaos

`verify.go` and `transparency.go` are copies of the Go verifier in
[verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
(`packages/verifiable-receipts-go`, commit `a5637ee5feeb6ef241b99479922f123ea761b5d3`),
licensed Apache-2.0. The only change is a provenance notice at the top of
each file.

That commit's `VerifyV2Receipt` gives every signature one valid string form:
it decodes the base64 strictly (non-zero padding bits are refused) and checks
that the decoded bytes re-encode to the exact text, which refuses CR and LF
that Go's decoder otherwise skips. The fixtures
`v2-invalid-noncanonical-base64.json` and `v2-invalid-crlf-base64.json` are
copied into `testdata/conformance/fixtures/`, and the log's admission tests
run every `v2-*.json` fixture.

The log server uses `VerifyV2Receipt` and `VerifyGuardianAttestation` to admit
receipts, so admission follows the published verifier's rules. The tests use
`VerifyInclusionProof` as an independent check on the proofs this log serves.
`interop/interop_test.go` compares these files and the fixtures with a
checkout of verifiable-receipts.
