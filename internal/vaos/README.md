# internal/vaos

`verify.go` and `transparency.go` are copies of the Go verifier in
[verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
(`packages/verifiable-receipts-go`, commit `55d30b72b277a025e7a20e0952aa5813241ba38f`),
licensed Apache-2.0.

Changes from that commit:

- a provenance notice at the top of each file;
- `VerifyV2Receipt` decodes the signature's base64 strictly
  (`base64.StdEncoding.Strict()`), so a signature with non-zero padding bits
  is refused and every signature has one valid string form. The
  verifiable-receipts working tree carries the same change and the fixture
  `v2-invalid-noncanonical-base64.json`, which is copied into
  `testdata/conformance/fixtures/`.

The log server uses `VerifyV2Receipt` and `VerifyGuardianAttestation` to admit
receipts, so admission follows the published verifier's rules. The tests use
`VerifyInclusionProof` as an independent check on the proofs this log serves.
`interop/interop_test.go` compares these files and the fixtures with a
checkout of verifiable-receipts.
