# internal/vaos

`verify.go`, `transparency.go` and `edwards25519.go` are copies of the Go
verifier in
[verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts)
(`packages/verifiable-receipts-go`, commit `4d9943a99376527f742dcfdf93652ed040a51b43`),
licensed Apache-2.0, and `contenthash_test.go`, `nesting_test.go`,
`key_test.go`, `edwards25519_test.go` and `strict_ed25519_test.go` are copies
of its tests from the same commit. The only change is
a provenance notice at the top of each file. `fixtures_test.go` gives the
copied tests what they expect from the rest of that package's tests (the
fixture paths, here this repository's copies, a fixture's expected verdict
and two key helpers).

`VerifyV2Receipt` gives every signature one valid string form: the text
must have the shape of padded standard base64, which refuses CR and LF that
Go's decoder otherwise skips, and the decoded bytes must re-encode to the
exact text, which refuses non-zero padding bits. The fixtures
`v2-invalid-noncanonical-base64.json` and `v2-invalid-crlf-base64.json` are
copied into `testdata/conformance/fixtures/`, and the log's admission tests
run every `v2-*.json` fixture. Its `VerifyInclusionProof` takes only
64-lowercase-hex hashes (transparency-log spec §3.6), the rule
`internal/merkle.ParseHash` also applies, and the `inclusion-*.json`
fixtures cover it.

`VerifyV2Receipt` also checks a `contentHash` that is present
as a string, even `""`, against the canonical's hash; an absent or `null`
`contentHash` is not checked. `Receipt.UnmarshalJSON` records which it read,
so the log must pass the parsed `Receipt` itself to the verifier, not one
built by hand. The fixtures `v2-invalid-empty-contenthash.json` and
`v2-valid-null-contenthash.json` cover it, and `contenthash_test.go`, copied
from the same commit with the same notice, checks the rule through a JSON
round trip.

The verifier limits nesting to 64 levels (VAOS 2.0 §7.2). `VerifyV2Receipt`
and `VerifyGuardianAttestation` reject a receipt nested deeper (the receipt
object is one level) before anything else, and a `Canonical` whose text nests
deeper after the signature check; `jsonEqual` recurses at most 64 deep.
`ParseReceipt` reads a receipt from text and counts the depth on the text
before `encoding/json` sees it, so it refuses a deep receipt with `vaos:
receipt nesting deeper than 64` at any depth, a duplicate key the decoder
discards included; `Receipt.UnmarshalJSON` counts first too. The log reads
every submitted body with `ParseReceipt` (`internal/translog`). `UnmarshalJSON`
no longer fails on a `canonical`, `signature` or `contentHash` that is not a
string: `VerifyV2Receipt` rejects it (`missing canonical projection`, `missing
signature`, `contentHash must be a string`). The signature's base64 reasons are
now `signature base64 invalid` and `signature base64 invalid: not canonical`.
The fixtures `v2-invalid-deep-nesting.json`, `v2-invalid-nesting-at-limit.json`
and `v2-invalid-duplicate-deep-key.json` (a `receiptText` fixture: the receipt
as text) cover it.

It also refuses an Ed25519 public key that is a point of small order
or a non-canonical encoding (VAOS 2.0 §7.3), in `LoadEd25519PublicKeyFromPEM`
and in `VerifyV2Receipt`. `internal/keys.CheckPublicKey` applies the same rule
through `LoadEd25519PublicKeyFromPEM`, so the log refuses such an issuer or
witness key when it loads it and when it opens. The fixtures
`v2-invalid-small-order-key.json` and `v2-invalid-noncanonical-key.json` carry
their own key (`publicKeyPem`); the admission test opens a log with it.

The log server uses `VerifyV2Receipt` and `VerifyGuardianAttestation` to admit
receipts, so admission follows the published verifier's rules. The tests use
`VerifyInclusionProof` as an independent check on the proofs this log serves.
`interop/interop_test.go` compares these files and the fixtures with a
checkout of verifiable-receipts.

Since f41348e every Ed25519 signature is checked under the strict profile of
VAOS 2.0 §7.3 (amended 30 October 2026). Before `crypto/ed25519` sees it, the
key must be a canonical encoding of a point of order L (not of small order,
off the curve or of mixed order), the signature's R one too (the identity
included among the points of small order), and its S below L. Each refusal
has its reason: `public key is not a point on the curve`, `public key is not
in the prime-order subgroup`, `signature R is not a canonical encoding`,
`signature R is not a point on the curve`, `signature R is a small-order
point` and `signature R is not in the prime-order subgroup`, besides the
earlier key reasons and `signature does not verify under the supplied public
key` (S of L or more included). `edwards25519.go` does the point arithmetic
with `math/big`. `VerifyV2Receipt` applies the profile, and `VerifyEd25519`
checks one raw signature with it: `internal/sth.VerifyBytes` uses it for tree
heads and cosignatures, and `sth.SignBytes` checks each signature it makes
with it. `LoadEd25519PublicKeyFromPEM`, and so `internal/keys.CheckPublicKey`,
refuse the new keys too. The fixtures `ed25519-*.json` are copied into
`testdata/conformance/fixtures/`: the admission tests run those given as
receipts, and `internal/sth` runs all of them through `VerifyBytes`.

Since 4d9943a the two pre-checks of `VerifyEd25519` are exported:
`Ed25519PublicKeyProblem(pub)` (the key, cached per key; a key that is not 32
bytes gets `public key is not 32 bytes`) and `Ed25519SignatureProblem(sig)`
(R and S), each returning the reason or `""`, in the same order and with the
same reasons as before. The log's admission (`verifyIssued` in
`internal/translog`) uses them so that the checks that depend only on the
signature run once per receipt, not once per issuer key.
