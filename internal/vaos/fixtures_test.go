package vaos

// The fixture paths and type that contenthash_test.go, copied from
// verifiable-receipts, expects. There they come from its
// conformance_test.go; here they name this repository's copies.

const fixturesDir = "../../testdata/conformance/fixtures"
const publicKeyPath = "../../testdata/conformance/public-key.pem"

type v2Fixture struct {
	Receipt Receipt `json:"receipt"`
}
