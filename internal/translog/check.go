package translog

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/store"
)

// CheckReport is the outcome of Check.
type CheckReport struct {
	Entries        uint64 `json:"entries"`
	CheckpointSize uint64 `json:"checkpointSize"`
	RootHash       string `json:"rootHash"`
	Timestamp      string `json:"timestamp"`
	TornTailBytes  int64  `json:"tornTailBytes"`

	// The fields below are set only when Check is given issuer keys.

	// IssuerKeys is the number of issuer keys the receipts were
	// verified under.
	IssuerKeys int `json:"issuerKeys,omitempty"`
	// NonconformingCount is the number of stored receipts that
	// admission would refuse today.
	NonconformingCount uint64 `json:"nonconformingCount,omitempty"`
	// Nonconforming lists the first of them, in index order, up to
	// NonconformingLimit.
	Nonconforming []Nonconforming `json:"nonconforming,omitempty"`
}

// Nonconforming is a stored receipt that the current admission rules
// refuse. Reason is the error Append returns for it, which the server
// sends with HTTP 422.
type Nonconforming struct {
	Index    uint64 `json:"index"`
	LeafHash string `json:"leafHash"`
	Reason   string `json:"reason"`
}

// NonconformingLimit is the most entries CheckReport.Nonconforming
// lists. The report is one JSON document; a cap keeps it, and Check's
// memory, bounded on a log of up to 2^53 - 1 entries, while
// NonconformingCount still counts them all.
const NonconformingLimit = 1000

// nonconformingLimit is NonconformingLimit; tests lower it.
var nonconformingLimit = NonconformingLimit

// Check verifies a data directory without modifying it, as Open does:
// every entry's checksum and leaf hash, and the checkpoint's signature
// (under pub), log ID and root. A damaged tail past the checkpoint is
// reported, not repaired; the server truncates it when it next opens the
// directory.
//
// With issuer keys, Check also verifies every stored receipt (those
// past the checkpoint too) as Append does, and reports those that do not verify under any of the keys in
// the report's Nonconforming fields. Such entries are not an integrity
// error: they were admitted under older rules, and the log keeps them.
// An integrity error is returned as without issuer keys.
func Check(dir, logID string, pub ed25519.PublicKey, issuerKeys ...ed25519.PublicKey) (CheckReport, error) {
	var rep CheckReport
	if err := validateIssuerKeys(issuerKeys); err != nil {
		return rep, err
	}
	data, err := store.ReadCheckpoint(dir)
	if err != nil {
		return rep, err
	}
	if data == nil {
		return rep, fmt.Errorf("%w: %s has no %s", store.ErrCorrupt, dir, store.CheckpointFile)
	}
	ck, err := parseCheckpoint(data, pub, logID)
	if err != nil {
		return rep, err
	}
	f, err := os.Open(filepath.Join(dir, store.EntriesFile))
	if err != nil {
		return rep, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return rep, err
	}
	var tree merkle.Tree
	var bad []Nonconforming
	var badCount uint64
	res, err := store.Scan(f, st.Size(), store.HardMaxPayload, ck.TreeSize, func(i uint64, leaf merkle.Hash, payload []byte) error {
		if err := checkEntry(leaf, payload); err != nil {
			return err
		}
		tree.Append(leaf)
		if len(issuerKeys) > 0 {
			if _, _, err := verifyReceipt(payload, issuerKeys); err != nil {
				badCount++
				if len(bad) < nonconformingLimit {
					bad = append(bad,
						Nonconforming{Index: i, LeafHash: leaf.String(), Reason: err.Error()})
				}
			}
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	rep.Entries = tree.Size()
	rep.CheckpointSize = ck.TreeSize
	rep.RootHash = ck.RootHash
	rep.Timestamp = ck.Timestamp
	rep.IssuerKeys = len(issuerKeys)
	rep.NonconformingCount = badCount
	rep.Nonconforming = bad
	if res.TornAt >= 0 {
		rep.TornTailBytes = st.Size() - res.TornAt
	}
	return rep, checkCheckpointRoot(ck, &tree)
}
