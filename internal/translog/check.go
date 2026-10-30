package translog

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
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
	// admission would refuse today. It is non-nil, 0 included, exactly
	// when Check was given issuer keys, so a script can read it.
	NonconformingCount *uint64 `json:"nonconformingCount,omitempty"`
	// Nonconforming lists the first of them, in index order, up to the
	// limit in CheckOptions.
	Nonconforming []Nonconforming `json:"nonconforming,omitempty"`

	// The fields below are set only when Check is given witness keys.

	// WitnessKeys is the number of witness keys the stored cosignatures
	// were verified under.
	WitnessKeys int `json:"witnessKeys,omitempty"`
	// Cosignatures is the number of stored cosignatures.
	Cosignatures uint64 `json:"cosignatures,omitempty"`
	// NonconformingCosignatureCount is the number of stored cosignatures
	// that the log would refuse today. It is non-nil, 0 included,
	// exactly when Check was given witness keys.
	NonconformingCosignatureCount *uint64 `json:"nonconformingCosignatureCount,omitempty"`
	// NonconformingCosignatures lists the first of them, in file order,
	// up to the limit in CheckOptions.
	NonconformingCosignatures []NonconformingCosignature `json:"nonconformingCosignatures,omitempty"`
}

// Nonconforming is a stored receipt that the current admission rules
// refuse. Reason is the error Append returns for it, which the server
// sends with HTTP 422, or 400 for a receipt it cannot read (one nested
// deeper than 64, for example). PastCheckpoint marks an entry that no signed
// checkpoint covers yet (an append interrupted before its checkpoint;
// the server signs one over it when it next opens the directory).
type Nonconforming struct {
	Index          uint64 `json:"index"`
	LeafHash       string `json:"leafHash"`
	Reason         string `json:"reason"`
	PastCheckpoint bool   `json:"pastCheckpoint,omitempty"`
}

// NonconformingCosignature is a stored cosignature that the log refuses
// today. Index is its line in cosignatures.jsonl, from 0. Reason is the
// error POST /v1/cosignatures returns for it: its witness is not
// configured, or its signature does not verify under the witness's key
// (the strict profile of VAOS 2.0 section 7.3 included).
type NonconformingCosignature struct {
	Index     uint64 `json:"index"`
	WitnessID string `json:"witnessId"`
	TreeSize  uint64 `json:"treeSize"`
	Reason    string `json:"reason"`
}

// DefaultNonconformingLimit is the most entries CheckReport.Nonconforming
// lists when CheckOptions.NonconformingLimit is 0. The report is one
// JSON document; a cap keeps it, and Check's memory, bounded on a log
// of up to 2^53 - 1 entries, while NonconformingCount counts them all.
const DefaultNonconformingLimit = 1000

// CheckOptions configures Check. The zero value checks integrity only.
type CheckOptions struct {
	// IssuerKeys, when non-empty, makes Check also verify every stored
	// receipt under them, as Append does.
	IssuerKeys []ed25519.PublicKey
	// WitnessKeys, when non-empty, makes Check also verify every stored
	// cosignature under the key of its witness, as AddCosignature does.
	WitnessKeys map[string]ed25519.PublicKey
	// NonconformingLimit caps CheckReport.Nonconforming and
	// CheckReport.NonconformingCosignatures; 0 means
	// DefaultNonconformingLimit.
	NonconformingLimit int
}

// Check verifies a data directory without modifying it, as Open does:
// every entry's checksum and leaf hash, and the checkpoint's signature
// (under pub), log ID and root. A damaged tail past the checkpoint is
// reported, not repaired; the server truncates it when it next opens the
// directory.
//
// With opts.IssuerKeys, Check also verifies every stored receipt (those
// past the checkpoint too) as Append does, and reports those that do
// not verify under any of the keys in the report's Nonconforming
// fields. Such entries are not an integrity error: they were admitted
// under older rules, and the log keeps them. An integrity error is
// returned as without issuer keys.
//
// With opts.WitnessKeys, Check also verifies every stored cosignature
// with sth.VerifyBytes under the key of its witness, as AddCosignature
// does, and reports those whose witness is not among the keys or whose
// signature does not verify in the NonconformingCosignature fields. Open
// loads cosignatures without verifying them, so these too were recorded
// under older rules and are kept; a line that is not a cosignature's
// JSON is an integrity error, as for Open.
func Check(dir, logID string, pub ed25519.PublicKey,
	opts CheckOptions) (CheckReport, error) {
	var rep CheckReport
	if err := keys.CheckPublicKey(pub); err != nil {
		return rep, fmt.Errorf("translog: log key: %w", err)
	}
	issuerKeys := opts.IssuerKeys
	if err := validateIssuerKeys(issuerKeys); err != nil {
		return rep, err
	}
	if err := validateWitnessKeys(opts.WitnessKeys); err != nil {
		return rep, err
	}
	limit := opts.NonconformingLimit
	if limit <= 0 {
		limit = DefaultNonconformingLimit
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
	visit := func(i uint64, leaf merkle.Hash, payload []byte) error {
		if err := checkEntry(leaf, payload); err != nil {
			return err
		}
		tree.Append(leaf)
		if len(issuerKeys) > 0 {
			if _, _, err := verifyReceipt(payload, issuerKeys); err != nil {
				badCount++
				if len(bad) < limit {
					bad = append(bad, Nonconforming{Index: i, LeafHash: leaf.String(),
						Reason: err.Error(), PastCheckpoint: i >= ck.TreeSize})
				}
			}
		}
		return nil
	}
	res, err := store.Scan(f, st.Size(), store.HardMaxPayload, ck.TreeSize, visit)
	if err != nil {
		return rep, err
	}
	rep.Entries = tree.Size()
	rep.CheckpointSize = ck.TreeSize
	rep.RootHash = ck.RootHash
	rep.Timestamp = ck.Timestamp
	if len(issuerKeys) > 0 {
		rep.IssuerKeys = len(issuerKeys)
		rep.NonconformingCount = &badCount
		rep.Nonconforming = bad
	}
	if res.TornAt >= 0 {
		rep.TornTailBytes = st.Size() - res.TornAt
	}
	if err := checkCheckpointRoot(ck, &tree); err != nil {
		return rep, err
	}
	if len(opts.WitnessKeys) > 0 {
		if err := checkCosignatures(dir, opts.WitnessKeys, limit, &rep); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// checkCosignatures verifies the stored cosignatures for Check.
func checkCosignatures(dir string, witnesses map[string]ed25519.PublicKey, limit int, rep *CheckReport) error {
	var n, badCount uint64
	var bad []NonconformingCosignature
	err := store.ReadCosignatures(dir, func(line []byte) error {
		var c Cosignature
		if err := json.Unmarshal(line, &c); err != nil {
			return err
		}
		reason := ""
		if pub, ok := witnesses[c.WitnessID]; !ok {
			reason = ErrUnknownWitness.Error()
		} else if err := verifyCosignature(c.STHCanonical, c.Signature, pub); err != nil {
			reason = err.Error()
		}
		if reason != "" {
			badCount++
			if len(bad) < limit {
				bad = append(bad, NonconformingCosignature{Index: n, WitnessID: c.WitnessID, TreeSize: c.TreeSize, Reason: reason})
			}
		}
		n++
		return nil
	})
	if err != nil {
		return err
	}
	rep.WitnessKeys = len(witnesses)
	rep.Cosignatures = n
	rep.NonconformingCosignatureCount = &badCount
	rep.NonconformingCosignatures = bad
	return nil
}
