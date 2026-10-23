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
}

// Check verifies a data directory without modifying it, as Open does:
// every entry's checksum and leaf hash, and the checkpoint's signature
// (under pub), log ID and root. A damaged tail past the checkpoint is
// reported, not repaired; the server truncates it when it next opens the
// directory.
func Check(dir, logID string, pub ed25519.PublicKey) (CheckReport, error) {
	var rep CheckReport
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
	res, err := store.Scan(f, st.Size(), store.HardMaxPayload, ck.TreeSize, func(_ uint64, leaf merkle.Hash, payload []byte) error {
		if err := checkEntry(leaf, payload); err != nil {
			return err
		}
		tree.Append(leaf)
		return nil
	})
	if err != nil {
		return rep, err
	}
	rep.Entries = tree.Size()
	rep.CheckpointSize = ck.TreeSize
	rep.RootHash = ck.RootHash
	rep.Timestamp = ck.Timestamp
	if res.TornAt >= 0 {
		rep.TornTailBytes = st.Size() - res.TornAt
	}
	return rep, checkCheckpointRoot(ck, &tree)
}
