package translog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
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

// Check verifies a data directory without modifying it: every entry's
// checksum and leaf hash, and the checkpoint's signature (under pub),
// log ID and root. A damaged tail past the checkpoint is reported, not
// repaired; the server truncates it when it next opens the directory.
func Check(dir, logID string, pub ed25519.PublicKey) (CheckReport, error) {
	var rep CheckReport
	ckData, err := os.ReadFile(filepath.Join(dir, store.CheckpointFile))
	if err != nil {
		return rep, fmt.Errorf("read checkpoint: %w", err)
	}
	var ck sth.STH
	dec := json.NewDecoder(bytes.NewReader(ckData))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ck); err != nil {
		return rep, fmt.Errorf("%w: checkpoint: %v", store.ErrCorrupt, err)
	}
	if err := sth.Verify(ck, pub); err != nil {
		return rep, fmt.Errorf("%w: checkpoint signature: %v", store.ErrCorrupt, err)
	}
	if ck.LogID != logID {
		return rep, fmt.Errorf("checkpoint is for log %q, not %q", ck.LogID, logID)
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
	res, err := store.Scan(f, st.Size(), store.HardMaxPayload, ck.TreeSize, func(i uint64, leaf merkle.Hash, payload []byte) error {
		r, err := parseReceipt(payload)
		if err != nil {
			return err
		}
		if merkle.LeafHash([]byte(r.Canonical)) != leaf {
			return errors.New("leaf hash does not match the receipt's canonical")
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
	if tree.Size() < ck.TreeSize {
		return rep, fmt.Errorf("%w: %d entries, checkpoint covers %d", store.ErrCorrupt, tree.Size(), ck.TreeSize)
	}
	if root, _ := tree.RootAt(ck.TreeSize); root.String() != ck.RootHash {
		return rep, fmt.Errorf("%w: root at size %d does not match the checkpoint", store.ErrCorrupt, ck.TreeSize)
	}
	return rep, nil
}
