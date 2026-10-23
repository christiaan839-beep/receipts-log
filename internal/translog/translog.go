// Package translog is the receipts transparency log: it admits signed
// receipts, keeps them in an append-only store, maintains the Merkle
// tree over their leaf hashes, signs tree heads, serves proofs and
// records witness cosignatures.
//
// The leaf for a receipt is LeafHash(UTF-8 bytes of its "canonical"
// string): the canonical projection is the leaf data (transparency-log
// spec §3.1). The stored entry is the whole receipt as submitted, in
// compact JSON.
package translog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/store"
	"github.com/christiaan839-beep/receipts-log/internal/vaos"
)

// Errors returned by the log. The server maps each to an HTTP status.
var (
	ErrTooLarge         = errors.New("receipt is larger than the entry size limit")
	ErrInvalidReceipt   = errors.New("receipt is not a valid receipt object")
	ErrUnverified       = errors.New("receipt signature does not verify under any configured issuer key")
	ErrReadOnly         = errors.New("log is read-only after a storage failure; restart it")
	ErrFull             = errors.New("log has reached its maximum size")
	ErrNotFound         = errors.New("no such entry")
	ErrRange            = errors.New("index or tree size out of range")
	ErrUnknownWitness   = errors.New("witness is not configured on this log")
	ErrWitnessSignature = errors.New("witness signature does not verify")
	ErrForeignSTH       = errors.New("tree head was not produced by this log")
	ErrInvalidCosig     = errors.New("invalid cosignature request")
)

// Config configures Open.
type Config struct {
	// Dir is the data directory.
	Dir string
	// LogID is this log's stable identifier, carried in every STH.
	LogID string
	// Key signs tree heads.
	Key ed25519.PrivateKey
	// IssuerKeys are the receipt issuers' Ed25519 public keys. A receipt
	// is admitted when it verifies under any of them.
	IssuerKeys []ed25519.PublicKey
	// WitnessKeys maps witness IDs to their public keys. Cosignatures
	// from other witnesses are refused.
	WitnessKeys map[string]ed25519.PublicKey
	// MaxEntryBytes bounds a submitted receipt; 0 means 1 MiB.
	MaxEntryBytes int
	// Logger receives structured logs; nil discards them.
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Cosignature is a witness's signature over one of this log's STHs.
type Cosignature struct {
	WitnessID    string `json:"witnessId"`
	TreeSize     uint64 `json:"treeSize"`
	RootHash     string `json:"rootHash"`
	Timestamp    string `json:"timestamp"`
	STHCanonical string `json:"sthCanonical"`
	Signature    string `json:"signature"`
	PublicKeyURL string `json:"publicKeyUrl,omitempty"`
	ReceivedAt   string `json:"receivedAt"`
}

// AppendResult reports an append.
type AppendResult struct {
	Index     uint64
	Leaf      merkle.Hash
	STH       sth.STH
	Duplicate bool
	IssuerKey string
}

// Entry is a stored receipt.
type Entry struct {
	Index   uint64
	Leaf    merkle.Hash
	Receipt json.RawMessage
}

// Log is an open transparency log. It is safe for concurrent use.
type Log struct {
	id          string
	key         ed25519.PrivateKey
	pub         ed25519.PublicKey
	issuers     []ed25519.PublicKey
	witnesses   map[string]ed25519.PublicKey
	maxEntry    int
	log         *slog.Logger
	now         func() time.Time
	mu          sync.RWMutex
	st          *store.Store
	tree        merkle.Tree
	byLeaf      map[merkle.Hash]uint64
	head        sth.STH
	failed      bool
	cosigs      []Cosignature
	cosigByKey  map[string]int
	cosigCounts map[string]int
}

// Open opens (or creates) the log in cfg.Dir and verifies it: every
// entry's checksum and leaf hash, and the stored checkpoint's signature,
// log ID and root against the rebuilt tree.
func Open(cfg Config) (*Log, error) {
	if err := sth.ValidateLogID(cfg.LogID); err != nil {
		return nil, err
	}
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("translog: a log signing key is required")
	}
	if len(cfg.IssuerKeys) == 0 {
		return nil, errors.New("translog: at least one issuer key is required")
	}
	for i, k := range cfg.IssuerKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("translog: issuer key %d is not an Ed25519 public key", i)
		}
	}
	maxEntry := cfg.MaxEntryBytes
	if maxEntry == 0 {
		maxEntry = store.DefaultMaxPayload
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	l := &Log{
		id:          cfg.LogID,
		key:         cfg.Key,
		pub:         cfg.Key.Public().(ed25519.PublicKey),
		issuers:     cfg.IssuerKeys,
		witnesses:   cfg.WitnessKeys,
		maxEntry:    maxEntry,
		log:         logger,
		now:         now,
		byLeaf:      make(map[merkle.Hash]uint64),
		cosigByKey:  make(map[string]int),
		cosigCounts: make(map[string]int),
	}
	visitEntry := func(i uint64, leaf merkle.Hash, payload []byte) error {
		r, err := parseReceipt(payload)
		if err != nil {
			return err
		}
		if merkle.LeafHash([]byte(r.Canonical)) != leaf {
			return errors.New("stored leaf hash does not match the receipt's canonical")
		}
		l.tree.Append(leaf)
		if _, dup := l.byLeaf[leaf]; !dup {
			l.byLeaf[leaf] = i
		}
		return nil
	}
	visitCosig := func(line []byte) error {
		var c Cosignature
		if err := json.Unmarshal(line, &c); err != nil {
			return err
		}
		l.addCosigLocked(c)
		return nil
	}
	st, err := store.Open(store.Options{Dir: cfg.Dir, MaxPayload: maxEntry, Logger: logger}, visitEntry, visitCosig)
	if err != nil {
		return nil, err
	}
	l.st = st
	if err := l.loadCheckpoint(); err != nil {
		st.Close()
		return nil, err
	}
	logger.Info("log opened", "logId", l.id, "treeSize", l.head.TreeSize,
		"rootHash", l.head.RootHash, "logKey", keys.ID(l.pub), "issuerKeys", len(l.issuers),
		"witnesses", len(l.witnesses), "cosignatures", len(l.cosigs))
	return l, nil
}

func (l *Log) loadCheckpoint() error {
	data, err := l.st.ReadCheckpoint()
	if err != nil {
		return err
	}
	size := l.tree.Size()
	if data == nil {
		if size != 0 {
			return fmt.Errorf("%w: %d entries but no %s", store.ErrCorrupt, size, store.CheckpointFile)
		}
		return l.signAndCheckpointLocked()
	}
	var ck sth.STH
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ck); err != nil {
		return fmt.Errorf("%w: %s: %v", store.ErrCorrupt, store.CheckpointFile, err)
	}
	if err := sth.Verify(ck, l.pub); err != nil {
		return fmt.Errorf("%w: %s does not verify under the configured log key: %v",
			store.ErrCorrupt, store.CheckpointFile, err)
	}
	if ck.LogID != l.id {
		return fmt.Errorf("translog: data directory belongs to log %q, not %q", ck.LogID, l.id)
	}
	if ck.TreeSize > size {
		return fmt.Errorf("%w: checkpoint covers %d entries, store has %d", store.ErrCorrupt, ck.TreeSize, size)
	}
	root, _ := l.tree.RootAt(ck.TreeSize)
	if root.String() != ck.RootHash {
		return fmt.Errorf("%w: rebuilt root at size %d does not match the signed checkpoint", store.ErrCorrupt, ck.TreeSize)
	}
	l.head = ck
	if ck.TreeSize < size {
		// Entries written after the last checkpoint by an append that
		// was interrupted before it was acknowledged.
		l.log.Warn("signing a tree head for entries past the checkpoint",
			"checkpoint", ck.TreeSize, "entries", size)
		return l.signAndCheckpointLocked()
	}
	return nil
}

// signAndCheckpointLocked signs a tree head over the whole tree and makes
// it durable. Timestamps never go backwards.
func (l *Log) signAndCheckpointLocked() error {
	at := l.now()
	if l.head.Timestamp != "" {
		if prev, err := time.Parse(time.RFC3339Nano, l.head.Timestamp); err == nil && at.Before(prev) {
			at = prev
		}
	}
	head, err := sth.Sign(sth.New(l.id, l.tree.Size(), l.tree.Root(), at), l.key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(head)
	if err != nil {
		return err
	}
	if err := l.st.WriteCheckpoint(data); err != nil {
		l.failed = true
		l.log.Error("checkpoint write failed; the log is now read-only", "err", err)
		return err
	}
	l.head = head
	return nil
}

func parseReceipt(body []byte) (vaos.Receipt, error) {
	var r vaos.Receipt
	if err := json.Unmarshal(body, &r); err != nil {
		return r, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	if r.Canonical == "" {
		return r, fmt.Errorf("%w: missing canonical", ErrInvalidReceipt)
	}
	if !utf8.ValidString(r.Canonical) {
		return r, fmt.Errorf("%w: canonical is not valid UTF-8", ErrInvalidReceipt)
	}
	return r, nil
}

// LeafForReceipt returns the leaf hash a receipt is logged under.
func LeafForReceipt(body []byte) (merkle.Hash, error) {
	r, err := parseReceipt(body)
	if err != nil {
		return merkle.Hash{}, err
	}
	return merkle.LeafHash([]byte(r.Canonical)), nil
}

// verify checks the receipt under each issuer key, as a VAOS 2.0
// receipt and then as a Guardian attestation.
func (l *Log) verify(r vaos.Receipt) (string, error) {
	reason := ""
	for _, k := range l.issuers {
		res := vaos.VerifyV2Receipt(r, k)
		if res.OK {
			return keys.ID(k), nil
		}
		if reason == "" {
			reason = res.Reason
		}
		if vaos.VerifyGuardianAttestation(r, k).OK {
			return keys.ID(k), nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrUnverified, reason)
}

// Append verifies a receipt and, when it is new, appends it. A receipt
// whose canonical is already logged returns the existing entry.
func (l *Log) Append(body []byte) (AppendResult, error) {
	if len(body) > l.maxEntry {
		return AppendResult{}, ErrTooLarge
	}
	r, err := parseReceipt(body)
	if err != nil {
		return AppendResult{}, err
	}
	issuer, err := l.verify(r)
	if err != nil {
		return AppendResult{}, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return AppendResult{}, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	if compact.Len() > l.maxEntry {
		return AppendResult{}, ErrTooLarge
	}
	leaf := merkle.LeafHash([]byte(r.Canonical))

	l.mu.Lock()
	defer l.mu.Unlock()
	if idx, ok := l.byLeaf[leaf]; ok && idx < l.head.TreeSize {
		return AppendResult{Index: idx, Leaf: leaf, STH: l.head, Duplicate: true, IssuerKey: issuer}, nil
	}
	if l.failed {
		return AppendResult{}, ErrReadOnly
	}
	if l.tree.Size() >= sth.MaxTreeSize {
		return AppendResult{}, ErrFull
	}
	idx, err := l.st.Append(leaf, compact.Bytes())
	if err != nil {
		l.failed = true
		l.log.Error("entry write failed; the log is now read-only", "err", err)
		return AppendResult{}, ErrReadOnly
	}
	if got := l.tree.Append(leaf); got != idx {
		l.failed = true
		return AppendResult{}, fmt.Errorf("translog: tree index %d != store index %d", got, idx)
	}
	l.byLeaf[leaf] = idx
	if err := l.signAndCheckpointLocked(); err != nil {
		return AppendResult{}, ErrReadOnly
	}
	return AppendResult{Index: idx, Leaf: leaf, STH: l.head, IssuerKey: issuer}, nil
}

// RefreshSTH signs a new tree head with the current time, so monitors
// can see the log is live even when nothing is appended.
func (l *Log) RefreshSTH() (sth.STH, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed {
		return l.head, ErrReadOnly
	}
	if err := l.signAndCheckpointLocked(); err != nil {
		return l.head, err
	}
	return l.head, nil
}

// LogID returns the log identifier.
func (l *Log) LogID() string { return l.id }

// PublicKey returns the tree-head verification key.
func (l *Log) PublicKey() ed25519.PublicKey { return l.pub }

// STH returns the latest signed tree head.
func (l *Log) STH() sth.STH {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.head
}

// ReadOnly reports whether a storage failure has stopped appends.
func (l *Log) ReadOnly() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.failed
}

// Entry returns entry i of the published tree.
func (l *Log) Entry(i uint64) (Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if i >= l.head.TreeSize {
		return Entry{}, ErrNotFound
	}
	leaf, payload, err := l.st.Read(i)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Index: i, Leaf: leaf, Receipt: json.RawMessage(payload)}, nil
}

// IndexOf returns the index of a leaf in the published tree.
func (l *Log) IndexOf(leaf merkle.Hash) (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	i, ok := l.byLeaf[leaf]
	if !ok || i >= l.head.TreeSize {
		return 0, ErrNotFound
	}
	return i, nil
}

// InclusionProof is an audit path with what is needed to check it, in
// the field names of the verifiable-receipts conformance fixtures.
type InclusionProof struct {
	Leaf  merkle.Hash
	Index uint64
	Size  uint64
	Path  []merkle.Hash
	Root  merkle.Hash
}

// ProveInclusion returns the audit path for entry index in the tree of
// the given size. Size 0 means the latest published size.
func (l *Log) ProveInclusion(index, size uint64) (InclusionProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if size == 0 {
		size = l.head.TreeSize
	}
	if size > l.head.TreeSize || index >= size {
		return InclusionProof{}, ErrRange
	}
	path, err := l.tree.InclusionProof(index, size)
	if err != nil {
		return InclusionProof{}, ErrRange
	}
	leaf, _ := l.tree.Leaf(index)
	root, _ := l.tree.RootAt(size)
	return InclusionProof{Leaf: leaf, Index: index, Size: size, Path: path, Root: root}, nil
}

// ConsistencyProof is a consistency proof with both roots.
type ConsistencyProof struct {
	First, Second         uint64
	FirstRoot, SecondRoot merkle.Hash
	Path                  []merkle.Hash
}

// ProveConsistency returns the proof that the tree of size second
// extends the tree of size first. Second 0 means the latest size.
func (l *Log) ProveConsistency(first, second uint64) (ConsistencyProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if second == 0 {
		second = l.head.TreeSize
	}
	if second > l.head.TreeSize || first > second {
		return ConsistencyProof{}, ErrRange
	}
	path, err := l.tree.ConsistencyProof(first, second)
	if err != nil {
		return ConsistencyProof{}, ErrRange
	}
	fr, _ := l.tree.RootAt(first)
	sr, _ := l.tree.RootAt(second)
	return ConsistencyProof{First: first, Second: second, FirstRoot: fr, SecondRoot: sr, Path: path}, nil
}

func cosigKey(witnessID, canonical string) string { return witnessID + "\x00" + canonical }

func (l *Log) addCosigLocked(c Cosignature) {
	k := cosigKey(c.WitnessID, c.STHCanonical)
	if _, ok := l.cosigByKey[k]; ok {
		return
	}
	l.cosigByKey[k] = len(l.cosigs)
	l.cosigs = append(l.cosigs, c)
	l.cosigCounts[c.STHCanonical]++
}

func validLabel(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// AddCosignature records a witness's signature over one of this log's
// tree heads. It returns the number of distinct witnesses that have
// cosigned that tree head and whether this call added a record.
func (l *Log) AddCosignature(witnessID, canonical, signature, publicKeyURL string) (int, bool, error) {
	if !validLabel(witnessID, 256) {
		return 0, false, fmt.Errorf("%w: witnessId", ErrInvalidCosig)
	}
	if publicKeyURL != "" && !validLabel(publicKeyURL, 2048) {
		return 0, false, fmt.Errorf("%w: publicKeyUrl", ErrInvalidCosig)
	}
	pub, ok := l.witnesses[witnessID]
	if !ok {
		return 0, false, ErrUnknownWitness
	}
	head, err := sth.ParseCanonical([]byte(canonical))
	if err != nil {
		return 0, false, fmt.Errorf("%w: sthCanonical: %v", ErrInvalidCosig, err)
	}
	if err := sth.VerifyBytes([]byte(canonical), signature, pub); err != nil {
		return 0, false, ErrWitnessSignature
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if head.LogID != l.id || head.TreeSize > l.head.TreeSize {
		return 0, false, ErrForeignSTH
	}
	if root, _ := l.tree.RootAt(head.TreeSize); root.String() != head.RootHash {
		return 0, false, ErrForeignSTH
	}
	if _, dup := l.cosigByKey[cosigKey(witnessID, canonical)]; dup {
		return l.cosigCounts[canonical], false, nil
	}
	if l.failed {
		return 0, false, ErrReadOnly
	}
	c := Cosignature{
		WitnessID: witnessID, TreeSize: head.TreeSize, RootHash: head.RootHash,
		Timestamp: head.Timestamp, STHCanonical: canonical, Signature: signature,
		PublicKeyURL: publicKeyURL, ReceivedAt: sth.FormatTime(l.now()),
	}
	line, err := json.Marshal(c)
	if err != nil {
		return 0, false, err
	}
	if err := l.st.AppendCosignature(line); err != nil {
		l.failed = true
		l.log.Error("cosignature write failed; the log is now read-only", "err", err)
		return 0, false, ErrReadOnly
	}
	l.addCosigLocked(c)
	return l.cosigCounts[canonical], true, nil
}

// Cosignatures returns the stored cosignatures for a tree size, or all
// of them when all is true.
func (l *Log) Cosignatures(size uint64, all bool) []Cosignature {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := []Cosignature{}
	for _, c := range l.cosigs {
		if all || c.TreeSize == size {
			out = append(out, c)
		}
	}
	return out
}

// Close closes the store.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.st.Close()
}
