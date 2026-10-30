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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

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
	// ErrCosigRecord is a stored cosignature record whose treeSize,
	// rootHash or timestamp differ from the tree head its sthCanonical
	// signs. Only Open and Check meet it; AddCosignature writes the
	// fields from the head.
	ErrCosigRecord = errors.New("cosignature record disagrees with its signed tree head")
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
	cosigSizes  []uint64 // cosigSizes[i] is the tree size cosigs[i]'s sthCanonical signs
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
	if err := checkLogKey(cfg.Key); err != nil {
		return nil, err
	}
	if len(cfg.IssuerKeys) == 0 {
		return nil, errors.New("translog: at least one issuer key is required")
	}
	if err := validateIssuerKeys(cfg.IssuerKeys); err != nil {
		return nil, err
	}
	if err := validateWitnessKeys(cfg.WitnessKeys); err != nil {
		return nil, err
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
		if err := checkEntry(leaf, payload); err != nil {
			return err
		}
		l.tree.Append(leaf)
		if _, dup := l.byLeaf[leaf]; !dup {
			l.byLeaf[leaf] = i
		}
		return nil
	}
	// A stored cosignature is served only as evidence of this log: one
	// whose sthCanonical is not a head of this log, or whose record fields
	// disagree with it, is skipped, with a warning, so that a store an
	// older build wrote (or one edited by hand) still opens. Its signature
	// is not verified here; check -witness-key does that.
	var skipped, line uint64
	firstSkipped := ""
	visitCosig := func(raw []byte) error {
		defer func() { line++ }()
		var c Cosignature
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		head, err := storedCosignatureHead(c, l.id, l.tree.Size(), l.tree.RootAt)
		if err != nil {
			if skipped == 0 {
				firstSkipped = fmt.Sprintf("line %d: %v", line, err)
			}
			skipped++
			return nil
		}
		l.addCosigLocked(c, head.TreeSize)
		return nil
	}
	st, err := store.Open(store.Options{Dir: cfg.Dir, MaxPayload: maxEntry, Logger: logger}, visitEntry, visitCosig)
	if err != nil {
		return nil, err
	}
	l.st = st
	if skipped > 0 {
		logger.Warn("skipping stored cosignatures that are not evidence of this log; run check -witness-key",
			"skipped", skipped, "first", firstSkipped)
	}
	if err := l.loadCheckpoint(cfg.Dir); err != nil {
		st.Close()
		return nil, err
	}
	logger.Info("log opened", "logId", l.id, "treeSize", l.head.TreeSize,
		"rootHash", l.head.RootHash, "logKey", keys.ID(l.pub), "issuerKeys", len(l.issuers),
		"witnesses", len(l.witnesses), "cosignatures", len(l.cosigs))
	return l, nil
}

// checkEntry checks that a stored entry's leaf hash is the leaf of the
// receipt stored with it, by LeafForReceipt and not the admission rules:
// an entry an older build admitted is intact even if admission now
// refuses it (Check reports those separately).
func checkEntry(leaf merkle.Hash, payload []byte) error {
	got, err := LeafForReceipt(payload)
	if err != nil {
		return err
	}
	if got != leaf {
		return errors.New("stored leaf hash does not match the receipt's canonical")
	}
	return nil
}

// parseCheckpoint decodes the contents of checkpoint.json and checks its
// signature under pub and its log ID.
func parseCheckpoint(data []byte, pub ed25519.PublicKey, logID string) (sth.STH, error) {
	var ck sth.STH
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ck); err != nil {
		return sth.STH{}, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, store.CheckpointFile, err)
	}
	if err := sth.Verify(ck, pub); err != nil {
		return sth.STH{}, fmt.Errorf("%w: %s does not verify under the log key: %v",
			store.ErrCorrupt, store.CheckpointFile, err)
	}
	if ck.LogID != logID {
		return sth.STH{}, fmt.Errorf("translog: %s is for log %q, not %q", store.CheckpointFile, ck.LogID, logID)
	}
	return ck, nil
}

// checkCheckpointRoot checks that tree holds the checkpoint's tree size
// and has the checkpoint's root at that size.
func checkCheckpointRoot(ck sth.STH, tree *merkle.Tree) error {
	if ck.TreeSize > tree.Size() {
		return fmt.Errorf("%w: %s covers %d entries, %s holds %d",
			store.ErrCorrupt, store.CheckpointFile, ck.TreeSize, store.EntriesFile, tree.Size())
	}
	if root, _ := tree.RootAt(ck.TreeSize); root.String() != ck.RootHash {
		return fmt.Errorf("%w: the root at size %d does not match the signed checkpoint", store.ErrCorrupt, ck.TreeSize)
	}
	return nil
}

func (l *Log) loadCheckpoint(dir string) error {
	data, err := store.ReadCheckpoint(dir)
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
	ck, err := parseCheckpoint(data, l.pub, l.id)
	if err != nil {
		return err
	}
	if err := checkCheckpointRoot(ck, &l.tree); err != nil {
		return err
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

// parseReceipt decodes a receipt and requires a canonical string. It
// reads with vaos.ParseReceipt, which counts the text's depth before
// decoding it, so a receipt nested deeper than 64 is refused at any
// depth, a duplicate key the decoder discards included (VAOS 2.0 section
// 7.2). The decoder replaces invalid UTF-8 with U+FFFD, so the canonical
// is valid UTF-8.
func parseReceipt(body []byte) (vaos.Receipt, error) {
	r, err := vaos.ParseReceipt(body)
	if err != nil {
		return r, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	if r.Canonical == "" {
		return r, fmt.Errorf("%w: missing canonical", ErrInvalidReceipt)
	}
	return r, nil
}

// LeafForReceipt returns the leaf hash a receipt is logged under: the
// leaf of its "canonical", which must be a non-empty string (of a key
// given twice, the last). It does not apply the admission rules, which
// change between versions, so a receipt an older build admitted keeps
// its leaf: Open and Check verify stored entries with it, and the prove
// command finds a receipt with it. Admission uses parseReceipt, which
// derives the same leaf for every receipt it accepts.
func LeafForReceipt(body []byte) (merkle.Hash, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return merkle.Hash{}, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	var canonical string
	if raw, ok := fields["canonical"]; ok {
		if err := json.Unmarshal(raw, &canonical); err != nil {
			return merkle.Hash{}, fmt.Errorf("%w: canonical is not a string", ErrInvalidReceipt)
		}
	}
	if canonical == "" {
		return merkle.Hash{}, fmt.Errorf("%w: missing canonical", ErrInvalidReceipt)
	}
	return merkle.LeafHash([]byte(canonical)), nil
}

// checkLogKey refuses a log signing key whose public half does not
// match its seed or is not a point of order L (VAOS 2.0 section 7.3):
// strict verifiers would reject every tree head signed with it.
func checkLogKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("translog: a log signing key is required")
	}
	pub := key.Public().(ed25519.PublicKey)
	if !ed25519.NewKeyFromSeed(key.Seed()).Public().(ed25519.PublicKey).Equal(pub) {
		return errors.New("translog: log key: the public half does not match the seed")
	}
	if err := keys.CheckPublicKey(pub); err != nil {
		return fmt.Errorf("translog: log key: %w", err)
	}
	return nil
}

// validateIssuerKeys refuses an issuer key that is not a usable Ed25519
// public key: one that is not a canonical encoding of a point of order L
// (small order, mixed order, off the curve or non-canonical; VAOS 2.0
// section 7.3). Under the identity key one signature verifies every
// receipt, and under a mixed-order key verifiers disagree.
func validateIssuerKeys(issuers []ed25519.PublicKey) error {
	for i, k := range issuers {
		if err := keys.CheckPublicKey(k); err != nil {
			return fmt.Errorf("translog: issuer key %d: %w", i, err)
		}
	}
	return nil
}

// validateWitnessKeys refuses a witness key as validateIssuerKeys does:
// under a small-order key anyone could cosign as that witness.
func validateWitnessKeys(witnesses map[string]ed25519.PublicKey) error {
	for id, k := range witnesses {
		if err := keys.CheckPublicKey(k); err != nil {
			return fmt.Errorf("translog: witness key %q: %w", id, err)
		}
	}
	return nil
}

// verifyReceipt applies admission's payload rules to body: it parses
// the receipt and checks it under each issuer key, as a VAOS 2.0
// receipt and then as a Guardian attestation. It returns the ID of the
// key that verified it. Append and Check both call it, so Check
// re-applies exactly the receipt checks admission applies today (the
// size limit apart, which is the server's configuration).
func verifyReceipt(body []byte, issuers []ed25519.PublicKey) (vaos.Receipt, string, error) {
	r, err := parseReceipt(body)
	if err != nil {
		return r, "", err
	}
	issuer, err := verifyIssued(r, issuers)
	return r, issuer, err
}

// rProblemPrefix and keyProblemPrefix begin the strict-profile reasons
// of VAOS 2.0 section 7.3 about R and about the key, as vaos gives them.
const (
	rProblemPrefix   = "signature R is "
	keyProblemPrefix = "public key is "
)

// signatureDoesNotVerify is vaos's reason for a signature that fails
// under the key (an S of L or more, or a wrong length, included).
const signatureDoesNotVerify = "signature does not verify under the supplied public key"

// isSignatureFailure reports whether a reason is about the signature
// under one key, as verify-receipts-action's isSignatureFailure: it does
// not verify, the key is refused, or R is. Every other reason is about
// the receipt: its form or contentHash, the same under every key, or an
// envelope field that fails after the signature has verified.
func isSignatureFailure(reason string) bool {
	return reason == signatureDoesNotVerify || strings.HasPrefix(reason, rProblemPrefix) ||
		strings.HasPrefix(reason, keyProblemPrefix)
}

// verifyIssued returns the ID of the first issuer key under which r
// verifies as a VAOS 2.0 receipt or as a Guardian attestation. Its
// answer under each key is what VerifyV2Receipt and then
// VerifyGuardianAttestation give, but the work that does not depend on
// the key is done once per receipt, not once per key, so that a forged
// signature costs about one subgroup check however many keys there are:
//
//   - VerifyV2Receipt under a key of the wrong length (nil) makes every
//     check that comes before the signature (the receipt's form, its
//     base64 and its contentHash, in VerifyV2Receipt's order) and stops
//     at the signature with signatureDoesNotVerify, without point
//     arithmetic. Any other reason is the reason under every valid key.
//   - vaos.Ed25519SignatureProblem then checks R and S once.
//   - Then crypto/ed25519 alone checks the signature under each issuer
//     in turn, after those checks, as vaos.VerifyEd25519 does; the key
//     is checked by vaos.Ed25519PublicKeyProblem, whose answers are
//     cached (Open and Check refuse a bad issuer key, so it is "" there).
//   - Only under a key the signature verifies under does VerifyV2Receipt
//     run in full, and VerifyGuardianAttestation only when that fails at
//     the envelope and the envelope has "rules" or "totalMs": the
//     attestation's signed view has the same canonical, signature and
//     contentHash, so it fails every earlier step the same way, and it
//     differs from the receipt only by dropping "totalMs" and projecting
//     "rules", so without either it is the receipt and fails the same.
//
// When no key verifies it, the reason follows verify-receipts-action's
// rule (verifyUnderKeys): a reason about the receipt wins, then one
// about R, then the one key's own reason or, with several, that the
// signature verifies under none of them.
func verifyIssued(r vaos.Receipt, issuers []ed25519.PublicKey) (string, error) {
	keyless := vaos.VerifyV2Receipt(r, nil).Reason
	var sig []byte
	sigProblem := ""
	if keyless == signatureDoesNotVerify {
		// VerifyV2Receipt has checked that the signature is "v2=" and
		// canonical base64.
		sig, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Signature, "v2="))
		sigProblem = vaos.Ed25519SignatureProblem(sig)
	}
	var first, receiptProblem, rProblem string
	for i, k := range issuers {
		var reason string
		switch {
		case vaos.Ed25519PublicKeyProblem(k) != "":
			// A refused key or one of the wrong length: VerifyV2Receipt
			// stops at it, or earlier, before any point arithmetic.
			reason = vaos.VerifyV2Receipt(r, k).Reason
		case keyless != signatureDoesNotVerify:
			reason = keyless
		case sigProblem != "":
			reason = sigProblem
		case !ed25519.Verify(k, []byte(r.Canonical), sig):
			reason = signatureDoesNotVerify
		default:
			res := vaos.VerifyV2Receipt(r, k)
			if res.OK || (hasGuardianFields(r) && vaos.VerifyGuardianAttestation(r, k).OK) {
				return keys.ID(k), nil
			}
			reason = res.Reason
		}
		if i == 0 {
			first = reason
		}
		switch {
		case !isSignatureFailure(reason):
			if receiptProblem == "" {
				receiptProblem = reason
			}
		case strings.HasPrefix(reason, rProblemPrefix):
			if rProblem == "" {
				rProblem = reason
			}
		}
	}
	reason := first
	switch {
	case receiptProblem != "":
		reason = receiptProblem
	case rProblem != "":
		reason = rProblem
	case len(issuers) > 1:
		reason = fmt.Sprintf("signature does not verify under any of the %d issuer keys", len(issuers))
	}
	return "", fmt.Errorf("%w: %s", ErrUnverified, reason)
}

// hasGuardianFields reports whether r's envelope has a field the
// Guardian attestation's signed view changes ("rules", projected, and
// "totalMs", dropped); without one the view is r itself.
func hasGuardianFields(r vaos.Receipt) bool {
	_, rules := r.Envelope["rules"]
	_, total := r.Envelope["totalMs"]
	return rules || total
}

// Append verifies a receipt and, when it is new, appends it. A receipt
// whose canonical is already logged returns the existing entry.
func (l *Log) Append(body []byte) (AppendResult, error) {
	if len(body) > l.maxEntry {
		return AppendResult{}, ErrTooLarge
	}
	r, issuer, err := verifyReceipt(body, l.issuers)
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

// addCosigLocked records c, whose sthCanonical signs a head of size.
func (l *Log) addCosigLocked(c Cosignature, size uint64) {
	k := cosigKey(c.WitnessID, c.STHCanonical)
	if _, ok := l.cosigByKey[k]; ok {
		return
	}
	l.cosigByKey[k] = len(l.cosigs)
	l.cosigs = append(l.cosigs, c)
	l.cosigSizes = append(l.cosigSizes, size)
	l.cosigCounts[c.STHCanonical]++
}

// cosigRules is what vetCosignature checks a cosignature against.
type cosigRules struct {
	witnesses map[string]ed25519.PublicKey
	// ownHead reports whether head is one this log produced: its log ID,
	// a size it has reached, and the root it had at that size.
	ownHead func(head sth.STH) bool
}

// ownHeadOf returns cosigRules.ownHead for the log logID with a tree of
// size entries whose roots rootAt gives.
func ownHeadOf(logID string, size uint64, rootAt func(uint64) (merkle.Hash, error)) func(sth.STH) bool {
	return func(head sth.STH) bool {
		if head.LogID != logID || head.TreeSize > size {
			return false
		}
		root, err := rootAt(head.TreeSize)
		return err == nil && root.String() == head.RootHash
	}
}

// vetCosignature applies the rules a cosignature must meet, in this
// order, and returns the tree head it signs:
//
//  1. witnessId and publicKeyUrl are valid labels (ErrInvalidCosig);
//  2. the witness is configured (ErrUnknownWitness);
//  3. sthCanonical is a tree head in canonical form (ErrInvalidCosig);
//  4. the head is one this log produced (ErrForeignSTH): checked before
//     the signature because it is cheap, so a head that is not this
//     log's costs no subgroup check;
//  5. the signature verifies under the witness's key, under the strict
//     profile of VAOS 2.0 section 7.3 (ErrWitnessSignature).
//
// AddCosignature and Check both call it.
func vetCosignature(rules cosigRules, witnessID, canonical, signature, publicKeyURL string) (sth.STH, error) {
	if !sth.ValidLabel(witnessID, 256) {
		return sth.STH{}, fmt.Errorf("%w: witnessId", ErrInvalidCosig)
	}
	if publicKeyURL != "" && !sth.ValidLabel(publicKeyURL, 2048) {
		return sth.STH{}, fmt.Errorf("%w: publicKeyUrl", ErrInvalidCosig)
	}
	pub, ok := rules.witnesses[witnessID]
	if !ok {
		return sth.STH{}, ErrUnknownWitness
	}
	head, err := sth.ParseCanonical([]byte(canonical))
	if err != nil {
		return sth.STH{}, fmt.Errorf("%w: sthCanonical: %v", ErrInvalidCosig, err)
	}
	if !rules.ownHead(head) {
		return sth.STH{}, ErrForeignSTH
	}
	if err := verifyCosignature(canonical, signature, pub); err != nil {
		return sth.STH{}, err
	}
	return head, nil
}

// storedCosignatureHead returns the head a stored record's sthCanonical
// signs, when it is in canonical form, is a head of the log logID (with
// size entries, whose roots rootAt gives) and the record's treeSize,
// rootHash and timestamp are the head's. It does not check the witness
// or the signature: Open calls it on every stored record, and Check
// after vetCosignature.
func storedCosignatureHead(c Cosignature, logID string, size uint64, rootAt func(uint64) (merkle.Hash, error)) (sth.STH, error) {
	head, err := sth.ParseCanonical([]byte(c.STHCanonical))
	if err != nil {
		return sth.STH{}, fmt.Errorf("%w: sthCanonical: %v", ErrInvalidCosig, err)
	}
	if !ownHeadOf(logID, size, rootAt)(head) {
		return sth.STH{}, ErrForeignSTH
	}
	var differ []string
	if c.TreeSize != head.TreeSize {
		differ = append(differ, "treeSize")
	}
	if c.RootHash != head.RootHash {
		differ = append(differ, "rootHash")
	}
	if c.Timestamp != head.Timestamp {
		differ = append(differ, "timestamp")
	}
	if len(differ) > 0 {
		return sth.STH{}, fmt.Errorf("%w: %s", ErrCosigRecord, strings.Join(differ, ", "))
	}
	return head, nil
}

// AddCosignature records a witness's signature over one of this log's
// tree heads. It returns the number of distinct witnesses that have
// cosigned that tree head and whether this call added a record.
func (l *Log) AddCosignature(witnessID, canonical, signature, publicKeyURL string) (int, bool, error) {
	// The head check reads the tree under the read lock; the signature
	// is then checked without a lock. A head that is this log's stays
	// so: the tree only grows.
	head, err := vetCosignature(cosigRules{witnesses: l.witnesses, ownHead: func(h sth.STH) bool {
		l.mu.RLock()
		defer l.mu.RUnlock()
		return ownHeadOf(l.id, l.head.TreeSize, l.tree.RootAt)(h)
	}}, witnessID, canonical, signature, publicKeyURL)
	if err != nil {
		return 0, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
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
	l.addCosigLocked(c, head.TreeSize)
	return l.cosigCounts[canonical], true, nil
}

// verifyCosignature checks a witness's signature over a tree head
// with sth.VerifyBytes, under the strict profile of VAOS 2.0 section
// 7.3. The error is ErrWitnessSignature with the verifier's reason.
// AddCosignature and Check both call it.
func verifyCosignature(canonical, signature string, pub ed25519.PublicKey) error {
	if err := sth.VerifyBytes([]byte(canonical), signature, pub); err != nil {
		reason := strings.TrimPrefix(err.Error(), sth.ErrSignature.Error()+": ")
		return fmt.Errorf("%w: %s", ErrWitnessSignature, reason)
	}
	return nil
}

// Cosignatures returns the stored cosignatures for a tree size, or all
// of them when all is true.
func (l *Log) Cosignatures(size uint64, all bool) []Cosignature {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := []Cosignature{}
	for i, c := range l.cosigs {
		// By the size the signed sthCanonical names, not the record's
		// own (unsigned) treeSize field.
		if all || l.cosigSizes[i] == size {
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
