// Package witness implements the witness protocol of the transparency
// log spec (§5): fetch the log's latest signed tree head, check its
// signature, check it is consistent with the last tree head this witness
// signed, cosign it and submit the cosignature.
//
// It speaks the HTTP routes the verifiable-receipts witness CLI uses
// (GET /api/transparency/sth, GET /api/transparency/proof?kind=consistency,
// POST /api/transparency/witness), so it works against this server and
// against any log that serves those routes. Its state file holds the
// same fields as that CLI's (lastSize, lastRoot, lastTimestamp,
// lastSubmittedAt) plus logId.
package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/store"
)

// Verdicts.
const (
	Witnessed = "witnessed"
	NoChange  = "no-change"
	Fork      = "fork-detected"
)

const maxResponse = 1 << 20

// Config configures a witness.
type Config struct {
	// BaseURL is the log's base URL.
	BaseURL string
	// WitnessID names this witness to the log.
	WitnessID string
	// PublicKeyURL is where this witness publishes its key (optional).
	PublicKeyURL string
	// Key signs tree heads.
	Key ed25519.PrivateKey
	// LogKey verifies the log's tree heads.
	LogKey ed25519.PublicKey
	// StatePath holds the last tree head this witness signed.
	StatePath string
	// Client makes the HTTP requests; nil means a client with a 30 s
	// timeout.
	Client *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// State is the witness's memory of the last tree head it signed.
type State struct {
	LogID           string `json:"logId,omitempty"`
	LastSize        uint64 `json:"lastSize"`
	LastRoot        string `json:"lastRoot"`
	LastTimestamp   string `json:"lastTimestamp"`
	LastSubmittedAt string `json:"lastSubmittedAt"`
}

// Result is the outcome of one check.
type Result struct {
	Verdict      string   `json:"verdict"`
	LogID        string   `json:"logId"`
	TreeSize     uint64   `json:"treeSize"`
	RootHash     string   `json:"rootHash"`
	OldSize      uint64   `json:"oldSize,omitempty"`
	OldRoot      string   `json:"oldRoot,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	WitnessCount int      `json:"witnessCount,omitempty"`
	Proof        []string `json:"proof,omitempty"`
	STHCanonical string   `json:"sthCanonical,omitempty"`
	STHSignature string   `json:"sthSignature,omitempty"`
}

// ErrState is returned when the state file exists but cannot be used.
// The witness never treats unreadable state as "first run": that would
// let anyone who can delete or corrupt the file reset its memory.
var ErrState = errors.New("witness: state file is unreadable")

// LoadState reads the state file; a missing file returns nil.
func LoadState(path string) (*State, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	if _, err := merkle.ParseHash(s.LastRoot); err != nil {
		return nil, fmt.Errorf("%w: lastRoot: %v", ErrState, err)
	}
	return &s, nil
}

// SaveState writes the state file atomically with mode 0600.
func SaveState(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return store.WriteFileAtomic(dir, filepath.Base(path), append(data, '\n'))
}

type client struct {
	base *url.URL
	http *http.Client
}

func (c *client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *client) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return fmt.Errorf("%s %s: response larger than %d bytes", req.Method, req.URL.Path, maxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%s %s: HTTP %d %s", req.Method, req.URL.Path, resp.StatusCode, msg)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: malformed response: %v", req.Method, req.URL.Path, err)
	}
	return nil
}

// FetchSTH fetches and verifies the log's latest tree head.
func FetchSTH(ctx context.Context, hc *http.Client, baseURL string, logKey ed25519.PublicKey) (sth.STH, []byte, error) {
	c, err := newClient(baseURL, hc)
	if err != nil {
		return sth.STH{}, nil, err
	}
	return c.fetchSTH(ctx, logKey)
}

func newClient(baseURL string, hc *http.Client) (*client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("witness: %q is not an http(s) URL", baseURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &client{base: u, http: hc}, nil
}

func (c *client) fetchSTH(ctx context.Context, logKey ed25519.PublicKey) (sth.STH, []byte, error) {
	var resp sth.Response
	if err := c.get(ctx, "/api/transparency/sth", nil, &resp); err != nil {
		return sth.STH{}, nil, err
	}
	head := resp.STH
	if err := sth.Verify(head, logKey); err != nil {
		return sth.STH{}, nil, fmt.Errorf("witness: tree head rejected: %w", err)
	}
	canonical, _ := head.Canonical()
	if resp.Canonical != "" && resp.Canonical != string(canonical) {
		return sth.STH{}, nil, errors.New("witness: the log's canonical string does not match its tree head")
	}
	return head, canonical, nil
}

type proofResponse struct {
	Proof []string `json:"proof"`
}

// RunOnce performs one witness check.
func RunOnce(ctx context.Context, cfg Config) (Result, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize || len(cfg.LogKey) != ed25519.PublicKeySize {
		return Result{}, errors.New("witness: a witness key and the log's public key are required")
	}
	if cfg.WitnessID == "" || cfg.StatePath == "" {
		return Result{}, errors.New("witness: witness ID and state path are required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	c, err := newClient(cfg.BaseURL, cfg.Client)
	if err != nil {
		return Result{}, err
	}
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return Result{}, err
	}
	head, canonical, err := c.fetchSTH(ctx, cfg.LogKey)
	if err != nil {
		return Result{}, err
	}
	res := Result{LogID: head.LogID, TreeSize: head.TreeSize, RootHash: head.RootHash,
		STHCanonical: string(canonical), STHSignature: head.Signature}
	newRoot, _ := head.Root()

	if state != nil {
		res.OldSize, res.OldRoot = state.LastSize, state.LastRoot
		oldRoot, _ := merkle.ParseHash(state.LastRoot)
		switch {
		case state.LogID != "" && state.LogID != head.LogID:
			return res, fmt.Errorf("witness: state is for log %q but the server is log %q", state.LogID, head.LogID)
		case head.TreeSize < state.LastSize:
			res.Verdict, res.Reason = Fork, "tree size went backwards"
			return res, nil
		case head.TreeSize == state.LastSize && head.RootHash != state.LastRoot:
			res.Verdict, res.Reason = Fork, "a different root at the same tree size"
			return res, nil
		case head.TreeSize == state.LastSize:
			res.Verdict = NoChange
			return res, nil
		}
		var p proofResponse
		q := url.Values{"kind": {"consistency"}, "old": {strconv.FormatUint(state.LastSize, 10)},
			"new": {strconv.FormatUint(head.TreeSize, 10)}}
		if err := c.get(ctx, "/api/transparency/proof", q, &p); err != nil {
			return res, err
		}
		if p.Proof == nil {
			return res, errors.New("witness: consistency response has no proof")
		}
		proof, err := merkle.ParseHashes(p.Proof)
		if err != nil {
			res.Verdict, res.Reason, res.Proof = Fork, "malformed consistency proof: "+err.Error(), p.Proof
			return res, nil
		}
		if err := merkle.VerifyConsistency(state.LastSize, head.TreeSize, oldRoot, newRoot, proof); err != nil {
			res.Verdict, res.Reason, res.Proof = Fork, err.Error(), p.Proof
			return res, nil
		}
	}

	var sub struct {
		WitnessCount int `json:"witnessCount"`
	}
	body := map[string]string{
		"witnessId":    cfg.WitnessID,
		"signature":    sth.EncodeSignature(ed25519.Sign(cfg.Key, canonical)),
		"sthCanonical": string(canonical),
	}
	if cfg.PublicKeyURL != "" {
		body["publicKeyUrl"] = cfg.PublicKeyURL
	}
	if err := c.post(ctx, "/api/transparency/witness", body, &sub); err != nil {
		return res, err
	}
	// The log accepted the cosignature: this head is now the reference
	// every later head must be consistent with.
	if err := SaveState(cfg.StatePath, State{
		LogID: head.LogID, LastSize: head.TreeSize, LastRoot: head.RootHash,
		LastTimestamp: head.Timestamp, LastSubmittedAt: sth.FormatTime(now()),
	}); err != nil {
		return res, err
	}
	res.Verdict, res.WitnessCount = Witnessed, sub.WitnessCount
	return res, nil
}
