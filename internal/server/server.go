// Package server is the HTTP API of the receipts log. API.md documents
// every route.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
)

// Defaults for Options.
const (
	DefaultMaxInFlight   = 256
	maxCosignatureBody   = 64 << 10
	maxProofQueryLen     = 2048
	defaultRequestTimout = 30 * time.Second
)

// Options configures the handler.
type Options struct {
	// MaxEntryBytes bounds a POST /v1/entries body; it should match the
	// log's entry limit.
	MaxEntryBytes int
	// MaxInFlight bounds concurrent requests; excess requests get 503.
	MaxInFlight int
	// RequestTimeout bounds each handler's work.
	RequestTimeout time.Duration
	// Logger receives one structured line per request.
	Logger *slog.Logger
}

// Server serves one log.
type Server struct {
	log    *translog.Log
	opts   Options
	logger *slog.Logger
	sem    chan struct{}
	pubPEM []byte
}

// New returns a Server for l.
func New(l *translog.Log, opts Options) (*Server, error) {
	if opts.MaxEntryBytes <= 0 {
		opts.MaxEntryBytes = 1 << 20
	}
	if opts.MaxInFlight <= 0 {
		opts.MaxInFlight = DefaultMaxInFlight
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = defaultRequestTimout
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	pubPEM, err := keys.PublicKeyPEM(l.PublicKey())
	if err != nil {
		return nil, err
	}
	return &Server{log: l, opts: opts, logger: logger, sem: make(chan struct{}, opts.MaxInFlight), pubPEM: pubPEM}, nil
}

// Handler returns the routed handler with its middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/entries", s.postEntry)
	mux.HandleFunc("GET /v1/entries/{index}", s.getEntry)
	mux.HandleFunc("GET /v1/sth", s.getSTH)
	mux.HandleFunc("GET /v1/proof/inclusion", s.getInclusion)
	mux.HandleFunc("GET /v1/proof/consistency", s.getConsistency)
	mux.HandleFunc("GET /v1/public-key", s.getPublicKey)
	mux.HandleFunc("POST /v1/cosignatures", s.postCosignature)
	mux.HandleFunc("GET /v1/cosignatures", s.getCosignatures)
	mux.HandleFunc("GET /healthz", s.getHealth)
	// The routes the verifiable-receipts witness CLI (bin/witness.mjs) calls.
	mux.HandleFunc("GET /api/transparency/sth", s.getSTH)
	mux.HandleFunc("GET /api/transparency/proof", s.getCompatProof)
	mux.HandleFunc("POST /api/transparency/witness", s.postCosignature)
	return s.middleware(jsonErrors(mux))
}

// jsonErrors answers the mux's own 404 and 405 responses with JSON.
func jsonErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		var allowed []string
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, p := mux.Handler(probe); p != "" {
				allowed = append(allowed, m)
			}
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not found")
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func requestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := requestID()
		sw := &statusWriter{ResponseWriter: w}
		h := sw.Header()
		h.Set("X-Request-Id", id)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic in handler", "requestId", id, "panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				if sw.status == 0 {
					writeError(sw, http.StatusInternalServerError, "internal error")
				}
			}
			s.logger.Info("request", "requestId", id, "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "bytes", sw.bytes, "durationMs", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr)
		}()
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			h.Set("Retry-After", "1")
			writeError(sw, http.StatusServiceUnavailable, "server is busy")
			return
		}
		if len(r.URL.RawQuery) > maxProofQueryLen {
			writeError(sw, http.StatusRequestURITooLong, "query string too long")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.opts.RequestTimeout)
		defer cancel()
		next.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSONBody reads a JSON request body of at most limit bytes.
func readJSONBody(w http.ResponseWriter, r *http.Request, limit int) ([]byte, bool) {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return nil, false
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", limit))
			return nil, false
		}
		writeError(w, http.StatusBadRequest, "could not read body")
		return nil, false
	}
	return body, true
}

func (s *Server) errorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, translog.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, err.Error()
	case errors.Is(err, translog.ErrInvalidReceipt), errors.Is(err, translog.ErrInvalidCosig):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, translog.ErrUnverified), errors.Is(err, translog.ErrWitnessSignature):
		return http.StatusUnprocessableEntity, err.Error()
	case errors.Is(err, translog.ErrUnknownWitness):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, translog.ErrForeignSTH):
		return http.StatusConflict, err.Error()
	case errors.Is(err, translog.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, translog.ErrRange):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, translog.ErrReadOnly), errors.Is(err, translog.ErrFull):
		return http.StatusServiceUnavailable, err.Error()
	}
	s.logger.Error("unexpected error", "err", err)
	return http.StatusInternalServerError, "internal error"
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	code, msg := s.errorStatus(err)
	writeError(w, code, msg)
}

// sthBody is the STH wire form with its canonical string.
func sthBody(h sth.STH) (sth.Response, error) { return sth.NewResponse(h) }

type appendResponse struct {
	Index     uint64       `json:"index"`
	LeafHash  string       `json:"leafHash"`
	Duplicate bool         `json:"duplicate"`
	STH       sth.Response `json:"sth"`
}

func (s *Server) postEntry(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSONBody(w, r, s.opts.MaxEntryBytes)
	if !ok {
		return
	}
	res, err := s.log.Append(body)
	if err != nil {
		s.fail(w, err)
		return
	}
	head, err := sthBody(res.STH)
	if err != nil {
		s.fail(w, err)
		return
	}
	status := http.StatusCreated
	if res.Duplicate {
		status = http.StatusOK
	} else {
		s.logger.Info("entry appended", "index", res.Index, "leafHash", res.Leaf.String(), "issuerKey", res.IssuerKey, "treeSize", res.STH.TreeSize)
	}
	writeJSON(w, status, appendResponse{Index: res.Index, LeafHash: res.Leaf.String(), Duplicate: res.Duplicate, STH: head})
}

// parseUint reads a decimal query value no larger than sth.MaxTreeSize.
func parseUint(v string) (uint64, bool) {
	if v == "" || len(v) > 16 {
		return 0, false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > sth.MaxTreeSize {
		return 0, false
	}
	return n, true
}

func (s *Server) getEntry(w http.ResponseWriter, r *http.Request) {
	i, ok := parseUint(r.PathValue("index"))
	if !ok {
		writeError(w, http.StatusBadRequest, "index must be a non-negative integer")
		return
	}
	e, err := s.log.Entry(i)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"index": e.Index, "leafHash": e.Leaf.String(), "receipt": e.Receipt})
}

func (s *Server) getSTH(w http.ResponseWriter, r *http.Request) {
	head, err := sthBody(s.log.STH())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, head)
}

type inclusionResponse struct {
	Kind        string   `json:"kind"`
	LogID       string   `json:"logId"`
	LeafHashHex string   `json:"leafHashHex"`
	LeafIndex   uint64   `json:"leafIndex"`
	TreeSize    uint64   `json:"treeSize"`
	AuditPath   []string `json:"auditPath"`
	RootHashHex string   `json:"rootHashHex"`
}

type consistencyResponse struct {
	Kind       string   `json:"kind"`
	LogID      string   `json:"logId"`
	OldSize    uint64   `json:"oldSize"`
	NewSize    uint64   `json:"newSize"`
	OldRootHex string   `json:"oldRootHex"`
	NewRootHex string   `json:"newRootHex"`
	Proof      []string `json:"proof"`
}

// optionalSize reads an optional size parameter; absent means latest (0).
func optionalSize(q string) (uint64, bool) {
	if q == "" {
		return 0, true
	}
	n, ok := parseUint(q)
	if !ok || n == 0 {
		return 0, false
	}
	return n, true
}

func (s *Server) inclusion(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size, ok := optionalSize(q.Get("treeSize"))
	if !ok {
		writeError(w, http.StatusBadRequest, "treeSize must be a positive integer")
		return
	}
	var index uint64
	switch {
	case q.Get("leafHash") != "" && q.Get("index") == "":
		leaf, err := merkle.ParseHash(q.Get("leafHash"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "leafHash must be 64 hex characters")
			return
		}
		i, err := s.log.IndexOf(leaf)
		if err != nil {
			s.fail(w, err)
			return
		}
		index = i
	case q.Get("index") != "" && q.Get("leafHash") == "":
		i, ok := parseUint(q.Get("index"))
		if !ok {
			writeError(w, http.StatusBadRequest, "index must be a non-negative integer")
			return
		}
		index = i
	default:
		writeError(w, http.StatusBadRequest, "give exactly one of index or leafHash")
		return
	}
	p, err := s.log.ProveInclusion(index, size)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inclusionResponse{
		Kind: "inclusion", LogID: s.log.LogID(), LeafHashHex: p.Leaf.String(), LeafIndex: p.Index,
		TreeSize: p.Size, AuditPath: merkle.HexHashes(p.Path), RootHashHex: p.Root.String(),
	})
}

func (s *Server) getInclusion(w http.ResponseWriter, r *http.Request) { s.inclusion(w, r) }

func (s *Server) consistency(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	first, ok := parseUint(q.Get("old"))
	if !ok {
		writeError(w, http.StatusBadRequest, "old must be a non-negative integer")
		return
	}
	second, ok := optionalSize(q.Get("new"))
	if !ok {
		writeError(w, http.StatusBadRequest, "new must be a positive integer")
		return
	}
	p, err := s.log.ProveConsistency(first, second)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, consistencyResponse{
		Kind: "consistency", LogID: s.log.LogID(), OldSize: p.First, NewSize: p.Second,
		OldRootHex: p.FirstRoot.String(), NewRootHex: p.SecondRoot.String(), Proof: merkle.HexHashes(p.Path),
	})
}

func (s *Server) getConsistency(w http.ResponseWriter, r *http.Request) { s.consistency(w, r) }

func (s *Server) getCompatProof(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("kind") {
	case "consistency":
		s.consistency(w, r)
	case "inclusion":
		s.inclusion(w, r)
	default:
		writeError(w, http.StatusBadRequest, "kind must be inclusion or consistency")
	}
}

func (s *Server) getPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.pubPEM)
}

type cosignRequest struct {
	WitnessID    string `json:"witnessId"`
	Signature    string `json:"signature"`
	STHCanonical string `json:"sthCanonical"`
	PublicKeyURL string `json:"publicKeyUrl"`
}

func (s *Server) postCosignature(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSONBody(w, r, maxCosignatureBody)
	if !ok {
		return
	}
	var req cosignRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object with witnessId, signature and sthCanonical")
		return
	}
	n, recorded, err := s.log.AddCosignature(req.WitnessID, req.STHCanonical, req.Signature, req.PublicKeyURL)
	if err != nil {
		s.fail(w, err)
		return
	}
	if recorded {
		s.logger.Info("cosignature recorded", "witnessId", req.WitnessID, "witnessCount", n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recorded": recorded, "firstForThisSth": recorded && n == 1, "witnessCount": n})
}

func (s *Server) getCosignatures(w http.ResponseWriter, r *http.Request) {
	size, ok := parseUint(r.URL.Query().Get("treeSize"))
	if !ok {
		writeError(w, http.StatusBadRequest, "treeSize must be a non-negative integer")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"treeSize": size, "cosignatures": s.log.Cosignatures(size, false)})
}

func (s *Server) getHealth(w http.ResponseWriter, r *http.Request) {
	if s.log.ReadOnly() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "readOnly": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "treeSize": s.log.STH().TreeSize})
}

// HTTPServer returns an http.Server with conservative limits.
func HTTPServer(addr string, h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}
