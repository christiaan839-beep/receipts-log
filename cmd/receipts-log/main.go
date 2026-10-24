// Command receipts-log runs a transparency log for verifiable-receipts
// receipts, its witness, and a few client commands. Run
// "receipts-log help" for usage.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/logclient"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/server"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/store"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
	"github.com/christiaan839-beep/receipts-log/internal/witness"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes, as in the verifiable-receipts CLIs, and one for check.
const (
	exitOK            = 0
	exitFail          = 1 // verification failed or fork detected
	exitUsage         = 2 // usage, configuration or network error
	exitNonconforming = 3 // check -issuer-key: the store is intact, but holds receipts admission now refuses
)

const usage = `receipts-log: a transparency log and witness for verifiable-receipts receipts.

Usage:
  receipts-log serve    -data DIR -log-id ID -log-key FILE -issuer-key FILE [flags]
  receipts-log witness  -url URL -key FILE -witness-id ID -log-public-key FILE [-once] [flags]
  receipts-log keygen   -out FILE [-pub FILE]
  receipts-log pubkey   -key FILE
  receipts-log append   -url URL -file RECEIPT.json
  receipts-log sth      -url URL -log-public-key FILE
  receipts-log prove    -url URL -file RECEIPT.json -log-public-key FILE
  receipts-log check    -data DIR -log-id ID -log-public-key FILE [-issuer-key FILE]
  receipts-log version

Run "receipts-log <command> -h" for a command's flags. The serve and
witness flags that name files, identifiers, addresses and the log level
can also be set with environment variables; -h names each one.

check -issuer-key (repeatable, as for serve) also verifies every stored
receipt as the server admits receipts now, and lists those it refuses.

Exit codes: 0 success, 1 verification failed or fork detected (for check,
a corrupt store), 2 usage, configuration or network error, 3 check found
stored receipts that the current admission rules refuse (the store is
otherwise intact).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := exitOK
	switch cmd {
	case "serve":
		err = cmdServe(rest, stderr)
	case "witness":
		code, err = cmdWitness(rest, stdout, stderr)
	case "keygen":
		err = cmdKeygen(rest, stdout, stderr)
	case "pubkey":
		err = cmdPubkey(rest, stdout, stderr)
	case "append":
		code, err = cmdAppend(rest, stdout, stderr)
	case "sth":
		code, err = cmdSTH(rest, stdout, stderr)
	case "prove":
		code, err = cmdProve(rest, stdout, stderr)
	case "check":
		code, err = cmdCheck(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if code == exitOK {
			code = exitUsage
		}
	}
	return code
}

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// envDefault returns the environment value of name, or def.
func envDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func envList(name string) listFlag {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	var out listFlag
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("-log-level: %w", err)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})), nil
}

func cmdServe(args []string, stderr io.Writer) error {
	fs := newFlags("serve", stderr)
	addr := fs.String("addr", envDefault("RECEIPTS_LOG_ADDR", ":8080"), "listen address (RECEIPTS_LOG_ADDR)")
	data := fs.String("data", envDefault("RECEIPTS_LOG_DATA", ""), "data directory (RECEIPTS_LOG_DATA)")
	logID := fs.String("log-id", envDefault("RECEIPTS_LOG_ID", ""), "log identifier carried in every tree head (RECEIPTS_LOG_ID)")
	logKey := fs.String("log-key", envDefault("RECEIPTS_LOG_KEY_FILE", ""), "PKCS #8 PEM Ed25519 key that signs tree heads (RECEIPTS_LOG_KEY_FILE)")
	issuers := envList("RECEIPTS_LOG_ISSUER_KEYS")
	fs.Var(&issuers, "issuer-key", "SPKI PEM Ed25519 issuer public key; repeat for several (RECEIPTS_LOG_ISSUER_KEYS, comma-separated)")
	witnesses := envList("RECEIPTS_LOG_WITNESS_KEYS")
	fs.Var(&witnesses, "witness-key", "NAME=FILE: a witness ID and its SPKI PEM public key; repeat for several (RECEIPTS_LOG_WITNESS_KEYS, comma-separated)")
	maxEntry := fs.Int("max-entry-bytes", store.DefaultMaxPayload, "largest receipt accepted, in bytes")
	sthInterval := fs.Duration("sth-interval", time.Hour, "re-sign the tree head this often when idle (0 disables)")
	maxInFlight := fs.Int("max-in-flight", server.DefaultMaxInFlight, "concurrent requests before 503")
	tlsCert := fs.String("tls-cert", envDefault("RECEIPTS_LOG_TLS_CERT", ""), "TLS certificate file; serve HTTPS when set with -tls-key (RECEIPTS_LOG_TLS_CERT)")
	tlsKey := fs.String("tls-key", envDefault("RECEIPTS_LOG_TLS_KEY", ""), "TLS key file (RECEIPTS_LOG_TLS_KEY)")
	level := fs.String("log-level", envDefault("RECEIPTS_LOG_LEVEL", "info"), "debug, info, warn or error (RECEIPTS_LOG_LEVEL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger, err := newLogger(stderr, *level)
	if err != nil {
		return err
	}
	if *data == "" || *logID == "" || *logKey == "" || len(issuers) == 0 {
		return errors.New("serve needs -data, -log-id, -log-key and at least one -issuer-key")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	key, insecure, err := keys.LoadPrivateKey(*logKey)
	if err != nil {
		return fmt.Errorf("-log-key: %w", err)
	}
	if insecure {
		logger.Warn("log key file is readable by group or others; restrict it to the server's user", "path", *logKey)
	}
	issuerKeys, err := loadIssuerKeys(issuers)
	if err != nil {
		return err
	}
	witnessKeys := map[string]ed25519.PublicKey{}
	for _, w := range witnesses {
		name, path, ok := strings.Cut(w, "=")
		if !ok || name == "" || path == "" {
			return fmt.Errorf("-witness-key %q: want NAME=FILE", w)
		}
		k, err := keys.LoadPublicKey(path)
		if err != nil {
			return fmt.Errorf("-witness-key %s: %w", name, err)
		}
		witnessKeys[name] = k
	}

	l, err := translog.Open(translog.Config{
		Dir: *data, LogID: *logID, Key: key, IssuerKeys: issuerKeys,
		WitnessKeys: witnessKeys, MaxEntryBytes: *maxEntry, Logger: logger,
	})
	if err != nil {
		return err
	}
	defer l.Close()
	srv, err := server.New(l, server.Options{MaxEntryBytes: *maxEntry, MaxInFlight: *maxInFlight, Logger: logger})
	if err != nil {
		return err
	}
	hs := server.HTTPServer(*addr, srv.Handler(), logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *sthInterval > 0 {
		go func() {
			t := time.NewTicker(*sthInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if h, err := l.RefreshSTH(); err != nil {
						logger.Error("tree head refresh failed", "err", err)
					} else {
						logger.Debug("tree head refreshed", "treeSize", h.TreeSize, "timestamp", h.Timestamp)
					}
				}
			}
		}()
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *addr, "tls", *tlsCert != "", "version", version)
		if *tlsCert != "" {
			errc <- hs.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := hs.Shutdown(sctx); err != nil {
			return err
		}
	}
	return nil
}

// loadIssuerKeys loads the -issuer-key files of serve and check.
func loadIssuerKeys(paths []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, p := range paths {
		k, err := keys.LoadPublicKey(p)
		if err != nil {
			return nil, fmt.Errorf("-issuer-key: %w", err)
		}
		out = append(out, k)
	}
	return out, nil
}

func defaultStatePath(witnessID string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '.' || r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, witnessID)
	if len(safe) > 100 {
		safe = safe[:100]
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".sovereign-witness", safe+".json")
}

func cmdWitness(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("witness", stderr)
	base := fs.String("url", envDefault("RECEIPTS_WITNESS_URL", ""), "log base URL (RECEIPTS_WITNESS_URL)")
	keyPath := fs.String("key", envDefault("RECEIPTS_WITNESS_KEY_FILE", ""), "witness PKCS #8 PEM Ed25519 key (RECEIPTS_WITNESS_KEY_FILE)")
	id := fs.String("witness-id", envDefault("RECEIPTS_WITNESS_ID", ""), "witness ID the log knows this witness by (RECEIPTS_WITNESS_ID)")
	logPub := fs.String("log-public-key", envDefault("RECEIPTS_WITNESS_LOG_PUBLIC_KEY", ""), "the log's SPKI PEM public key (RECEIPTS_WITNESS_LOG_PUBLIC_KEY)")
	pubURL := fs.String("public-key-url", envDefault("RECEIPTS_WITNESS_PUBLIC_KEY_URL", ""), "where this witness publishes its public key (RECEIPTS_WITNESS_PUBLIC_KEY_URL)")
	statePath := fs.String("state", envDefault("RECEIPTS_WITNESS_STATE", ""), "state file (default ~/.sovereign-witness/<witness-id>.json) (RECEIPTS_WITNESS_STATE)")
	once := fs.Bool("once", false, "check once and exit")
	interval := fs.Duration("interval", time.Hour, "poll interval in daemon mode (at least 1m)")
	jsonOut := fs.Bool("json", false, "print one JSON result per check")
	level := fs.String("log-level", envDefault("RECEIPTS_LOG_LEVEL", "info"), "debug, info, warn or error (RECEIPTS_LOG_LEVEL)")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	logger, err := newLogger(stderr, *level)
	if err != nil {
		return exitUsage, err
	}
	if *base == "" || *keyPath == "" || *id == "" || *logPub == "" {
		return exitUsage, errors.New("witness needs -url, -key, -witness-id and -log-public-key")
	}
	key, insecure, err := keys.LoadPrivateKey(*keyPath)
	if err != nil {
		return exitUsage, fmt.Errorf("-key: %w", err)
	}
	if insecure {
		logger.Warn("witness key file is readable by group or others", "path", *keyPath)
	}
	lk, err := keys.LoadPublicKey(*logPub)
	if err != nil {
		return exitUsage, fmt.Errorf("-log-public-key: %w", err)
	}
	if *statePath == "" {
		*statePath = defaultStatePath(*id)
	}
	cfg := witness.Config{BaseURL: strings.TrimRight(*base, "/"), WitnessID: *id, PublicKeyURL: *pubURL,
		Key: key, LogKey: lk, StatePath: *statePath}

	check := func(ctx context.Context) (int, error) {
		res, err := witness.RunOnce(ctx, cfg)
		if err != nil {
			return exitUsage, err
		}
		if *jsonOut {
			out, _ := json.Marshal(res)
			fmt.Fprintln(stdout, string(out))
		}
		switch res.Verdict {
		case witness.Fork:
			logger.Error("FORK DETECTED: the log is not consistent with the last tree head this witness signed",
				"logId", res.LogID, "oldSize", res.OldSize, "oldRoot", res.OldRoot,
				"treeSize", res.TreeSize, "rootHash", res.RootHash, "reason", res.Reason,
				"sthCanonical", res.STHCanonical, "sthSignature", res.STHSignature)
			return exitFail, nil
		case witness.NoChange:
			logger.Info("no change since the last check", "treeSize", res.TreeSize)
		default:
			logger.Info("witnessed", "treeSize", res.TreeSize, "rootHash", res.RootHash,
				"oldSize", res.OldSize, "witnessCount", res.WitnessCount)
		}
		return exitOK, nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		return check(ctx)
	}
	if *interval < time.Minute {
		*interval = time.Minute
	}
	logger.Info("witness daemon started", "url", cfg.BaseURL, "interval", interval.String())
	for {
		code, err := check(ctx)
		if code == exitFail {
			logger.Error("halting: operator action required")
			return exitFail, nil
		}
		if err != nil {
			logger.Warn("check failed; will retry", "err", err)
		}
		select {
		case <-ctx.Done():
			return exitOK, nil
		case <-time.After(*interval):
		}
	}
}

func cmdKeygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("keygen", stderr)
	out := fs.String("out", "", "write the new private key here (mode 0600; never overwrites)")
	pubOut := fs.String("pub", "", "also write the public key here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen needs -out")
	}
	key, err := keys.Generate(*out)
	if err != nil {
		return err
	}
	pem, err := keys.PublicKeyPEM(key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	if *pubOut != "" {
		if err := os.WriteFile(*pubOut, pem, 0o644); err != nil {
			return err
		}
	}
	_, err = stdout.Write(pem)
	return err
}

func cmdPubkey(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("pubkey", stderr)
	keyPath := fs.String("key", "", "private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("pubkey needs -key")
	}
	key, _, err := keys.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	pem, err := keys.PublicKeyPEM(key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	_, err = stdout.Write(pem)
	return err
}

// fetchSTH fetches and verifies the log's latest tree head. A head that
// fails verification is exitFail; any other error is exitUsage.
func fetchSTH(c *logclient.Client, logKey ed25519.PublicKey) (sth.STH, int, error) {
	head, _, err := c.FetchSTH(context.Background(), logKey)
	if errors.Is(err, sth.ErrSignature) || errors.Is(err, sth.ErrInvalid) {
		return sth.STH{}, exitFail, err
	}
	if err != nil {
		return sth.STH{}, exitUsage, err
	}
	return head, exitOK, nil
}

func cmdAppend(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("append", stderr)
	base := fs.String("url", "", "log base URL")
	file := fs.String("file", "", "receipt JSON file")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *base == "" || *file == "" {
		return exitUsage, errors.New("append needs -url and -file")
	}
	body, err := os.ReadFile(*file)
	if err != nil {
		return exitUsage, err
	}
	c, err := logclient.New(*base, nil)
	if err != nil {
		return exitUsage, err
	}
	var out json.RawMessage
	err = c.Post(context.Background(), "/v1/entries", body, &out)
	var se *logclient.StatusError
	switch {
	case err == nil:
		fmt.Fprintln(stdout, string(out))
		return exitOK, nil
	case errors.As(err, &se):
		stdout.Write(se.Body)
		if se.Status == http.StatusUnprocessableEntity || se.Status == http.StatusBadRequest {
			return exitFail, fmt.Errorf("log refused the receipt: HTTP %d", se.Status)
		}
		return exitUsage, fmt.Errorf("HTTP %d", se.Status)
	default:
		return exitUsage, err
	}
}

func cmdSTH(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("sth", stderr)
	base := fs.String("url", "", "log base URL")
	logPub := fs.String("log-public-key", "", "the log's SPKI PEM public key")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *base == "" || *logPub == "" {
		return exitUsage, errors.New("sth needs -url and -log-public-key")
	}
	lk, err := keys.LoadPublicKey(*logPub)
	if err != nil {
		return exitUsage, err
	}
	c, err := logclient.New(*base, nil)
	if err != nil {
		return exitUsage, err
	}
	head, code, err := fetchSTH(c, lk)
	if err != nil {
		return code, err
	}
	out, _ := json.MarshalIndent(head, "", "  ")
	fmt.Fprintln(stdout, string(out))
	return exitOK, nil
}

func cmdProve(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("prove", stderr)
	base := fs.String("url", "", "log base URL")
	file := fs.String("file", "", "receipt JSON file")
	logPub := fs.String("log-public-key", "", "the log's SPKI PEM public key")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *base == "" || *file == "" || *logPub == "" {
		return exitUsage, errors.New("prove needs -url, -file and -log-public-key")
	}
	lk, err := keys.LoadPublicKey(*logPub)
	if err != nil {
		return exitUsage, err
	}
	body, err := os.ReadFile(*file)
	if err != nil {
		return exitUsage, err
	}
	leaf, err := translog.LeafForReceipt(body)
	if err != nil {
		return exitUsage, err
	}
	c, err := logclient.New(*base, nil)
	if err != nil {
		return exitUsage, err
	}
	head, code, err := fetchSTH(c, lk)
	if err != nil {
		return code, err
	}
	if head.TreeSize == 0 {
		return exitFail, errors.New("the log is empty")
	}
	var p struct {
		LeafIndex uint64   `json:"leafIndex"`
		TreeSize  uint64   `json:"treeSize"`
		AuditPath []string `json:"auditPath"`
	}
	q := url.Values{"leafHash": {leaf.String()}, "treeSize": {fmt.Sprint(head.TreeSize)}}
	err = c.Get(context.Background(), "/v1/proof/inclusion", q, &p)
	if logclient.IsStatus(err, http.StatusNotFound) {
		return exitFail, errors.New("the receipt is not in the log")
	}
	if err != nil {
		return exitUsage, err
	}
	if p.TreeSize != head.TreeSize {
		return exitFail, errors.New("the proof is for a different tree size")
	}
	path, err := merkle.ParseHashes(p.AuditPath)
	if err != nil {
		return exitFail, err
	}
	root, _ := head.Root() // FetchSTH verified the head, root included
	if err := merkle.VerifyInclusion(leaf, p.LeafIndex, head.TreeSize, path, root); err != nil {
		return exitFail, fmt.Errorf("inclusion proof rejected: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"included": true, "leafHash": leaf.String(), "leafIndex": p.LeafIndex,
		"treeSize": head.TreeSize, "rootHash": head.RootHash, "sthTimestamp": head.Timestamp,
		"sthSignature": head.Signature,
	}, "", "  ")
	fmt.Fprintln(stdout, string(out))
	return exitOK, nil
}

func cmdCheck(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("check", stderr)
	data := fs.String("data", "", "data directory")
	logID := fs.String("log-id", "", "log identifier")
	logPub := fs.String("log-public-key", "", "the log's SPKI PEM public key")
	var issuers listFlag
	fs.Var(&issuers, "issuer-key", "SPKI PEM Ed25519 issuer public key, as for serve; repeat for several. "+
		"Also verify every stored receipt under these keys and list those admission now refuses (exit 3)")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *data == "" || *logID == "" || *logPub == "" {
		return exitUsage, errors.New("check needs -data, -log-id and -log-public-key")
	}
	lk, err := keys.LoadPublicKey(*logPub)
	if err != nil {
		return exitUsage, err
	}
	issuerKeys, err := loadIssuerKeys(issuers)
	if err != nil {
		return exitUsage, err
	}
	rep, err := translog.Check(*data, *logID, lk, translog.CheckOptions{IssuerKeys: issuerKeys})
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Fprintln(stdout, string(out))
	if err != nil {
		return exitFail, err
	}
	if n := rep.NonconformingCount; n != nil && *n > 0 {
		shown := ""
		if uint64(len(rep.Nonconforming)) < *n {
			shown = fmt.Sprintf(" (the first %d are listed)", len(rep.Nonconforming))
		}
		return exitNonconforming, fmt.Errorf("%d stored receipt(s) fail the current admission rules%s",
			*n, shown)
	}
	return exitOK, nil
}
