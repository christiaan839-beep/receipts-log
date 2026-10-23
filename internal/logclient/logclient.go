// Package logclient sends the HTTP requests that the witness and the
// client commands make to a receipts log: JSON in, JSON out, with a
// bounded response size.
package logclient

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
	"strings"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/sth"
)

// maxResponse bounds every response body read.
const maxResponse = 1 << 20

// Client talks to one log.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a Client for the log at baseURL, which must be an http or
// https URL. A nil hc means a client with a 30 s timeout.
func New(baseURL string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("logclient: %q is not an http(s) URL", baseURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: u, http: hc}, nil
}

// StatusError is a response whose status is neither 200 nor 201.
type StatusError struct {
	Method, Path string
	Status       int
	// Body is the response body, at most 1 MiB.
	Body []byte
}

func (e *StatusError) Error() string {
	msg := strings.TrimSpace(string(e.Body))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Sprintf("%s %s: HTTP %d %s", e.Method, e.Path, e.Status, msg)
}

func (c *Client) url(path string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	return u.String()
}

// Get sends GET path?q and decodes the JSON response into out.
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path, q), nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// Post sends body as JSON to path and decodes the JSON response into out.
func (c *Client) Post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path, nil), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
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
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &StatusError{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, Body: data}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: malformed response: %v", req.Method, req.URL.Path, err)
	}
	return nil
}

// FetchSTH fetches the log's latest tree head from GET
// /api/transparency/sth and verifies it under logKey. It returns the
// head and its canonical string; an error wraps sth.ErrInvalid or
// sth.ErrSignature when the head itself is bad.
func (c *Client) FetchSTH(ctx context.Context, logKey ed25519.PublicKey) (sth.STH, []byte, error) {
	var resp sth.Response
	if err := c.Get(ctx, "/api/transparency/sth", nil, &resp); err != nil {
		return sth.STH{}, nil, err
	}
	head := resp.STH
	if err := sth.Verify(head, logKey); err != nil {
		return sth.STH{}, nil, fmt.Errorf("tree head rejected: %w", err)
	}
	canonical, _ := head.Canonical()
	if resp.Canonical != "" && resp.Canonical != string(canonical) {
		return sth.STH{}, nil, fmt.Errorf("%w: the log's canonical string does not match its tree head", sth.ErrInvalid)
	}
	return head, canonical, nil
}

// IsStatus reports whether err is a StatusError with the given status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == status
}
