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

// StatusError is a response whose status is neither 200 nor 201. Its
// message names the method, the route and the status only; the body is
// left to the caller.
type StatusError struct {
	// Method and Route are the request's method and the route the
	// caller passed (such as "/v1/sth"), not the URL sent.
	Method, Route string
	Status        int
	// Body is the response body, at most 1 MiB.
	Body []byte
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %q: HTTP %d", e.Method, e.Route, e.Status)
}

func (c *Client) url(path string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	return u.String()
}

// Get sends GET route?q and decodes the JSON response into out.
func (c *Client) Get(ctx context.Context, route string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(route, q), nil)
	if err != nil {
		return fmt.Errorf("GET %q: %w", route, err)
	}
	return c.do(req, route, out)
}

// Post sends body as JSON to route and decodes the JSON response into
// out.
func (c *Client) Post(ctx context.Context, route string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(route, nil), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %q: %w", route, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, route, out)
}

// do sends req and decodes its response. Every error it returns names
// the request by its method and route, never by the URL it was sent to.
func (c *Client) do(req *http.Request, route string, out any) error {
	method := req.Method
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// A *url.Error prints the whole URL; keep only its cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s %q: %w", method, route, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("%s %q: reading the response: %w", method, route, err)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("%s %q: response larger than %d bytes", method, route, maxResponse)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &StatusError{Method: method, Route: route, Status: resp.StatusCode, Body: data}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %q: malformed response JSON", method, route)
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
