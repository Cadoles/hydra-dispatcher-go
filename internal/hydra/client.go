// Package hydra talks to Hydra's admin API v2 through the official SDK
// (github.com/ory/hydra-client-go), and shapes the same models for the login
// apps on the emulated API. The dispatcher is the only one to call Hydra.
package hydra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

var (
	// ErrUnavailable covers network errors, timeouts, 5xx and unexpected
	// answers: error E1004 for the user.
	ErrUnavailable = errors.New("hydra unavailable")
	// ErrOverloaded means hydra.max_in_flight calls are already running: the
	// caller answers 503 with Retry-After instead of queueing.
	ErrOverloaded = errors.New("hydra overloaded: too many calls in flight")

	// errEmptyAnswer is a 2xx without a body, or with null: the SDK decodes
	// it as a nil model without an error.
	errEmptyAnswer = errors.New("empty answer")
)

const (
	// maxBody bounds Hydra's answers: a login request with its client
	// weighs a few KiB.
	maxBody = 1 << 20
	// readyTTL is how long Ready reuses Hydra's answer.
	readyTTL = time.Second
)

// tls12Suites are the TLS 1.2 suites the ANSSI TLS guide recommends: ECDHE
// with an AEAD. Go still enables ECDHE with AES-CBC-SHA by default. TLS 1.3
// suites are all AEAD and not configurable.
var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// RequestError is a 4xx answer: an unknown or expired challenge (404), a
// request already handled (410, with redirect_to), or a refused body. Body is
// Hydra's error document, forwarded as is to login apps on the emulated API.
type RequestError struct {
	Op     string
	Status int
	Body   []byte
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("hydra %s: status %d", e.Op, e.Status)
}

// RedirectTo returns where Hydra sends a request it already handled (410),
// or "".
func (e *RequestError) RedirectTo() string {
	var body struct {
		RedirectTo string `json:"redirect_to"`
	}
	if e.Status != http.StatusGone || json.Unmarshal(e.Body, &body) != nil {
		return ""
	}
	return body.RedirectTo
}

// Client calls the admin API with one shared transport and a cap on
// concurrent calls.
type Client struct {
	oauth2   ory.OAuth2API
	metadata ory.MetadataAPI
	inFlight chan struct{}

	// readySlot lets one readiness probe call Hydra at a time; readyAt and
	// readyErr, its last answer, are only touched while holding it.
	readySlot chan struct{}
	readyAt   time.Time
	readyErr  error
}

// New builds the client: 2 s to connect, 2 s more for the TLS handshake,
// hydra.timeout per call, TLS per the tls section. Hydra is called directly
// on the internal network: no proxy from the environment, no redirect
// followed. Connections are kept alive and reused (Go's default of 2 idle
// connections per host would open a connection per call under load); their
// number is bounded by hydra.max_in_flight alone, as a lower limit in the
// transport would queue the calls the cap let through.
func New(h config.Hydra, t config.TLS) (*Client, error) {
	tlsConfig, err := clientTLS(t)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        h.MaxInFlight,
		MaxIdleConnsPerHost: h.MaxInFlight,
		IdleConnTimeout:     90 * time.Second,
	}
	cfg := ory.NewConfiguration()
	// The SDK appends /admin/...: a trailing slash would give //admin/...,
	// which Hydra redirects.
	cfg.Servers = ory.ServerConfigurations{{URL: strings.TrimRight(h.AdminURL, "/")}}
	cfg.HTTPClient = &http.Client{
		Transport: hydraTransport{transport},
		Timeout:   h.Timeout.Std(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cfg.UserAgent = "hydra-dispatcher-go"
	api := ory.NewAPIClient(cfg)
	return &Client{
		oauth2:    api.OAuth2API,
		metadata:  api.MetadataAPI,
		inFlight:  make(chan struct{}, h.MaxInFlight),
		readySlot: make(chan struct{}, 1),
	}, nil
}

func clientTLS(t config.TLS) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: tls12Suites}
	if t.MinVersion == "1.3" {
		c.MinVersion = tls.VersionTLS13
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, err
		}
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.ca_file: no certificate in %s", t.CAFile)
		}
	}
	return c, nil
}

// hydraTransport sends the request's trace id along, so Hydra's logs (which
// carry the request headers) join the dispatcher's, and bounds the answers.
// traceparent waits for OpenTelemetry: without the caller's sampling flag, a
// made-up one would decide Hydra's sampling.
type hydraTransport struct{ base http.RoundTripper }

func (t hydraTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if id := httpx.TraceID(r.Context()); id != "" {
		r = r.Clone(r.Context())
		r.Header.Set("X-Trace-ID", id)
	}
	resp, err := t.base.RoundTrip(r)
	if err == nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, maxBody)
	}
	return resp, err
}

// call runs one admin API call under the in-flight cap and classifies its
// error. op is a stable operation name, used in errors, logs and metrics.
func call[T any](c *Client, op string, do func() (T, *http.Response, error)) (T, error) {
	var zero T
	select {
	case c.inFlight <- struct{}{}:
		defer func() { <-c.inFlight }()
	default:
		return zero, fmt.Errorf("%s: %w", op, ErrOverloaded)
	}
	v, resp, err := do()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		return v, nil
	}
	return zero, classify(op, resp, err)
}

// classify turns an SDK error into ErrUnavailable or a RequestError. A 4xx
// is a RequestError only with Hydra's error document: a 404 page from
// elsewhere (Hydra's public port, a proxy) or a body cut short is a broken
// setup or network, not an unknown challenge.
func classify(op string, resp *http.Response, err error) error {
	err = withoutURL(err)
	switch {
	case resp == nil: // no answer: refused, timed out, cancelled
		return fmt.Errorf("%s: %w: %v", op, ErrUnavailable, err)
	case resp.StatusCode >= 500 || resp.StatusCode < 400: // includes a 2xx the SDK could not decode, and redirects
		return fmt.Errorf("%s: %w: status %d: %v", op, ErrUnavailable, resp.StatusCode, err)
	}
	var apiErr *ory.GenericOpenAPIError
	if !errors.As(err, &apiErr) || !hydraError(apiErr.Body()) {
		return fmt.Errorf("%s: %w: status %d without Hydra's error document: %v", op, ErrUnavailable, resp.StatusCode, err)
	}
	return &RequestError{Op: op, Status: resp.StatusCode, Body: apiErr.Body()}
}

// withoutURL drops the request URL net/http puts in its errors: its query
// carries the challenge, which never goes to the logs.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// hydraError reports whether body is one of Hydra's error documents: an
// OAuth2 error, or the redirect_to of a request already handled.
func hydraError(body []byte) bool {
	var doc struct {
		Error      json.RawMessage `json:"error"`
		RedirectTo json.RawMessage `json:"redirect_to"`
	}
	return json.Unmarshal(body, &doc) == nil && (doc.Error != nil || doc.RedirectTo != nil)
}

// present refuses the nil model the SDK returns, without an error, for an
// empty or null 2xx body.
func present[T any](v *T, resp *http.Response, err error) (*T, *http.Response, error) {
	if err == nil && v == nil {
		err = errEmptyAnswer
	}
	return v, resp, err
}

func redirectTo(r *ory.OAuth2RedirectTo, resp *http.Response, err error) (string, *http.Response, error) {
	if err != nil {
		return "", resp, err
	}
	if r == nil || r.RedirectTo == "" {
		return "", resp, errEmptyAnswer
	}
	return r.RedirectTo, resp, nil
}

func (c *Client) LoginRequest(ctx context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	return call(c, "get_login_request", func() (*ory.OAuth2LoginRequest, *http.Response, error) {
		return present(c.oauth2.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute())
	})
}

// AcceptLogin accepts the login request and returns Hydra's redirect_to.
func (c *Client) AcceptLogin(ctx context.Context, challenge string, body ory.AcceptOAuth2LoginRequest) (string, error) {
	return call(c, "accept_login", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(body).Execute())
	})
}

func (c *Client) RejectLogin(ctx context.Context, challenge string, body ory.RejectOAuth2Request) (string, error) {
	return call(c, "reject_login", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.RejectOAuth2LoginRequest(ctx).LoginChallenge(challenge).RejectOAuth2Request(body).Execute())
	})
}

func (c *Client) ConsentRequest(ctx context.Context, challenge string) (*ory.OAuth2ConsentRequest, error) {
	return call(c, "get_consent_request", func() (*ory.OAuth2ConsentRequest, *http.Response, error) {
		return present(c.oauth2.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute())
	})
}

func (c *Client) AcceptConsent(ctx context.Context, challenge string, body ory.AcceptOAuth2ConsentRequest) (string, error) {
	return call(c, "accept_consent", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.AcceptOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(body).Execute())
	})
}

func (c *Client) RejectConsent(ctx context.Context, challenge string, body ory.RejectOAuth2Request) (string, error) {
	return call(c, "reject_consent", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.RejectOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).RejectOAuth2Request(body).Execute())
	})
}

func (c *Client) LogoutRequest(ctx context.Context, challenge string) (*ory.OAuth2LogoutRequest, error) {
	return call(c, "get_logout_request", func() (*ory.OAuth2LogoutRequest, *http.Response, error) {
		return present(c.oauth2.GetOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute())
	})
}

func (c *Client) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	return call(c, "accept_logout", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute())
	})
}

func (c *Client) RejectLogout(ctx context.Context, challenge string) error {
	_, err := call(c, "reject_logout", func() (struct{}, *http.Response, error) {
		resp, err := c.oauth2.RejectOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
		return struct{}{}, resp, err
	})
	return err
}

// Ready checks Hydra's readiness (database reachable), for /ready. It stays
// out of the in-flight cap: a full cap is load, not Hydra down, and must not
// take the instance out of the load balancer. /ready is outside every
// allowlist, so probes call Hydra one at a time and share its answer for
// readyTTL.
func (c *Client) Ready(ctx context.Context) error {
	select {
	case c.readySlot <- struct{}{}:
		defer func() { <-c.readySlot }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if time.Since(c.readyAt) < readyTTL {
		return c.readyErr
	}
	_, resp, err := c.metadata.IsReady(ctx).Execute()
	if err != nil {
		err = classify("ready", resp, err)
	}
	if ctx.Err() == nil { // Hydra's answer, not this probe giving up
		c.readyAt, c.readyErr = time.Now(), err
	}
	return err
}
