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
	"os"
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
)

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
}

// New builds the client: 2 s to connect, hydra.timeout per call, connections
// kept alive and reused (Go's default of 2 idle connections per host would
// open a connection per call under load), TLS per the tls section.
func New(h config.Hydra, t config.TLS) (*Client, error) {
	tlsConfig, err := clientTLS(t)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 256,
		MaxConnsPerHost:     256,
		IdleConnTimeout:     90 * time.Second,
	}
	cfg := ory.NewConfiguration()
	cfg.Servers = ory.ServerConfigurations{{URL: h.AdminURL}}
	cfg.HTTPClient = &http.Client{Transport: traceTransport{transport}, Timeout: h.Timeout.Std()}
	cfg.UserAgent = "hydra-dispatcher-go"
	api := ory.NewAPIClient(cfg)
	return &Client{
		oauth2:   api.OAuth2API,
		metadata: api.MetadataAPI,
		inFlight: make(chan struct{}, h.MaxInFlight),
	}, nil
}

func clientTLS(t config.TLS) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
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

// traceTransport sends the request's trace id along, so Hydra's logs and
// traces join the dispatcher's.
type traceTransport struct{ base http.RoundTripper }

func (t traceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if id := httpx.TraceID(r.Context()); id != "" {
		r = r.Clone(r.Context())
		r.Header.Set("X-Trace-ID", id)
	}
	return t.base.RoundTrip(r)
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

func classify(op string, resp *http.Response, err error) error {
	switch {
	case resp == nil: // no answer: refused, timed out, cancelled
		return fmt.Errorf("%s: %w: %v", op, ErrUnavailable, err)
	case resp.StatusCode >= 500 || resp.StatusCode < 400: // includes a 2xx the SDK could not decode
		return fmt.Errorf("%s: %w: status %d: %v", op, ErrUnavailable, resp.StatusCode, err)
	}
	reqErr := &RequestError{Op: op, Status: resp.StatusCode}
	var apiErr *ory.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		reqErr.Body = apiErr.Body()
	}
	return reqErr
}

func redirectTo(r *ory.OAuth2RedirectTo, resp *http.Response, err error) (string, *http.Response, error) {
	if err != nil || r == nil {
		return "", resp, err
	}
	return r.RedirectTo, resp, nil
}

func (c *Client) LoginRequest(ctx context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	return call(c, "get_login_request", c.oauth2.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute)
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
	return call(c, "get_consent_request", c.oauth2.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute)
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
	return call(c, "get_logout_request", c.oauth2.GetOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute)
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

// Ready checks Hydra's readiness (database reachable), for /ready.
func (c *Client) Ready(ctx context.Context) error {
	_, err := call(c, "ready", c.metadata.IsReady(ctx).Execute)
	return err
}
