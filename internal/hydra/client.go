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
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

var (
	// ErrUnavailable covers network errors, timeouts, 5xx and unexpected
	// answers: error E1004 for the user. Calls return it as an
	// *UnavailableError.
	ErrUnavailable = errors.New("hydra unavailable")
	// ErrOverloaded means hydra.max_in_flight calls are already running: the
	// caller answers 503 with Retry-After instead of queueing.
	ErrOverloaded = errors.New("hydra overloaded: too many calls in flight")

	// errEmptyAnswer is a 2xx without a body, or with null, where a model or
	// a redirect_to is expected.
	errEmptyAnswer = errors.New("empty answer")
	// errIncompleteAnswer is a 2xx request without a member every Hydra
	// request carries.
	errIncompleteAnswer = errors.New("incomplete answer")
)

const (
	// maxBody bounds Hydra's answers: a login request with its client
	// weighs a few KiB.
	maxBody = 1 << 20
	// maxCause bounds the part of a 5xx error document kept in the error.
	maxCause = 200
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

// UnavailableError is the ErrUnavailable of one call, with what the logs and
// the metrics need (hydra_requests_total's status_class,
// hydra_rejected_total's reason). The cause stays wrapped: context.Canceled
// when the caller gave up, context.DeadlineExceeded (and a net.Error timing
// out) past hydra.timeout or the caller's deadline.
type UnavailableError struct {
	Op string
	// Status is the status of the answer, 0 when none came.
	Status int
	detail string
	err    error
}

func (e *UnavailableError) Error() string {
	msg := e.Op + ": " + ErrUnavailable.Error()
	if e.Status != 0 {
		msg += fmt.Sprintf(": status %d", e.Status)
	}
	return msg + e.detail + ": " + e.err.Error()
}

func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }

func (e *UnavailableError) Unwrap() error { return e.err }

// RequestError is a 4xx answer: an unknown challenge (404), an expired one
// (401, from Hydra 2.2 on), a request already handled (410, with
// redirect_to), or a refused body. Body is Hydra's error document, forwarded
// as is to login apps on the emulated API.
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
	var doc map[string]json.RawMessage
	if e.Status != http.StatusGone || json.Unmarshal(e.Body, &doc) != nil {
		return ""
	}
	return stringMember(doc, "redirect_to")
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
// transport would queue the calls the cap let through. An idle connection is
// closed after 90 s, before Hydra closes it after 120 s (ory/graceful's
// default): Go never replays a PUT sent on a connection the server is
// closing, and the final accept would be lost. Over HTTP/2, a connection
// silent for hydra.timeout gets a ping, and is closed if it stays unanswered
// for 2 s: a Hydra node gone without a reset would otherwise take every call
// multiplexed on it until TCP gives up.
func New(h config.Hydra, t config.TLS) (*Client, error) {
	transport, err := newTransport(h, t)
	if err != nil {
		return nil, err
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

// newTransport builds the transport New describes. It takes no proxy from
// the environment: the admin API, without authentication, carries subjects
// and claims.
func newTransport(h config.Hydra, t config.TLS) (*http.Transport, error) {
	tlsConfig, err := clientTLS(t)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: h.Timeout.Std(), PingTimeout: 2 * time.Second},
		MaxIdleConns:        h.MaxInFlight,
		MaxIdleConnsPerHost: h.MaxInFlight,
		IdleConnTimeout:     90 * time.Second,
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

// InFlight returns the number of calls running, for hydra_in_flight.
func (c *Client) InFlight() int { return len(c.inFlight) }

// classify turns an SDK error into an UnavailableError or a RequestError. A
// 4xx is a RequestError only with Hydra's error document: a 404 page from
// elsewhere (Hydra's public port, a proxy), a gateway's refusal or a body cut
// short is a broken setup or network, not an unknown challenge.
func classify(op string, resp *http.Response, err error) error {
	unavailable := &UnavailableError{Op: op, err: withoutURL(err)}
	if resp == nil { // no answer: refused, timed out, cancelled
		return unavailable
	}
	unavailable.Status = resp.StatusCode
	var apiErr *ory.GenericOpenAPIError
	switch {
	case resp.StatusCode < 300: // a 2xx not decoded, incomplete or cut short
	case !errors.As(err, &apiErr): // the SDK reads any other body whole first
		unavailable.detail = " while reading the body"
	case resp.StatusCode >= 500:
		unavailable.detail = serverCause(resp, apiErr.Body())
	case resp.StatusCode < 400: // a redirect
	case !hydraError(resp.StatusCode, apiErr.Body()):
		unavailable.detail = " without Hydra's error document"
	default:
		return &RequestError{Op: op, Status: resp.StatusCode, Body: apiErr.Body()}
	}
	return unavailable
}

// serverCause returns " (error: error_description)" from the error document
// of a 5xx, or " (check: error; …)" from the failed checks of
// /health/ready, which the SDK's message leaves out, or "". It drops the
// request's query values, which a gateway may quote: the challenge never
// goes to the logs.
func serverCause(resp *http.Response, body []byte) string {
	var doc struct {
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
		Errors      json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	cause := doc.Error
	var checks map[string]string
	switch {
	case cause != "" && doc.Description != "":
		cause += ": " + doc.Description
	case cause == "" && json.Unmarshal(doc.Errors, &checks) == nil:
		for _, name := range slices.Sorted(maps.Keys(checks)) {
			cause += "; " + name + ": " + checks[name]
		}
		cause = strings.TrimPrefix(cause, "; ")
	}
	if cause == "" {
		return ""
	}
	if resp.Request != nil {
		for _, values := range resp.Request.URL.Query() {
			for _, v := range values {
				if v != "" {
					cause = strings.ReplaceAll(cause, v, "…")
					cause = strings.ReplaceAll(cause, url.QueryEscape(v), "…")
				}
			}
		}
	}
	if len(cause) > maxCause {
		cause = strings.ToValidUTF8(cause[:maxCause], "") + "…"
	}
	return " (" + cause + ")"
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

// hydraError reports whether a 4xx body is one of Hydra's error documents:
// an OAuth2 error, or on a 410 the redirect_to of a request already handled.
// Hydra's admin API has neither authentication nor rate limit: a 407 or 429
// comes from a gateway or proxy in front of it, even with a JSON error, and so
// does a 401 but for fosite's request_unauthorized, Hydra's answer from 2.2
// on to an expired login or consent request.
func hydraError(status int, body []byte) bool {
	if status == http.StatusProxyAuthRequired || status == http.StatusTooManyRequests {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return false
	}
	code := stringMember(doc, "error")
	if status == http.StatusUnauthorized {
		return code == "request_unauthorized"
	}
	return code != "" || status == http.StatusGone && stringMember(doc, "redirect_to") != ""
}

// stringMember returns the string member name of doc, or "". The name is
// matched exactly: a struct's fields would also take {"Error": …} or
// {"ERROR": …}, which Hydra never writes.
func stringMember(doc map[string]json.RawMessage, name string) string {
	var s string
	if json.Unmarshal(doc[name], &s) != nil {
		return ""
	}
	return s
}

// answer decodes the body of a 2xx with decode, in place of the SDK's model:
// the SDK refuses a client whose jwks has a key without alg, kid or use (see
// decodeClient), and decodes an XML Content-Type as XML. The SDK leaves the
// whole body in resp.Body, so its decoding error on a 2xx is moot; a body it
// could not read stays an error.
func answer[T any](resp *http.Response, err error, decode func([]byte) (*T, error)) (*T, *http.Response, error) {
	var apiErr *ory.GenericOpenAPIError
	if resp == nil || resp.StatusCode >= 300 || err != nil && !errors.As(err, &apiErr) {
		return nil, resp, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, err
	}
	v, err := decode(body)
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
		_, resp, err := c.oauth2.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute()
		return answer(resp, err, decodeLoginRequest)
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
		_, resp, err := c.oauth2.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute()
		return answer(resp, err, decodeConsentRequest)
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
		_, resp, err := c.oauth2.GetOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
		return answer(resp, err, decodeLogoutRequest)
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
// readyTTL. A call's error is always an UnavailableError: /health/ready has
// no 4xx, so whatever answers one, error document or not, is not Hydra's
// admin API.
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
		cause := err
		var reqErr *RequestError
		if err = classify("ready", resp, err); errors.As(err, &reqErr) {
			err = &UnavailableError{Op: "ready", Status: reqErr.Status, err: cause}
		}
	}
	if ctx.Err() == nil { // Hydra's answer, not this probe giving up
		c.readyAt, c.readyErr = time.Now(), err
	}
	return err
}
