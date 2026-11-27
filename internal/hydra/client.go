// Package hydra talks to Hydra's admin API v2 through the official SDK
// (github.com/ory/hydra-client-go), and shapes the same models for the login
// apps on the emulated API. The dispatcher is the only one to call Hydra.
package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/Cadoles/hydra-dispatcher-go/internal/config"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"github.com/Cadoles/hydra-dispatcher-go/internal/loglevel"
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
	maxCause = httpx.MaxCause
	// readyTTL is how long Ready reuses Hydra's answer.
	readyTTL = time.Second
	// userAgent is the dispatcher's, on every call.
	userAgent = "hydra-dispatcher-go"
)

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
	// server is the error document of a 5xx (serverCause), a server's free text.
	server string
	err    error
	// elapsed is how long the call ran.
	elapsed time.Duration
}

func (e *UnavailableError) Error() string {
	msg := e.Op + ": " + ErrUnavailable.Error()
	if e.Status != 0 {
		msg += fmt.Sprintf(": status %d", e.Status)
	}
	msg += e.detail + e.server
	if text := httpx.BoundedCause(e.cause()); text != "" {
		msg += ": " + text
	}
	return msg
}

func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }

func (e *UnavailableError) Unwrap() error { return e.err }

// Failure is what the log says of a failed call (hydra.request_failed): its
// operation, the status of the answer, 0 when none came, and the cause, at most
// maxCause. Not the error document of a 5xx: serverCause only masks the values of the
// request's query, and the free text of a server or a gateway may quote a sid or a
// subject, which the log never holds (Journalisation).
func Failure(err error) (op string, status int, cause string) {
	var unavailable *UnavailableError
	var request *RequestError
	switch {
	case errors.As(err, &unavailable):
		cause = strings.TrimSpace(unavailable.detail)
		if text := unavailable.cause(); text != "" {
			if cause != "" {
				cause += ": "
			}
			cause += text
		}
		return unavailable.Op, unavailable.Status, httpx.BoundedCause(cause)
	case errors.As(err, &request):
		return request.Op, request.Status, ""
	}
	return "", 0, ""
}

// cause is what Failure and Error keep of the error of a call. An answer of 300 and up,
// read whole, is named by its status alone: the text of its status line, which read and
// the SDK repeat, is a server's. Go's libraries cite what they could not read, a line
// that is no HTTP, a Location, a Content-Length, a date, an element: that, and what
// follows, stays out (Q64, Q67).
func (e *UnavailableError) cause() string {
	if e.err == nil {
		return ""
	}
	if _, answered := errorBody(e.err); answered && e.Status >= 300 {
		return strings.TrimSpace(fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status)))
	}
	return httpx.Uncited(e.err.Error())
}

// Elapsed is how long a failed call ran (hydra.request_abandoned), 0 when it was not
// made.
func Elapsed(err error) time.Duration {
	var unavailable *UnavailableError
	if errors.As(err, &unavailable) {
		return unavailable.elapsed
	}
	return 0
}

// RequestError is a 4xx answer: an unknown challenge (404), an expired one
// (401, from Hydra 2.2 on), a refused body (400), or, from Hydra 2.1 only, a
// request already handled: 410 with redirect_to on a read, 409 on a second
// accept or a reject. Body is Hydra's error document, forwarded as is to
// login apps on the emulated API.
type RequestError struct {
	Op     string
	Status int
	Body   []byte
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("hydra %s: status %d", e.Op, e.Status)
}

// RedirectTo returns where Hydra 2.1 sends a request it already handled
// (410), or "".
func (e *RequestError) RedirectTo() string {
	var doc map[string]json.RawMessage
	if e.Status != http.StatusGone || json.Unmarshal(e.Body, &doc) != nil {
		return ""
	}
	return stringMember(doc, "redirect_to")
}

// Observer watches the calls: their operation, the class of their answer and how long
// they ran, then the calls refused or past their delay. It must not block.
type Observer interface {
	HydraCall(ctx context.Context, op, statusClass string, elapsed time.Duration)
	HydraRejected(reason string)
}

// The classes of an answer, and why a call is rejected, for Observer.
const (
	Class2xx      = "2xx"
	Class4xx      = "4xx"
	Class5xx      = "5xx"
	ClassError    = "error"
	ClassCanceled = "canceled"

	RejectedLimit   = "limit"
	RejectedTimeout = "timeout"
)

// statusClass is the class of the answer err tells of: canceled when the client left
// (Q67), error for no answer or an unexpected one.
func statusClass(err error) string {
	var request *RequestError
	var unavailable *UnavailableError
	switch {
	case err == nil:
		return Class2xx
	case errors.Is(err, context.Canceled):
		return ClassCanceled
	case errors.As(err, &request):
		return Class4xx
	case errors.As(err, &unavailable) && unavailable.Status >= 500:
		return Class5xx
	}
	return ClassError
}

// Client calls the admin API with one shared transport and a cap on
// concurrent calls.
type Client struct {
	// Observer, nil for none, is set before the first call.
	Observer Observer
	// Log, nil for none, gets hydra.request at the level debug for each call
	// (Q132): its operation, its status, its duration, the flow and the app of
	// its request; never a challenge nor a body. Set before the first call.
	Log *slog.Logger

	oauth2   ory.OAuth2API
	metadata ory.MetadataAPI
	// http and admin make the reads (see read), on the SDK's HTTP client.
	http     *http.Client
	admin    string
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
// closed after 30 s (httpx.IdleConnTimeout, Q84), before Hydra closes it after
// 120 s (ory/graceful's default) and before a balancer in front of it does:
// Go never replays a PUT sent on a connection the server is closing, and the
// final accept would be lost. Over HTTP/2, a connection silent for
// hydra.timeout gets a ping, and is closed if it stays unanswered for 2 s: a
// Hydra node gone without a reset would otherwise take every call multiplexed
// on it until TCP gives up.
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
	cfg.UserAgent = userAgent
	api := ory.NewAPIClient(cfg)
	return &Client{
		oauth2:    api.OAuth2API,
		metadata:  api.MetadataAPI,
		http:      cfg.HTTPClient,
		admin:     cfg.Servers[0].URL,
		inFlight:  make(chan struct{}, h.MaxInFlight),
		readySlot: make(chan struct{}, 1),
	}, nil
}

// newTransport builds the transport New describes. It takes no proxy from
// the environment: the admin API, without authentication, carries subjects
// and claims.
func newTransport(h config.Hydra, t config.TLS) (*http.Transport, error) {
	tlsConfig, err := httpx.ClientTLS(t.MinVersion, t.CAFile)
	if err != nil {
		return nil, fmt.Errorf("tls.ca_file: %w", err)
	}
	return &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: h.Timeout.Std(), PingTimeout: httpx.PingTimeout},
		MaxIdleConns:        h.MaxInFlight,
		MaxIdleConnsPerHost: h.MaxInFlight,
		IdleConnTimeout:     httpx.IdleConnTimeout,
	}, nil
}

// hydraTransport sends the request's trace id along, so Hydra's logs (which
// carry the request headers) join the dispatcher's, its traceparent when tracing is on,
// which Hydra's own traces attach to, and bounds the answers.
type hydraTransport struct{ base http.RoundTripper }

func (t hydraTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if id := httpx.TraceID(r.Context()); id != "" {
		r.Header.Set("X-Trace-ID", id)
	}
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	resp, err := t.base.RoundTrip(r)
	if err == nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, maxBody)
	}
	return resp, err
}

// call runs one admin API call under the in-flight cap and classifies its
// error. op is a stable operation name, used in errors, logs and metrics.
func call[T any](c *Client, ctx context.Context, op string, do func() (T, *http.Response, error)) (T, error) {
	var zero T
	select {
	case c.inFlight <- struct{}{}:
		defer func() { <-c.inFlight }()
	default:
		if c.Observer != nil {
			c.Observer.HydraRejected(RejectedLimit)
		}
		return zero, fmt.Errorf("%s: %w", op, ErrOverloaded)
	}
	start := time.Now()
	v, resp, err := do()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if c.Log != nil && c.Log.Enabled(ctx, slog.LevelDebug) {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		c.Log.DebugContext(ctx, "hydra.request", append([]any{"operation", op, "status", status, "duration_ms", time.Since(start).Milliseconds()},
			loglevel.ScopeAttrs(ctx)...)...)
	}
	if err == nil {
		if c.Observer != nil {
			c.Observer.HydraCall(ctx, op, Class2xx, time.Since(start))
		}
		return v, nil
	}
	failure := classify(op, resp, err)
	elapsed := time.Since(start)
	var unavailable *UnavailableError
	if errors.As(failure, &unavailable) {
		unavailable.elapsed = elapsed
	}
	if c.Observer != nil {
		c.Observer.HydraCall(ctx, op, statusClass(failure), elapsed)
		if errors.Is(failure, context.DeadlineExceeded) {
			c.Observer.HydraRejected(RejectedTimeout)
		}
	}
	return zero, failure
}

// InFlight returns the number of calls running, for hydra_in_flight.
func (c *Client) InFlight() int { return len(c.inFlight) }

// classify turns the error of a call into an UnavailableError or a
// RequestError. A 4xx is a RequestError only with Hydra's error document: a
// 404 page from elsewhere (Hydra's public port, a proxy), a gateway's refusal
// or a body cut short is a broken setup or network, not an unknown challenge.
func classify(op string, resp *http.Response, err error) error {
	unavailable := &UnavailableError{Op: op, err: withoutURL(err)}
	if resp == nil { // no answer: refused, timed out, cancelled
		return unavailable
	}
	unavailable.Status = resp.StatusCode
	body, read := errorBody(err)
	switch {
	case resp.StatusCode < 300: // a 2xx not decoded, incomplete or cut short
	case !read: // the body of any other answer is read whole first
		unavailable.detail = " while reading the body"
	case resp.StatusCode >= 500:
		unavailable.server = serverCause(resp, body)
	case resp.StatusCode < 400: // a redirect
	case !hydraError(resp.StatusCode, body):
		unavailable.detail = " without Hydra's error document"
	default:
		return &RequestError{Op: op, Status: resp.StatusCode, Body: body}
	}
	return unavailable
}

// statusError is an answer other than a 2xx to a read, its body read whole,
// as the SDK's GenericOpenAPIError carries it for the other calls.
type statusError struct {
	status string
	body   []byte
}

func (e *statusError) Error() string { return e.status }

// errorBody returns the body of an answer other than a 2xx, and whether it
// was read whole.
func errorBody(err error) ([]byte, bool) {
	var apiErr *ory.GenericOpenAPIError
	var statusErr *statusError
	switch {
	case errors.As(err, &apiErr):
		return apiErr.Body(), true
	case errors.As(err, &statusErr):
		return statusErr.body, true
	}
	return nil, false
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

// read is a GET of the admin API whose 2xx decode decodes, once: the SDK
// would decode it into its own model first, which refuses a client whose jwks
// has a key without alg, kid or use (see DecodeClient) and reads an XML
// Content-Type as XML. It goes through the SDK's HTTP client, transport and
// redirect policy included, as the SDK's own calls.
func read[T any](c *Client, ctx context.Context, op, path, param, challenge string, decode func([]byte) (*T, error)) (*T, error) {
	return call(c, ctx, op, func() (*T, *http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.admin+path+"?"+url.Values{param: {challenge}}.Encode(), nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, resp, err
		}
		body, err := io.ReadAll(resp.Body)
		switch {
		case err != nil:
			return nil, resp, err
		case resp.StatusCode >= 300:
			return nil, resp, &statusError{status: resp.Status, body: body}
		}
		v, err := decode(body)
		return v, resp, err
	})
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

// LoginRequest reads the login request of challenge.
func (c *Client) LoginRequest(ctx context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	return read(c, ctx, "get_login_request", "/admin/oauth2/auth/requests/login", "login_challenge", challenge, decodeLoginRequest)
}

// AcceptLogin accepts the login request and returns Hydra's redirect_to.
func (c *Client) AcceptLogin(ctx context.Context, challenge string, body ory.AcceptOAuth2LoginRequest) (string, error) {
	return call(c, ctx, "accept_login", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(body).Execute())
	})
}

func (c *Client) RejectLogin(ctx context.Context, challenge string, body ory.RejectOAuth2Request) (string, error) {
	return call(c, ctx, "reject_login", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.RejectOAuth2LoginRequest(ctx).LoginChallenge(challenge).RejectOAuth2Request(body).Execute())
	})
}

// ConsentRequest reads the consent request of challenge.
func (c *Client) ConsentRequest(ctx context.Context, challenge string) (*ory.OAuth2ConsentRequest, error) {
	return read(c, ctx, "get_consent_request", "/admin/oauth2/auth/requests/consent", "consent_challenge", challenge, decodeConsentRequest)
}

func (c *Client) AcceptConsent(ctx context.Context, challenge string, body ory.AcceptOAuth2ConsentRequest) (string, error) {
	return call(c, ctx, "accept_consent", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.AcceptOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(body).Execute())
	})
}

func (c *Client) RejectConsent(ctx context.Context, challenge string, body ory.RejectOAuth2Request) (string, error) {
	return call(c, ctx, "reject_consent", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.RejectOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).RejectOAuth2Request(body).Execute())
	})
}

// LogoutRequest reads the logout request of challenge.
func (c *Client) LogoutRequest(ctx context.Context, challenge string) (*ory.OAuth2LogoutRequest, error) {
	return read(c, ctx, "get_logout_request", "/admin/oauth2/auth/requests/logout", "logout_challenge", challenge, decodeLogoutRequest)
}

func (c *Client) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	return call(c, ctx, "accept_logout", func() (string, *http.Response, error) {
		return redirectTo(c.oauth2.AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute())
	})
}

func (c *Client) RejectLogout(ctx context.Context, challenge string) error {
	_, err := call(c, ctx, "reject_logout", func() (struct{}, *http.Response, error) {
		resp, err := c.oauth2.RejectOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
		return struct{}{}, resp, err
	})
	return err
}

// RevokeLoginSession deletes a session of login, which sends its back-channel: 204,
// again if it is gone (HLO-11, HLO-18). For a chain of logout that stopped (SKP-12).
func (c *Client) RevokeLoginSession(ctx context.Context, sid string) error {
	_, err := call(c, ctx, "revoke_login_session", func() (struct{}, *http.Response, error) {
		resp, err := c.oauth2.RevokeOAuth2LoginSessions(ctx).Sid(sid).Execute()
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
