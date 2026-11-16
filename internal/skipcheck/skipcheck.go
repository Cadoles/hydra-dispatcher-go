// Package skipcheck calls the pre-check of a step (phase 4, Plan phase 4,
// P27 en détail): POST <skip_check_url>, signed by the app's key as a webhook
// is, within 300 ms; the answer taken only signed by the same key, over
// "response." first, the nonce of the request back, skip true. Anything else runs the step: the extension
// never blocks a login.
package skipcheck

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

const (
	// Timeout bounds a pre-check, from the connection to the last byte.
	Timeout = 300 * time.Millisecond
	// maxAnswer is the most of an answer read.
	maxAnswer = 64 << 10
	// skew is how far the time of an answer may be from the dispatcher's.
	skew = 5 * time.Minute

	// The headers of the signature, those of the webhooks.
	headerTimestamp = "X-Dispatcher-Timestamp"
	headerSignature = "X-Dispatcher-Signature"
)

// Snapshots gives the configuration of the moment: the app's URL, key and
// signals.
type Snapshots interface{ Snapshot() *store.Snapshot }

// Client makes the pre-checks.
type Client struct {
	config Snapshots
	http   *http.Client
	now    func() time.Time
}

// New returns the client, its TLS that of the webhooks (tls.min_version,
// webhooks.ca_file).
func New(config Snapshots, tlsConfig *tls.Config) *Client {
	return &Client{config: config, now: time.Now, http: &http.Client{
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: Timeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: Timeout,
			TLSClientConfig:     tlsConfig,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     httpx.IdleConnTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// request is what the app receives.
type request struct {
	Version     int            `json:"version"`
	Nonce       string         `json:"nonce"`
	Subject     string         `json:"subject"`
	Device      string         `json:"device"`
	ClientID    string         `json:"client_id"`
	Flow        string         `json:"flow"`
	Step        string         `json:"step"`
	Claims      map[string]any `json:"claims"`
	Signals     map[string]any `json:"signals"`
	Attestation *struct{}      `json:"attestation"`
}

// answer is what the app answers.
type answer struct {
	Nonce       string          `json:"nonce"`
	Skip        *bool           `json:"skip"`
	Subject     string          `json:"subject"`
	Context     json.RawMessage `json:"context"`
	IDToken     json.RawMessage `json:"id_token"`
	AccessToken json.RawMessage `json:"access_token"`
}

// Check makes the pre-check of call, ctx the browser's request, whose
// signals the app receives as it declares them.
func (c *Client) Check(ctx context.Context, call flow.SkipCheckCall) flow.SkipCheckAnswer {
	start := time.Now()
	fail := func(cause string) flow.SkipCheckAnswer {
		return flow.SkipCheckAnswer{Result: flow.SkipFailed, Cause: cause, Elapsed: time.Since(start)}
	}
	app, ok := c.config.Snapshot().App(call.App)
	if !ok || app.SkipCheckURL == "" {
		return fail("no_url")
	}
	key, err := domain.ParseKey(app.SkipCheckKey)
	if err != nil || key == nil {
		return fail("key")
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce) // crypto/rand never fails
	claims := call.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	now := c.now()
	body, err := json.Marshal(request{Version: 1, Nonce: hex.EncodeToString(nonce), Subject: call.Subject, Device: call.Device,
		ClientID: call.ClientID, Flow: call.Flow, Step: call.App, Claims: claims, Signals: signals(ctx, app.SkipCheckSignals, call.DeviceAt, now)})
	if err != nil {
		return fail("request")
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.SkipCheckURL, bytes.NewReader(body))
	if err != nil {
		return fail("request")
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hydra-dispatcher-go")
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerSignature, sign(key, ts, body))
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return fail("timeout")
		}
		return fail("unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fail("status")
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return fail("content_type")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	switch {
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return fail("timeout")
	case err != nil:
		return fail("read")
	case len(data) > maxAnswer:
		return fail("too_large")
	}
	rts := resp.Header.Get(headerTimestamp)
	t, err := strconv.ParseInt(rts, 10, 64)
	if err != nil || c.now().Sub(time.Unix(t, 0)).Abs() > skew {
		return fail("timestamp")
	}
	if !hmac.Equal([]byte(resp.Header.Get(headerSignature)), []byte(sign(key, responseLabel+rts, data))) {
		return fail("signature")
	}
	var a answer
	if json.Unmarshal(data, &a) != nil {
		return fail("form")
	}
	if !hmac.Equal([]byte(a.Nonce), []byte(hex.EncodeToString(nonce))) {
		return fail("nonce")
	}
	if a.Skip == nil || !*a.Skip {
		return flow.SkipCheckAnswer{Result: flow.SkipDeclined, Elapsed: time.Since(start)}
	}
	out := flow.SkipCheckAnswer{Skip: true, Subject: a.Subject, Result: flow.SkipSkipped}
	for _, o := range []struct {
		raw  json.RawMessage
		into *flow.Object
	}{{a.Context, &out.Context}, {a.IDToken, &out.IDToken}, {a.AccessToken, &out.AccessToken}} {
		if len(o.raw) == 0 || string(o.raw) == "null" {
			continue
		}
		if o.raw[0] != '{' || json.Unmarshal(o.raw, o.into) != nil {
			return fail("form")
		}
	}
	out.Elapsed = time.Since(start)
	return out
}

// responseLabel starts what the answer's signature covers: a request sent
// back as it came, its body and headers echoed, never passes for an answer
// (R50).
const responseLabel = "response."

// sign gives the signature of body at the time ts: hex(HMAC-SHA256(key,
// ts + "." + body)), as a webhook's; an answer's covers "response." + ts +
// "." + body.
func sign(key []byte, ts string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// signals are the signals of the browser the app declares, of the request
// ctx belongs to: the address truncated (ip) or whole (full_ip), the
// User-Agent, the client hints, the Accept-Language, the age of the device in
// seconds. An unknown one gives nothing.
func signals(ctx context.Context, declared []string, deviceAt int64, now time.Time) map[string]any {
	out := map[string]any{}
	for _, s := range declared {
		switch s {
		case "ip", "full_ip":
			if ip := httpx.ClientIP(ctx); ip.IsValid() {
				out["ip"] = ip.String()
				if s == "ip" {
					out["ip"] = truncated(ip).String()
				}
			}
		case "user_agent":
			out["user_agent"] = httpx.UserAgent(ctx)
		case "client_hints":
			hints := httpx.ClientHints(ctx)
			if hints == nil {
				hints = map[string]string{}
			}
			out["client_hints"] = hints
		case "accept_language":
			out["accept_language"] = httpx.AcceptLanguage(ctx)
		case "device_age":
			if deviceAt > 0 {
				out["device_age"] = int64(now.Sub(time.Unix(deviceAt, 0)) / time.Second)
			}
		}
	}
	return out
}

// truncated is the network of ip a pre-check sends for ip: /24 in IPv4, /48
// in IPv6.
func truncated(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p
}
