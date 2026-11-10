package admin

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

const (
	clientID     = "admin-client"
	clientSecret = "s3cret-of-the-client"
)

// snapshots is a configuration that a test changes.
type snapshots struct {
	mu sync.Mutex
	s  *store.Snapshot
}

func (f *snapshots) Snapshot() *store.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.s
}

func (f *snapshots) set(clients ...store.APIClient) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s = store.NewSnapshot(nil, nil, store.DefaultSettings()).WithAPIClients(clients)
}

// clientHash is at the lowest cost of bcrypt, for the tests to go fast; the
// unknown client is compared to a hash of the default cost.
var clientHash = sync.OnceValue(func() string {
	h, err := bcrypt.GenerateFromPassword(domain.BcryptInput(clientSecret), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
})

// rig is an admin API behind the RealIP of serve, with a clock and what its
// hooks and its log saw.
type rig struct {
	api     *API
	handler http.Handler
	config  *snapshots
	now     time.Time
	logs    bytes.Buffer
	tokens  []string // client result reason
	refused atomic.Int32
	limited atomic.Int32
	mu      sync.Mutex
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{config: &snapshots{}, now: time.Unix(1_800_000_000, 0)}
	r.config.set(
		store.APIClient{ID: clientID, SecretHash: clientHash(), Scopes: []string{ScopeFlows, ScopeApps}},
		store.APIClient{ID: "reader", SecretHash: clientHash(), Scopes: []string{ScopeRead}},
	)
	r.api = mustNew(t, Options{
		Keys:            mustKeys(t, pkcs8(t, ecKey(t, elliptic.P256())), ""),
		Config:          r.config,
		Issuer:          issuer,
		TokenTTL:        15 * time.Minute,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		RatePerMinute:   100,
		Logger:          slog.New(slog.NewJSONHandler(&r.logs, nil)),
		LogSample:       httpx.NewSampler(time.Minute),
		Refused:         func(context.Context) { r.refused.Add(1) },
		RateLimited:     func(context.Context) { r.limited.Add(1) },
		Token: func(_ context.Context, client, result, reason string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.tokens = append(r.tokens, strings.TrimSpace(client+" "+result+" "+reason))
		},
		Now: func() time.Time {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.now
		},
	})
	ok := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, _ := CallerOf(req.Context())
		writeJSON(w, http.StatusOK, map[string]any{"client": c.Client, "scopes": c.Scopes})
	})
	r.api.Handle("GET /admin/v1/apps", Apps, ok)
	r.api.Handle("POST /admin/v1/apps", Apps, ok)
	r.api.Handle("POST /admin/v1/oauth2-clients", Clients, ok)
	mux := http.NewServeMux()
	r.api.Register(mux)
	r.handler = httpx.Chain(mux, httpx.RealIP([]netip.Prefix{netip.MustParsePrefix("10.0.0.10/32")}))
	return r
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = r.now.Add(d)
}

// do sends a request from addr (ip:port), with the headers given as name, value.
func (r *rig) do(method, path, addr, body string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = addr
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, req)
	return w
}

const admin = "10.1.2.3:4567"

func form(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

func (r *rig) tokenForm(body string) *httptest.ResponseRecorder {
	return r.do(http.MethodPost, "/admin/v1/token", admin, body, "Content-Type", "application/x-www-form-urlencoded")
}

func (r *rig) tokenJSON(body string) *httptest.ResponseRecorder {
	return r.do(http.MethodPost, "/admin/v1/token", admin, body, "Content-Type", "application/json")
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return m
}

// accessToken obtains a token of client, with scope ("" for all).
func (r *rig) accessToken(t *testing.T, client, scope string) string {
	t.Helper()
	w := r.tokenForm(form("grant_type", "client_credentials", "client_id", client, "client_secret", clientSecret, "scope", scope))
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	return decode(t, w)["access_token"].(string)
}

// The cases of TokenControllerTest of Symfony, with the deviations of the
// plan: an unknown client described as a wrong secret, an address outside the
// allowlist in 403.
func TestToken(t *testing.T) {
	r := newRig(t)
	valid := []string{"grant_type", "client_credentials", "client_id", clientID, "client_secret", clientSecret}
	with := func(kv ...string) []string { return append(append([]string{}, valid...), kv...) }

	w := r.tokenForm(form(valid...))
	body := decode(t, w)
	if w.Code != http.StatusOK || body["token_type"] != "Bearer" || len(strings.Split(body["access_token"].(string), ".")) != 3 ||
		body["expires_in"] != float64(900) || body["scope"] != "admin:flows admin:apps" {
		t.Errorf("form: %d %v", w.Code, body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("headers: %v", w.Header())
	}
	if w := r.tokenJSON(`{"grant_type":"client_credentials","client_id":"` + clientID + `","client_secret":"` + clientSecret + `"}`); w.Code != http.StatusOK {
		t.Errorf("JSON: %d %s", w.Code, w.Body)
	}
	for name, tt := range map[string]struct {
		w      *httptest.ResponseRecorder
		status int
		error  string
		scope  string
	}{
		"scope intersected":       {r.tokenForm(form(with("scope", "admin:flows")...)), 200, "", "admin:flows"},
		"scope of another client": {r.tokenForm(form(with("scope", "admin:clients")...)), 400, "invalid_scope", ""},
		"scope trimmed":           {r.tokenForm(form(with("scope", "  admin:flows  ")...)), 200, "", "admin:flows"},
		"scopes and spaces":       {r.tokenForm(form(with("scope", "admin:flows  admin:apps")...)), 200, "", "admin:flows admin:apps"},
		"scopes intersected":      {r.tokenForm(form(with("scope", "admin:apps admin:clients")...)), 200, "", "admin:apps"},
		"scope twice":             {r.tokenForm(form(with("scope", "admin:apps admin:apps")...)), 200, "", "admin:apps"},
		"wrong secret":            {r.tokenForm(form("grant_type", "client_credentials", "client_id", clientID, "client_secret", "nope")), 401, "invalid_client", ""},
		"unknown client":          {r.tokenForm(form("grant_type", "client_credentials", "client_id", "nobody", "client_secret", clientSecret)), 401, "invalid_client", ""},
		"other grant":             {r.tokenForm(form("grant_type", "password", "client_id", clientID, "client_secret", clientSecret)), 400, "unsupported_grant_type", ""},
		"no client_id":            {r.tokenForm(form("grant_type", "client_credentials", "client_secret", clientSecret)), 400, "invalid_request", ""},
		"no client_secret":        {r.tokenForm(form("grant_type", "client_credentials", "client_id", clientID)), 400, "invalid_request", ""},
		"grant_type a number":     {r.tokenJSON(`{"grant_type":123,"client_id":"` + clientID + `","client_secret":"` + clientSecret + `"}`), 400, "unsupported_grant_type", ""},
		"not JSON":                {r.tokenJSON(`grant_type=client_credentials`), 400, "unsupported_grant_type", ""},
		"credentials in the URL":  {r.do(http.MethodPost, "/admin/v1/token?"+form(valid...), admin, "", "Content-Type", "application/x-www-form-urlencoded"), 400, "unsupported_grant_type", ""},
		"body too large":          {r.tokenForm(form(with("scope", strings.Repeat("a", maxBody))...)), 400, "unsupported_grant_type", ""},
		"address not allowed":     {r.do(http.MethodPost, "/admin/v1/token", "203.0.113.7:1", form(valid...), "Content-Type", "application/x-www-form-urlencoded"), 403, "request_forbidden", ""},
	} {
		got := decode(t, tt.w)
		if tt.w.Code != tt.status || tt.error != "" && got["error"] != tt.error || tt.scope != "" && got["scope"] != tt.scope {
			t.Errorf("%s: %d %v", name, tt.w.Code, got)
		}
	}
	// One bcrypt whether the client exists or not: the dummy hash for an
	// unknown one (revue R34).
	var compared []string
	saved := secretMatches
	secretMatches = func(hash, secret string) bool { compared = append(compared, hash); return saved(hash, secret) }
	r.tokenForm(form("grant_type", "client_credentials", "client_id", "nobody", "client_secret", "x"))
	secretMatches = saved
	if len(compared) != 1 || compared[0] != dummyHash() {
		t.Errorf("an unknown client compared %d hashes", len(compared))
	}
	// One description whether the client exists or not.
	unknown := decode(t, r.tokenForm(form("grant_type", "client_credentials", "client_id", "nobody", "client_secret", "x")))
	wrong := decode(t, r.tokenForm(form("grant_type", "client_credentials", "client_id", clientID, "client_secret", "x")))
	if unknown["error_description"] != wrong["error_description"] {
		t.Errorf("descriptions differ: %v, %v", unknown, wrong)
	}
	// A hash of too high a cost, written by hand in the database: refused at
	// once, never computed (revue R33).
	costly := strings.Replace(clientHash(), "$04$", "$31$", 1)
	r.config.set(store.APIClient{ID: "costly", SecretHash: costly, Scopes: []string{ScopeRead}})
	start := time.Now()
	if w := r.tokenForm(form("grant_type", "client_credentials", "client_id", "costly", "client_secret", clientSecret)); w.Code != http.StatusUnauthorized || time.Since(start) > 5*time.Second {
		t.Errorf("hash of cost 31: %d after %v", w.Code, time.Since(start))
	}
	if got := Warnings(r.config.Snapshot().APIClients); len(got) != 1 || !strings.HasPrefix(got[0], "API client costly: its secret is hashed at a bcrypt cost over 14") {
		t.Errorf("warnings = %q", got)
	}
	if w := r.do(http.MethodGet, "/admin/v1/token", admin, ""); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" ||
		decode(t, w)["status"] != float64(405) {
		t.Errorf("GET /token: %d %v", w.Code, w.Header())
	}
	if w := r.do(http.MethodDelete, "/admin/v1/apps", admin, ""); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD, POST" {
		t.Errorf("DELETE /apps: %d %v", w.Code, w.Header())
	}
	if w := r.do(http.MethodGet, "/admin/v1/nope", admin, ""); w.Code != http.StatusNotFound || decode(t, w)["status"] != float64(404) {
		t.Errorf("unknown path: %d %s", w.Code, w.Body)
	}
	// A client_id no client can have goes to the audit as a marker, whatever
	// its size (revue R34): the body may hold 64 KiB of it.
	r.advance(2 * rateWindow) // a new count of the rate limit
	r.mu.Lock()
	before := len(r.tokens)
	r.mu.Unlock()
	for _, id := range []string{strings.Repeat("\x01", 20000), strings.Repeat("a", 129), "a/b", "\xff"} {
		r.tokenForm(form("grant_type", "client_credentials", "client_id", id))
	}
	r.mu.Lock()
	if told := r.tokens[before:]; len(told) != 4 || slices.ContainsFunc(told, func(s string) bool { return !strings.HasPrefix(s, "(invalid) refused ") }) {
		t.Errorf("tokens told: %.300q", told)
	}
	r.mu.Unlock()

	// The audit is told of each token, granted or refused, never of a secret.
	r.mu.Lock()
	tokens := strings.Join(r.tokens, "\n")
	r.mu.Unlock()
	for _, want := range []string{clientID + " granted", "nobody refused invalid_client", clientID + " refused invalid_scope", "refused invalid_request"} {
		if !strings.Contains(tokens, want) {
			t.Errorf("no %q in the tokens told:\n%s", want, tokens)
		}
	}
	if strings.Contains(r.logs.String(), clientSecret) || strings.Contains(r.logs.String(), "eyJ") {
		t.Errorf("a secret or a token in the logs: %s", r.logs.String())
	}
}

// The cases of BearerTokenAuthenticatorTest of Symfony, the client read in the
// configuration of the moment (Q101) and the scopes checked (Q96).
func TestBearer(t *testing.T) {
	r := newRig(t)
	token := r.accessToken(t, clientID, "")
	bearer := func(method, path, token string) *httptest.ResponseRecorder {
		return r.do(method, path, admin, "", "Authorization", "Bearer "+token)
	}
	w := bearer(http.MethodGet, "/admin/v1/apps", token)
	if body := decode(t, w); w.Code != http.StatusOK || body["client"] != clientID {
		t.Errorf("valid token: %d %v", w.Code, body)
	}
	// The claims of the token.
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil || claims["sub"] != clientID || claims["iss"] != issuer ||
		claims["exp"].(float64) <= float64(r.now.Unix()) || claims["jti"] == "" || claims["iat"] == nil {
		t.Errorf("claims %v, %v", claims, err)
	}

	parts := strings.Split(token, ".")
	for name, tt := range map[string]struct {
		header string
		desc   string
	}{
		"no token":           {"", "Authentication required."},
		"another scheme":     {"Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)), "Authentication required."},
		"malformed":          {"Bearer not-a-jwt", "Invalid or expired token."},
		"tampered signature": {"Bearer " + parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])), "Invalid or expired token."},
	} {
		req := []string{}
		if tt.header != "" {
			req = []string{"Authorization", tt.header}
		}
		w := r.do(http.MethodGet, "/admin/v1/apps", admin, "", req...)
		if body := decode(t, w); w.Code != http.StatusUnauthorized || body["error"] != "invalid_token" || body["error_description"] != tt.desc ||
			!strings.HasPrefix(w.Header().Get("WWW-Authenticate"), `Bearer realm="Dispatcher Admin API"`) {
			t.Errorf("%s: %d %v %q", name, w.Code, body, w.Header().Get("WWW-Authenticate"))
		}
	}
	// The scheme in any case.
	if w := r.do(http.MethodGet, "/admin/v1/apps", admin, "", "Authorization", "bearer "+token); w.Code != http.StatusOK {
		t.Errorf("bearer in lowercase: %d", w.Code)
	}
	// Expired.
	r.advance(15*time.Minute + clockSkew + time.Second)
	if w := bearer(http.MethodGet, "/admin/v1/apps", token); w.Code != http.StatusUnauthorized {
		t.Errorf("expired: %d", w.Code)
	}
	token = r.accessToken(t, clientID, "")

	// A scope the token lacks: 403, the scope expected named.
	w = bearer(http.MethodPost, "/admin/v1/oauth2-clients", token)
	if body := decode(t, w); w.Code != http.StatusForbidden || body["error"] != "insufficient_scope" ||
		w.Header().Get("WWW-Authenticate") != `Bearer realm="Dispatcher Admin API", error="insufficient_scope", scope="admin:clients"` {
		t.Errorf("insufficient scope: %d %v %q", w.Code, body, w.Header().Get("WWW-Authenticate"))
	}
	// admin:read reads, never writes.
	read := r.accessToken(t, "reader", "")
	if w := bearer(http.MethodGet, "/admin/v1/apps", read); w.Code != http.StatusOK {
		t.Errorf("admin:read reads: %d", w.Code)
	}
	if w := bearer(http.MethodPost, "/admin/v1/apps", read); w.Code != http.StatusForbidden {
		t.Errorf("admin:read writes: %d", w.Code)
	}
	// A token of fewer scopes than its client keeps them.
	flowsOnly := r.accessToken(t, clientID, ScopeFlows)
	if w := bearer(http.MethodPost, "/admin/v1/apps", flowsOnly); w.Code != http.StatusForbidden {
		t.Errorf("a token without admin:apps: %d", w.Code)
	}

	// A scope removed from the client is removed from its tokens; a client
	// deleted loses the access at once.
	r.config.set(store.APIClient{ID: clientID, SecretHash: clientHash(), Scopes: []string{ScopeFlows}})
	if w := bearer(http.MethodPost, "/admin/v1/apps", token); w.Code != http.StatusForbidden {
		t.Errorf("scope removed: %d", w.Code)
	}
	r.config.set()
	w = bearer(http.MethodGet, "/admin/v1/apps", token)
	if body := decode(t, w); w.Code != http.StatusUnauthorized || body["error_description"] != "Client not found." {
		t.Errorf("deleted client: %d %v", w.Code, body)
	}
}

// The rate limit: 100 requests a minute and per address, /token included,
// after the allowlist, its headers on each answer.
func TestRateLimit(t *testing.T) {
	r := newRig(t)
	for i := range 100 {
		w := r.do(http.MethodGet, "/admin/v1/apps", admin, "")
		if w.Code != http.StatusUnauthorized || w.Header().Get("X-RateLimit-Remaining") != strconv.Itoa(99-i) {
			t.Fatalf("request %d: %d, remaining %s", i, w.Code, w.Header().Get("X-RateLimit-Remaining"))
		}
		if reset := w.Header().Get("X-RateLimit-Reset"); reset != strconv.FormatInt(r.now.Add(rateWindow).Unix(), 10) {
			t.Fatalf("request %d: reset %s", i, reset)
		}
	}
	w := r.tokenForm(form("grant_type", "client_credentials", "client_id", clientID, "client_secret", clientSecret))
	if body := decode(t, w); w.Code != http.StatusTooManyRequests || body["error"] != "rate_limit_exceeded" ||
		// At 60 s, the previous window still weighs in full: 61 s.
		w.Header().Get("Retry-After") != "61" || w.Header().Get("X-RateLimit-Remaining") != "0" || r.limited.Load() != 1 {
		t.Errorf("over the limit: %d %v %v", w.Code, body, w.Header())
	}
	// Another address has its own count; one outside the allowlist none.
	if w := r.do(http.MethodGet, "/admin/v1/apps", "10.9.9.9:1", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("another address: %d", w.Code)
	}
	for range 3 {
		if w := r.do(http.MethodGet, "/admin/v1/apps", "203.0.113.7:1", ""); w.Code != http.StatusForbidden || w.Header().Get("X-RateLimit-Remaining") != "" {
			t.Errorf("outside the allowlist: %d %v", w.Code, w.Header())
		}
	}
	if r.refused.Load() != 3 || strings.Count(r.logs.String(), `"msg":"security.ip_rejected"`) != 1 {
		t.Errorf("refusals told %d, logs:\n%s", r.refused.Load(), r.logs.String())
	}
	// Half a window after the first: the previous count weighs half.
	r.advance(rateWindow + rateWindow/2)
	passed := 0
	for range 100 {
		if r.do(http.MethodGet, "/admin/v1/apps", admin, "").Code != http.StatusTooManyRequests {
			passed++
		}
	}
	if passed != 50 {
		t.Errorf("%d passed half a window later, want 50", passed)
	}
	// Two windows later, all again.
	r.advance(2 * rateWindow)
	if w := r.do(http.MethodGet, "/admin/v1/apps", admin, ""); w.Header().Get("X-RateLimit-Remaining") != "99" {
		t.Errorf("two windows later: remaining %s", w.Header().Get("X-RateLimit-Remaining"))
	}
}

// The allowlist reads the address of the client, X-Forwarded-For from the
// trusted proxies only.
func TestAllowlistBehindProxies(t *testing.T) {
	r := newRig(t)
	for name, tt := range map[string]struct {
		addr, xff string
		status    int
	}{
		"proxy, admin behind":       {"10.0.0.10:1", "10.1.2.3", http.StatusUnauthorized},
		"proxy, outsider behind":    {"10.0.0.10:1", "203.0.113.5", http.StatusForbidden},
		"outsider claiming a hop":   {"203.0.113.9:1", "10.1.2.3", http.StatusForbidden},
		"admin, a hop not believed": {"10.1.2.3:1", "203.0.113.5", http.StatusUnauthorized},
	} {
		if w := r.do(http.MethodGet, "/admin/v1/apps", tt.addr, "", "X-Forwarded-For", tt.xff); w.Code != tt.status {
			t.Errorf("%s: %d, want %d", name, w.Code, tt.status)
		}
	}
	if w := r.do(http.MethodGet, "/admin/v1", "203.0.113.9:1", ""); w.Code != http.StatusForbidden {
		t.Errorf("/admin/v1 itself: %d", w.Code)
	}
}

func TestRetryAt(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	for name, tt := range map[string]struct {
		w    window
		now  time.Time
		want time.Duration // after start
	}{
		"full window":            {window{start: start, cur: 100}, start.Add(10 * time.Second), rateWindow + rateWindow/100},
		"previous full":          {window{start: start, prev: 100, cur: 0}, start, rateWindow / 100},
		"previous half, current": {window{start: start, prev: 100, cur: 49}, start, rateWindow / 2},
		"already free":           {window{start: start, prev: 10}, start.Add(time.Second), time.Second},
	} {
		if got := tt.w.retryAt(tt.now, 100).Sub(start); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}

// mustNew is New, failing the test on an error.
func mustNew(t testing.TB, o Options) *API {
	t.Helper()
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
