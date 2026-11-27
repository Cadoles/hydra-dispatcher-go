package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"github.com/Cadoles/hydra-dispatcher-go/internal/ratelimit"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// Prefix is the path of the admin API.
const Prefix = "/admin/v1"

// realm is that of WWW-Authenticate, Symfony's.
const realm = `Bearer realm="Dispatcher Admin API"`

// maxBody bounds the body of /token: three fields and a scope.
const maxBody = 64 << 10

// dummyHash is compared when the client is unknown, for /token to take the
// time of a known one: the answer does not tell which clients exist. Made at
// the first use: bcrypt is slow on purpose.
var dummyHash = sync.OnceValue(func() string {
	h, _ := domain.HashSecret("no client has this secret")
	return h
})

// Snapshots gives the configuration of the moment, API clients included:
// store.Live.
type Snapshots interface {
	Snapshot() *store.Snapshot
}

// Options are those of the admin API.
type Options struct {
	Keys   *Keys
	Config Snapshots
	// Issuer is the iss of the tokens, server.base_url.
	Issuer   string
	TokenTTL time.Duration
	// AuthorizedHosts is security.admin_authorized_hosts: the other addresses
	// get 403 before anything else.
	AuthorizedHosts []netip.Prefix
	// RatePerMinute is admin.api.rate_limit_per_minute, by address.
	RatePerMinute int
	Logger        *slog.Logger
	LogIP         string
	LogSample     *httpx.Sampler
	// Refused, RateLimited and Token, nil for none, are told of an address
	// refused, of a request over the limit, and of a token granted or
	// refused (result granted or refused, the reason of a refusal): the
	// metrics and the audit log.
	Refused     func(ctx context.Context)
	RateLimited func(ctx context.Context)
	Token       func(ctx context.Context, client, result, reason string)
	// Rehash replaces the hash old of the client id by new, the same secret
	// at the current cost (store.RehashAPIClient, Q118); nil, a hash of
	// another cost stays.
	Rehash func(ctx context.Context, id, old, new string) error
	// Writer writes the resources; nil, the API serves /token alone.
	Writer Writer
	// Wrote, nil for none, is told of each write done: the audit (admin.write),
	// the names of the fields written, never their values.
	Wrote func(ctx context.Context, client, resource, id, method string, fields []string)
	// LogLevel is observability.log_level, and DebugMaxDuration
	// observability.debug_max_duration: /log-level (P25).
	LogLevel         string
	DebugMaxDuration time.Duration
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

// API is the admin API /admin/v1.
type API struct {
	o     Options
	mux   *http.ServeMux
	limit *ratelimit.Limiter
	// bcrypt bounds the bcrypts at once, one per processor: 100 requests of
	// /token on a client of cost 13 held sixteen cores 4 s, the pages with
	// them (revue R34).
	bcrypt chan struct{}
	// rehashing are the clients whose secret is being hashed again.
	rehashing sync.Map
	// routes are the patterns served, for the test that compares them with
	// the OpenAPI document.
	routes []string
}

// New returns the admin API: /token, the documentation, and the resources
// with a writer.
func New(o Options) (*API, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	a := &API{o: o, mux: http.NewServeMux(), limit: ratelimit.New(o.RatePerMinute), bcrypt: make(chan struct{}, runtime.GOMAXPROCS(0))}
	a.route("POST "+Prefix+"/token", http.HandlerFunc(a.token))
	a.mux.HandleFunc(Prefix+"/", a.notFound)
	if err := a.registerDocs(); err != nil {
		return nil, err
	}
	if o.Writer != nil {
		a.registerApps()
		a.registerFlows()
		a.registerClients()
		a.registerSettings()
		a.registerScopes()
		a.registerLogLevel()
	}
	return a, nil
}

// route serves h on pattern, a method and a path of the API.
func (a *API) route(pattern string, h http.Handler) {
	a.mux.Handle(pattern, h)
	a.routes = append(a.routes, pattern)
}

// Routes are the patterns the API serves, method and path.
func (a *API) Routes() []string { return slices.Clone(a.routes) }

// methods are those a route of the API may take.
var methods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// notFound answers what no route takes: 405 with Allow when the path has
// routes for other methods, 404 otherwise, in problem+json as the resources.
// The catch-all pattern hides the 405 of the mux.
func (a *API) notFound(w http.ResponseWriter, r *http.Request) {
	var allowed []string
	for _, m := range methods {
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pattern := a.mux.Handler(probe); pattern != Prefix+"/" && pattern != "" {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeProblem(w, http.StatusMethodNotAllowed, "No route found for \""+r.Method+" "+r.URL.Path+"\": Method Not Allowed (Allow: "+strings.Join(allowed, ", ")+")")
		return
	}
	writeProblem(w, http.StatusNotFound, "Not Found")
}

// Register serves the API on mux, under Prefix.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle(Prefix, a)
	mux.Handle(Prefix+"/", a)
}

// Handle serves h on pattern, a path of the API with its method (POST
// /admin/v1/apps), for a caller whose token allows the method on r (Q96).
func (a *API) Handle(pattern string, r Resource, h http.Handler) {
	a.route(pattern, a.authenticate(r, h))
}

// ServeHTTP filters by address, then by rate, then routes. Nothing of the API
// is cached.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := httpx.ClientIP(r.Context())
	if !httpx.Within(a.o.AuthorizedHosts, ip) {
		if a.o.Logger != nil && a.o.LogSample.AllowClient(r.Context(), "security.ip_rejected") {
			a.o.Logger.WarnContext(r.Context(), "security.ip_rejected", "surface", "admin", "ip", httpx.FormatIP(ip, a.o.LogIP))
		}
		if a.o.Refused != nil {
			a.o.Refused(r.Context())
		}
		writeError(w, http.StatusForbidden, "request_forbidden", "The request is not allowed.")
		return
	}
	now := a.o.Now()
	rt := a.limit.Take(ip, now)
	h := w.Header()
	h.Set("X-RateLimit-Remaining", strconv.Itoa(rt.Remaining))
	h.Set("X-RateLimit-Reset", strconv.FormatInt(int64(math.Ceil(float64(rt.Reset.UnixNano())/1e9)), 10))
	if !rt.Allowed {
		if a.o.Logger != nil && a.o.LogSample.AllowClient(r.Context(), "admin.rate_limited") {
			a.o.Logger.WarnContext(r.Context(), "admin.rate_limited", "ip", httpx.FormatIP(ip, a.o.LogIP))
		}
		if a.o.RateLimited != nil {
			a.o.RateLimited(r.Context())
		}
		h.Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(rt.Reset.Sub(now).Seconds())))))
		writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Too many requests")
		return
	}
	a.mux.ServeHTTP(w, r)
}

// tokenRequest is the body of /token, in JSON or as a form.
type tokenRequest struct {
	grantType, clientID, clientSecret, scope string
}

// readTokenRequest reads the body as Symfony does: JSON when the Content-Type
// says so, a form otherwise. A JSON field that is not a string, as a body that
// is not JSON, reads as absent.
func readTokenRequest(r *http.Request) tokenRequest {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		str := func(k string) string { s, _ := body[k].(string); return s }
		return tokenRequest{str("grant_type"), str("client_id"), str("client_secret"), str("scope")}
	}
	_ = r.ParseForm()
	f := r.PostForm
	return tokenRequest{f.Get("grant_type"), f.Get("client_id"), f.Get("client_secret"), f.Get("scope")}
}

// secretMatches compares a secret with a hash, the dummy one for an unknown
// client included; the tests count its calls.
var secretMatches = domain.SecretMatches

// invalidClient stands at the audit for a client_id no client can have: it is
// not an id (domain.ValidID), so it names none.
const invalidClient = "(invalid)"

// token is POST /admin/v1/token, the client_credentials grant of Symfony.
func (a *API) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	req := readTokenRequest(r)
	// The id as the audit holds it: one a client may have, never what the body
	// brings, up to 64 KiB that the JSON of the audit would make six times
	// larger (revue R34).
	audited := req.clientID
	if !domain.ValidID(audited) {
		audited = invalidClient
	}
	refuse := func(status int, code, description string) {
		if a.o.Token != nil {
			a.o.Token(r.Context(), audited, "refused", code)
		}
		writeError(w, status, code, description)
	}
	if req.grantType != "client_credentials" {
		refuse(http.StatusBadRequest, "unsupported_grant_type", "Only client_credentials grant type is supported.")
		return
	}
	if req.clientID == "" || req.clientSecret == "" {
		refuse(http.StatusBadRequest, "invalid_request", "client_id and client_secret are required.")
		return
	}
	// One description, and one bcrypt, whether the client exists or not.
	client, known := a.o.Config.Snapshot().APIClient(req.clientID)
	hash := dummyHash()
	if known {
		hash = client.SecretHash
	}
	var matches bool
	if !a.withBcrypt(r.Context(), func() { matches = secretMatches(hash, req.clientSecret) }) {
		return // the client left while its turn came
	}
	if !matches || !known {
		refuse(http.StatusUnauthorized, "invalid_client", "Invalid client credentials.")
		return
	}
	if a.o.Rehash != nil && domain.NeedsRehash(client.SecretHash) {
		a.rehash(r.Context(), client, req.clientSecret)
	}
	granted := client.Scopes
	if requested := strings.Fields(req.scope); len(requested) > 0 {
		granted = nil
		for _, s := range requested {
			if slices.Contains(client.Scopes, s) && !slices.Contains(granted, s) {
				granted = append(granted, s)
			}
		}
		if len(granted) == 0 {
			refuse(http.StatusBadRequest, "invalid_scope", "Requested scope not allowed for this client.")
			return
		}
	}
	token, err := a.o.Keys.Issue(a.o.Issuer, client.ID, granted, a.o.TokenTTL, a.o.Now())
	if err != nil {
		if a.o.Logger != nil {
			a.o.Logger.ErrorContext(r.Context(), "admin.token_failed", "cause", err.Error())
		}
		writeError(w, http.StatusInternalServerError, "server_error", "The token could not be issued.")
		return
	}
	if a.o.Token != nil {
		a.o.Token(r.Context(), client.ID, "granted", "")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(a.o.TokenTTL / time.Second),
		"scope":        strings.Join(granted, " "),
	})
}

// withBcrypt runs f with a place among a.bcrypt, given back on every way out
// of f, a panic included: a place kept would take /token one bcrypt nearer to
// a halt (revue R38). False when ctx ended before a place came.
func (a *API) withBcrypt(ctx context.Context, f func()) bool {
	select {
	case a.bcrypt <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-a.bcrypt }()
	f()
	return true
}

// rehashTimeout bounds the hash and the write of a rehash.
const rehashTimeout = 10 * time.Second

// rehash hashes again, at the current cost, the secret of the client a token
// was just granted to, whose hash has another cost: one of Symfony, at 13
// (Q118). The time of /token then no longer tells an imported client from an
// unknown id. In the background, once per client at a time, among the bcrypts
// of a.bcrypt; a failure is logged and the token stays.
func (a *API) rehash(ctx context.Context, c store.APIClient, secret string) {
	if _, busy := a.rehashing.LoadOrStore(c.ID, true); busy {
		return
	}
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer a.rehashing.Delete(c.ID)
		ctx, cancel := context.WithTimeout(ctx, rehashTimeout)
		defer cancel()
		var hash string
		var err error
		if !a.withBcrypt(ctx, func() { hash, err = domain.HashSecret(secret) }) {
			return
		}
		if err == nil {
			err = a.o.Rehash(ctx, c.ID, c.SecretHash, hash)
		}
		if a.o.Logger == nil || errors.Is(err, store.ErrNotFound) {
			// The hash changed meanwhile: hashed again by another instance, or
			// a new secret. An instance whose snapshot is behind tries at each
			// token until it refreshes: no warning for that (revue R38).
			return
		}
		if err != nil {
			a.o.Logger.WarnContext(ctx, "admin.rehash_failed", "client_id", c.ID, "cause", err.Error())
			return
		}
		a.o.Logger.InfoContext(ctx, "admin.secret_rehashed", "client_id", c.ID)
	}()
}

// callerKey keys the caller of a request in its context.
type callerKey struct{}

// Caller is the API client of an authenticated request, and the scopes it has.
type Caller struct {
	Client string
	// Scopes are those of the token the client still holds: a scope removed
	// from the client is removed from its tokens at once.
	Scopes []string
}

// CallerOf returns the caller of an authenticated request.
func CallerOf(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// authenticate lets through a request whose bearer token is valid, from a
// client the configuration of the moment still holds (Q101), with a scope
// that allows its method on r (Q96).
func (a *API) authenticate(r Resource, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		scheme, token, _ := strings.Cut(req.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			w.Header().Set("WWW-Authenticate", realm)
			writeError(w, http.StatusUnauthorized, "invalid_token", "Authentication required.")
			return
		}
		invalid := func(description string) {
			w.Header().Set("WWW-Authenticate", realm+`, error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", description)
		}
		claims, err := a.o.Keys.Verify(strings.TrimSpace(token), a.o.Issuer, a.o.Now())
		if err != nil {
			invalid("Invalid or expired token.")
			return
		}
		client, ok := a.o.Config.Snapshot().APIClient(claims.Subject)
		if !ok {
			invalid("Client not found.")
			return
		}
		var scopes []string
		for _, s := range claims.Scopes() {
			if slices.Contains(client.Scopes, s) {
				scopes = append(scopes, s)
			}
		}
		if !Allowed(scopes, r, req.Method) {
			w.Header().Set("WWW-Authenticate", realm+`, error="insufficient_scope", scope="`+strings.Join(Required(r, req.Method), " ")+`"`)
			writeError(w, http.StatusForbidden, "insufficient_scope", "The token does not grant the scope this request requires.")
			return
		}
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), callerKey{}, Caller{Client: client.ID, Scopes: scopes})))
	})
}

// writeError writes an error as Symfony's admin API does, for /token and the
// authentication: {"error", "error_description"}.
func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
