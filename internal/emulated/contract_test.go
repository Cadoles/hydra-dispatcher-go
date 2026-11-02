package emulated

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The contract tests replay the Symfony captures against the dispatcher: the
// browser's steps go to the engine, the login apps' calls to the emulated
// API over HTTP with the bodies they sent, and Hydra is a fake that answers
// what Hydra answered Symfony. Each answer served to an app is compared with
// Symfony's; only the deviations the phase 1 plan assumes are normalized,
// each by name (Points d'attention, Écarts assumés).

const captures = "../../testdata/protocol/symfony-hydra-2.1/"

type exchange struct {
	Leg     string `json:"leg"`
	Request struct {
		Method string          `json:"method"`
		URI    string          `json:"uri"`
		Body   json.RawMessage `json:"body"`
	} `json:"request"`
	Response struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	} `json:"response"`
}

func readCapture(t *testing.T, dir string) []exchange {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(captures, dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("capture %s: %v", dir, err)
	}
	sort.Strings(files)
	var out []exchange
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var x exchange
		if err := json.Unmarshal(data, &x); err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	return out
}

// replayedHydra answers the dispatcher's admin calls with the answers the
// capture recorded, by method and path; the consent request carries the
// context of the last login accept, as Hydra's does.
type replayedHydra struct {
	mu        sync.Mutex
	answers   map[string]exchange
	accepted  json.RawMessage // the context of the final login accept
	sent      map[string]json.RawMessage
	calls     []string
	t         *testing.T
	unplanned bool
}

func newReplayedHydra(t *testing.T, xs []exchange) *replayedHydra {
	h := &replayedHydra{answers: map[string]exchange{}, sent: map[string]json.RawMessage{}, t: t}
	for _, x := range xs {
		if x.Leg != "hydra" {
			continue
		}
		key := x.Request.Method + " " + strings.SplitN(x.Request.URI, "?", 2)[0]
		if _, ok := h.answers[key]; !ok {
			h.answers[key] = x
		}
	}
	return h
}

func (h *replayedHydra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	h.calls = append(h.calls, key)
	body, _ := io.ReadAll(r.Body)
	if len(body) > 0 {
		h.sent[key] = body
	}
	x, ok := h.answers[key]
	if !ok {
		h.unplanned = true
		h.t.Errorf("Hydra called %s, which the capture never was", key)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	answer := x.Response.Body
	switch {
	case strings.HasSuffix(key, "/login/accept"):
		var accept struct {
			Context json.RawMessage `json:"context"`
		}
		_ = json.Unmarshal(body, &accept)
		h.accepted = accept.Context
	case strings.HasSuffix(key, "/requests/consent") && h.accepted != nil:
		var doc map[string]json.RawMessage
		_ = json.Unmarshal(answer, &doc)
		doc["context"] = h.accepted
		answer, _ = json.Marshal(doc)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(x.Response.Status)
	_, _ = w.Write(answer)
}

// hydraDevSnapshot is the configuration of hydra-dev's dispatcher.yaml.
func hydraDevSnapshot() *store.Snapshot {
	apps := []store.App{
		{ID: "hydra-oidc", LoginURL: "http://oidc.hydra.test/login", ConsentURL: "http://oidc.hydra.test/consent", Method: "oidc", AuthMode: "network"},
		{ID: "hydra-sql", LoginURL: "http://sql.hydra.test/login", ConsentURL: "http://sql.hydra.test/consent", Method: "pwd", AuthMode: "network"},
		{ID: "hydra-2fa", LoginURL: "http://2fa.hydra.test/login", ConsentURL: "http://2fa.hydra.test/consent", Method: "otp", AuthMode: "network"},
	}
	flows := []store.Flow{
		{ID: "hydra-oidc", Enabled: true, Steps: []store.Step{{AppID: "hydra-oidc", Position: 1, SubjectCheck: "none"}}},
		{ID: "hydra-sql", Enabled: true, Steps: []store.Step{{AppID: "hydra-sql", Position: 1, SubjectCheck: "none"}}},
		{ID: "hydra-sql-2fa", Enabled: true, Steps: []store.Step{{AppID: "hydra-sql", Position: 1, SubjectCheck: "none"}, {AppID: "hydra-2fa", Position: 2, SubjectCheck: "none"}}},
	}
	return store.NewSnapshot(apps, flows, store.DefaultSettings())
}

type snapshots struct{ s *store.Snapshot }

func (s snapshots) Snapshot() *store.Snapshot { return s.s }

// player plays a capture: the browser through the engine, the apps through
// the emulated API.
type player struct {
	t       *testing.T
	o       *flow.Orchestrator
	api     http.Handler
	hydra   *replayedHydra
	prefix  string // "" for the v1 paths the capture holds, "/admin" for v2
	cookie  string
	ref     string
	current struct{ login, consent string }
	// accepts are the bodies of the step login accepts, by step challenge:
	// the context a consent request serves (A2).
	accepts map[string]json.RawMessage
	// claims are the x_dispatcher_claims of the login requests served, by
	// step challenge: the consent request of the step serves the same.
	claims map[string]any
	// compared counts the app calls compared.
	compared int
	// app is the host of the app the browser was last sent to; addrs the
	// address each app calls from, and the X-Forwarded-For of the proxy it
	// calls through, if any: 10.0.1.7 directly for the others.
	app   string
	addrs map[string][2]string
}

func newPlayer(t *testing.T, xs []exchange, prefix string) *player {
	t.Helper()
	p := &player{t: t, hydra: newReplayedHydra(t, xs), prefix: prefix, accepts: map[string]json.RawMessage{}, claims: map[string]any{}}
	srv := httptest.NewServer(p.hydra)
	t.Cleanup(srv.Close)
	client, err := hydra.New(config.Hydra{AdminURL: srv.URL, Timeout: config.Duration(5 * time.Second), MaxInFlight: 8}, config.TLS{MinVersion: "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	mem := state.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	p.o = &flow.Orchestrator{
		Store:           mem,
		Config:          snapshots{hydraDevSnapshot()},
		Source:          flow.Fallback{Hydra: client},
		Hydra:           client,
		Webhooks:        flow.StubWebhooks{},
		BaseURL:         "http://dispatcher.hydra.test",
		LoginConsentTTL: 30 * time.Minute,
		Keys:            flow.Keys{[]byte("0123456789abcdef0123456789abcdef")},
	}
	mux := http.NewServeMux()
	Register(mux, Options{
		Engine:          p.o,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		LegacyV1Paths:   true,
		Logger:          slog.New(slog.DiscardHandler),
	})
	p.api = httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(nil))
	return p
}

func (p *player) handle(ev flow.Event) flow.Response {
	p.t.Helper()
	r := p.o.Handle(context.Background(), ev).Response
	if r.SetCSRF != "" {
		p.cookie = r.SetCSRF
	}
	if r.Kind == flow.Redirect {
		u, _ := url.Parse(r.URL)
		if u.Host != "dispatcher.hydra.test" {
			p.app = u.Host
		}
		if c := u.Query().Get("login_challenge"); c != "" && u.Host != "dispatcher.hydra.test" {
			p.current.login = c
		}
		if c := u.Query().Get("consent_challenge"); c != "" && u.Host != "dispatcher.hydra.test" {
			p.current.consent = c
		}
	}
	return r
}

// call sends an app's call to the emulated API, from the app's address.
func (p *player) call(method, path, param, challenge string, body json.RawMessage) (int, map[string]any) {
	p.t.Helper()
	from, ok := p.addrs[p.app]
	if !ok {
		from = [2]string{"10.0.1.7", ""}
	}
	w := p.callFrom(from[0], from[1], method, path, param, challenge, body)
	var doc map[string]any
	decodeNumbers(p.t, w.Body.Bytes(), &doc)
	return w.Code, doc
}

// callFrom sends a call from remote, through a proxy when xff is set.
func (p *player) callFrom(remote, xff, method, path, param, challenge string, body json.RawMessage) *httptest.ResponseRecorder {
	target := p.prefix + path + "?" + param + "=" + url.QueryEscape(challenge)
	var rd io.Reader
	if len(body) > 0 && string(body) != "null" {
		rd = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.RemoteAddr = net.JoinHostPort(remote, "4321")
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	p.api.ServeHTTP(w, r)
	return w
}

func decodeNumbers(t *testing.T, data []byte, v any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatalf("%v: %s", err, data)
	}
}

// formFlow is the flow the choice form posted: Symfony numbered them in the
// order of the page, by id (README of the captures).
func formFlow(t *testing.T, body json.RawMessage) string {
	var form string
	if err := json.Unmarshal(body, &form); err != nil {
		t.Fatal(err)
	}
	v, _ := url.ParseQuery(form)
	ids := []string{"hydra-oidc", "hydra-sql", "hydra-sql-2fa"}
	var i int
	_, _ = fmt.Sscan(v.Get("login[flow]"), &i)
	return ids[i]
}

// play replays the capture, comparing each answer to an app.
func (p *player) play(xs []exchange) {
	t := p.t
	for _, x := range xs {
		if x.Leg != "front" {
			continue
		}
		u, _ := url.Parse(x.Request.URI)
		q := u.Query()
		switch path := u.Path; {
		case x.Request.Method == http.MethodGet && path == "/" && q.Get("login_challenge") != "":
			if p.ref == "" {
				p.ref = flow.Ref(q.Get("login_challenge"))
				p.handle(flow.Entry{LoginChallenge: q.Get("login_challenge"), Cookie: p.cookie})
			}
		case x.Request.Method == http.MethodPost && path == "/":
			r := p.handle(flow.Choose{FlowID: formFlow(t, x.Request.Body), LoginChallenge: q.Get("login_challenge"), Token: p.cookie, Cookie: p.cookie, SameOrigin: true})
			if r.Kind != flow.Redirect {
				t.Fatalf("POST /: %+v", r)
			}
		case path == "/oauth2/auth":
			p.handle(flow.Loop{Ref: p.ref, Cookie: p.cookie})
		case path == "/consent":
			p.handle(flow.Consent{Challenge: q.Get("consent_challenge"), Cookie: p.cookie})
		case strings.HasPrefix(path, "/oauth2/auth/requests/"):
			p.compareCall(x, path)
		}
	}
}

// compareCall makes the app's call x and compares the answers.
func (p *player) compareCall(x exchange, path string) {
	t := p.t
	param, challenge := "login_challenge", p.current.login
	if strings.Contains(path, "/consent") {
		param, challenge = "consent_challenge", p.current.consent
	}
	if strings.HasSuffix(path, "/login/accept") {
		p.accepts[challenge] = x.Request.Body
	}
	p.compared++
	status, got := p.call(x.Request.Method, path, param, challenge, x.Request.Body)
	var want map[string]any
	decodeNumbers(t, x.Response.Body, &want)
	wantStatus := x.Response.Status
	switch {
	case strings.HasSuffix(path, "/reject") && wantStatus == http.StatusGone:
		// T3: Hydra's redirect_to in 200, which the apps follow; Symfony
		// answered 410.
		wantStatus = http.StatusOK
	case strings.HasSuffix(path, "/accept"):
		// A1: the redirect_to of a step accept is the ref's loop, never
		// Hydra's challenge.
		if loop := flow.LoopURL("http://dispatcher.hydra.test", p.ref); got["redirect_to"] != loop {
			t.Errorf("%s: redirect_to %v, want %s", path, got["redirect_to"], loop)
		}
		want["redirect_to"] = got["redirect_to"]
	case path == "/oauth2/auth/requests/login":
		p.normalizeRequest(want, got)
		// x_dispatcher_restart_url, which Symfony did not serve: the choice
		// of the ref, never Hydra's challenge (A1).
		if restart := flow.RestartURL("http://dispatcher.hydra.test", p.ref); got["x_dispatcher_restart_url"] != restart {
			t.Errorf("x_dispatcher_restart_url %v, want %s", got["x_dispatcher_restart_url"], restart)
		}
		want["x_dispatcher_restart_url"] = got["x_dispatcher_restart_url"]
		p.claims[challenge] = got["x_dispatcher_claims"]
	case path == "/oauth2/auth/requests/consent":
		p.normalizeRequest(want, got)
		// The consent requests carry the claims of the previous steps too,
		// which Symfony did not serve: those of the step's login request.
		if served, ok := p.claims[p.loginOf(challenge)]; !ok || !reflect.DeepEqual(got["x_dispatcher_claims"], served) {
			t.Errorf("consent request x_dispatcher_claims %v, want the step's login request's %v", got["x_dispatcher_claims"], served)
		}
		want["x_dispatcher_claims"] = got["x_dispatcher_claims"]
		// A2: the context of the step's login accept, where Symfony served
		// {}.
		var accept struct {
			Context map[string]any `json:"context"`
		}
		decodeNumbers(t, p.accepts[p.loginOf(challenge)], &accept)
		if accept.Context == nil {
			accept.Context = map[string]any{}
		}
		if !reflect.DeepEqual(got["context"], any(accept.Context)) {
			t.Errorf("A2: consent request context %v, want the step's login accept context %v", got["context"], accept.Context)
		}
		want["context"] = got["context"]
	}
	if status != wantStatus {
		t.Errorf("%s %s: status %d, Symfony %d", x.Request.Method, path, status, x.Response.Status)
	}
	if d := diff(want, got, ""); len(d) > 0 {
		t.Errorf("%s %s differs from Symfony: %v", x.Request.Method, path, d)
	}
}

// loginOf is the login challenge of the step whose consent challenge is c:
// the one served last.
func (p *player) loginOf(string) string { return p.current.login }

// normalizeRequest applies the assumed deviations of a served request: the
// step's challenges, subject "" and claims {} on the first step where
// Symfony served null and [], the client's dates relayed as Hydra gives
// them, where Symfony wrote them to the second with +00:00.
func (p *player) normalizeRequest(want, got map[string]any) {
	for _, k := range []string{"challenge", "login_challenge"} {
		if _, ok := want[k]; ok {
			want[k] = got[k]
		}
	}
	if want["subject"] == nil {
		want["subject"] = ""
	}
	if claims, ok := want["x_dispatcher_claims"].([]any); ok && len(claims) == 0 {
		want["x_dispatcher_claims"] = map[string]any{}
	}
	var hydraLogin map[string]any
	decodeNumbers(p.t, p.hydra.answers["GET /admin/oauth2/auth/requests/login"].Response.Body, &hydraLogin)
	relayed, _ := hydraLogin["client"].(map[string]any)
	client, _ := want["client"].(map[string]any)
	for _, k := range []string{"created_at", "updated_at"} {
		if _, ok := client[k]; ok {
			client[k] = relayed[k]
		}
	}
}

// diff lists the JSON paths where want and got differ.
func diff(want, got any, path string) []string {
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if wok && gok {
		var out []string
		for k, w := range wm {
			if g, ok := gm[k]; ok {
				out = append(out, diff(w, g, path+"."+k)...)
			} else {
				out = append(out, path+"."+k+": dropped")
			}
		}
		for k, g := range gm {
			if _, ok := wm[k]; !ok {
				v, _ := json.Marshal(g)
				out = append(out, path+"."+k+": added "+string(v))
			}
		}
		slices.Sort(out)
		return out
	}
	if reflect.DeepEqual(want, got) {
		return nil
	}
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	return []string{path + ": " + string(w) + " -> " + string(g)}
}

// sentToHydra compares what the dispatcher sent Hydra with what Symfony
// sent, at the final login accept, the consent accept and the rejects.
func (p *player) sentToHydra(xs []exchange) {
	t := p.t
	for _, x := range xs {
		if x.Leg != "hydra" || x.Request.Method != http.MethodPut {
			continue
		}
		key := "PUT " + strings.SplitN(x.Request.URI, "?", 2)[0]
		var want, got map[string]any
		decodeNumbers(t, x.Request.Body, &want)
		if p.hydra.sent[key] == nil {
			t.Errorf("%s: never sent", key)
			continue
		}
		decodeNumbers(t, p.hydra.sent[key], &got)
		switch {
		case strings.HasSuffix(key, "/login/accept"):
			// The final context: the steps' consent contexts and
			// x_dispatcher_ref, where Symfony sent [].
			ctx, _ := got["context"].(map[string]any)
			if ctx["x_dispatcher_ref"] != p.ref {
				t.Errorf("final accept context %v, without x_dispatcher_ref %s", got["context"], p.ref)
			}
			want["context"] = got["context"]
		case strings.HasSuffix(key, "/consent/accept"):
			// A2: a claim null of a later step erases nothing.
			for _, part := range []string{"id_token", "access_token"} {
				w, _ := want["session"].(map[string]any)[part].(map[string]any)
				g, _ := got["session"].(map[string]any)[part].(map[string]any)
				for k, v := range w {
					if v == nil && g[k] != nil {
						w[k] = g[k]
					}
				}
			}
		}
		if d := diff(want, got, ""); len(d) > 0 {
			t.Errorf("%s differs from Symfony's: %v", key, d)
		}
	}
}

func TestSymfonyCaptures(t *testing.T) {
	for _, tc := range []struct {
		dir string
		// calls are the admin calls of the dispatcher, B3 for the complete
		// authentications.
		calls int
	}{
		{"12-sql-consent-skipped", 4},
		{"14-sql-2fa-consent-skipped", 5},
		{"16-consent-reject-first-step", 2},
		{"17-consent-reject-second-step", 3},
		{"18-login-reject-first-step", 2},
		{"19-login-reject-second-step", 3},
		{"20-accept-twice", 3},
	} {
		for _, prefix := range []string{"", "/admin"} {
			t.Run(tc.dir+prefix, func(t *testing.T) {
				xs := readCapture(t, tc.dir)
				p := newPlayer(t, xs, prefix)
				p.play(xs)
				p.sentToHydra(xs)
				calls := 0
				for _, x := range xs {
					if x.Leg == "front" && strings.HasPrefix(x.Request.URI, "/oauth2/auth/requests/") {
						calls++
					}
				}
				if calls == 0 || p.compared != calls {
					t.Errorf("%d app calls compared of %d", p.compared, calls)
				}
				if len(p.hydra.calls) != tc.calls {
					t.Errorf("Hydra called %d times: %v", len(p.hydra.calls), p.hydra.calls)
				}
			})
		}
	}
}

// The error answers of the emulated API, whatever the flow: the captures'
// calls sent as they are.
func TestSymfonyErrors(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		from string
		// adjust turns Symfony's answer into the one expected.
		adjust func(status int, body map[string]any) (int, map[string]any)
	}{
		// T5: an unknown challenge, as Symfony.
		{"21-unknown-step-challenge", "10.0.1.7", nil},
		// T5: a malformed challenge, as Symfony but for the trace id.
		{"22-malformed-challenge", "10.0.1.7", nil},
		// Q17, capture 26: Symfony answered its allowlist's refusal as any
		// error, 500; the dispatcher answers 403.
		{"26-allowlist-refusal", "203.0.113.10", func(int, map[string]any) (int, map[string]any) {
			return http.StatusForbidden, map[string]any{"error": "request_forbidden", "error_description": "The request is not allowed.", "status_code": json.Number("403")}
		}},
	} {
		for _, prefix := range []string{"", "/admin"} {
			t.Run(tc.dir+prefix, func(t *testing.T) {
				p := newPlayer(t, nil, prefix)
				n := 0
				for _, x := range readCapture(t, tc.dir) {
					if x.Leg != "front" || !strings.HasPrefix(x.Request.URI, "/oauth2/auth/requests/") {
						continue
					}
					n++
					var body io.Reader
					if len(x.Request.Body) > 0 && string(x.Request.Body) != "null" {
						body = bytes.NewReader(x.Request.Body)
					}
					r := httptest.NewRequest(x.Request.Method, prefix+x.Request.URI, body)
					r.RemoteAddr = tc.from + ":4321"
					w := httptest.NewRecorder()
					p.api.ServeHTTP(w, r)
					var got, want map[string]any
					decodeNumbers(t, w.Body.Bytes(), &got)
					decodeNumbers(t, x.Response.Body, &want)
					status := x.Response.Status
					if tc.adjust != nil {
						status, want = tc.adjust(status, want)
					}
					if _, ok := want["trace_id"]; ok || tc.adjust != nil {
						if got["trace_id"] != w.Header().Get("X-Trace-ID") {
							t.Errorf("%s: trace_id %v", x.Request.URI, got["trace_id"])
						}
						want["trace_id"] = got["trace_id"]
					}
					if w.Code != status {
						t.Errorf("%s %s: %d, want %d", x.Request.Method, x.Request.URI, w.Code, status)
					}
					if d := diff(want, got, ""); len(d) > 0 {
						t.Errorf("%s %s: %v", x.Request.Method, x.Request.URI, d)
					}
				}
				if n == 0 || len(p.hydra.calls) != 0 {
					t.Errorf("%d calls replayed, Hydra called %v", n, p.hydra.calls)
				}
			})
		}
	}
}

// Durcissement 1 on the engine: the apps of capture 14 identified by their
// sources, hydra-2fa in IPv6, one directly and one through the proxy. At
// each step, the app's challenge is refused from another app's source, from
// an address of the allowlist that is no app's, directly or through the
// proxy, and the refusal is logged with its trace id.
func TestIdentification(t *testing.T) {
	xs := readCapture(t, "14-sql-2fa-consent-skipped")
	p := newPlayer(t, xs, "/admin")
	snap := hydraDevSnapshot()
	sources := map[string]string{"hydra-oidc": "10.0.1.9", "hydra-sql": "10.0.1.7", "hydra-2fa": "2001:db8::8"}
	for i, a := range snap.Apps {
		addr := netip.MustParseAddr(sources[a.ID])
		snap.Apps[i].AllowedSources = []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}
	}
	p.o.Config = snapshots{snap}
	var logs bytes.Buffer
	logger := slog.New(httpx.LogHandler(slog.NewJSONHandler(&logs, nil)))
	p.o.Log = logger
	mux := http.NewServeMux()
	Register(mux, Options{
		Engine:          p.o,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/64")},
		LegacyV1Paths:   true,
		Logger:          logger,
	})
	proxy := []netip.Prefix{netip.MustParsePrefix("10.0.0.10/32")}
	p.api = httpx.Chain(httpx.Routes(mux), httpx.RealIP(proxy), httpx.Trace(nil))
	// hydra-sql calls directly, hydra-2fa through the proxy.
	p.addrs = map[string][2]string{"sql.hydra.test": {"10.0.1.7", ""}, "2fa.hydra.test": {"10.0.0.10", "2001:db8::8"}}
	served := map[string]bool{}
	for _, x := range xs {
		if x.Leg == "front" && strings.HasPrefix(x.Request.URI, "/oauth2/auth/requests/login?") && !served[p.current.login] {
			served[p.current.login] = true
			for _, from := range [][2]string{{"10.0.1.9", ""}, {"10.0.1.50", ""}, {"10.0.0.10", "10.0.1.9"}, {"10.0.0.10", "10.0.1.50"}, {"2001:db8::50", ""}} {
				w := p.callFrom(from[0], from[1], http.MethodGet, "/oauth2/auth/requests/login", "login_challenge", p.current.login, nil)
				var b errorBody
				_ = json.Unmarshal(w.Body.Bytes(), &b)
				if w.Code != http.StatusForbidden || b.Error != "request_forbidden" {
					t.Errorf("%s from %v: %d %s", p.app, from, w.Code, w.Body)
				}
				if line := `"msg":"security.ip_rejected","surface":"emulated","detail":"emulated: app outside its sources","audit":false,"trace_id":"` + b.TraceID + `"`; !strings.Contains(logs.String(), line) {
					t.Errorf("%s from %v: no %s in %s", p.app, from, line, logs.String())
				}
			}
			// The app itself, directly or through the proxy, passes.
			from := p.addrs[p.app]
			if w := p.callFrom(from[0], from[1], http.MethodGet, "/oauth2/auth/requests/login", "login_challenge", p.current.login, nil); w.Code != http.StatusOK {
				t.Errorf("%s from %v: %d %s", p.app, from, w.Code, w.Body)
			}
		}
		p.play([]exchange{x})
	}
	if len(served) != 2 {
		t.Errorf("%d steps checked", len(served))
	}
	p.sentToHydra(xs)
}

// Numbers beyond 2^53 in a step's context and claims reach the consent
// request and Hydra as written.
func TestNumbersAsWritten(t *testing.T) {
	xs := readCapture(t, "12-sql-consent-skipped")
	for i, x := range xs {
		switch {
		case x.Leg == "front" && strings.Contains(x.Request.URI, "/login/accept"):
			xs[i].Request.Body = json.RawMessage(`{"amr":["pwd"],"context":{"n":12345678901234567891,"f":1.10},"remember":true,"subject":"test2@test.com"}`)
		case x.Leg == "front" && strings.Contains(x.Request.URI, "/consent/accept"):
			xs[i].Request.Body = json.RawMessage(`{"grant_scope":["openid"],"remember":true,"session":{"id_token":{"big":98765432109876543211,"email":"test2@test.com"}}}`)
		}
	}
	p := newPlayer(t, xs, "/admin")
	p.play(xs) // A2: the consent request's context compared, numbers as written
	if sent := string(p.hydra.sent["PUT /admin/oauth2/auth/requests/consent/accept"]); !strings.Contains(sent, `"id_token":{"big":98765432109876543211,`) {
		t.Errorf("consent accept sent %s", sent)
	}
}
