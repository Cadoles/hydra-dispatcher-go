package emulated

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// fakeEngine records the events and answers response.
type fakeEngine struct {
	events   []flow.AppCall
	response flow.Response
}

func (e *fakeEngine) Handle(_ context.Context, ev flow.Event) flow.Result {
	e.events = append(e.events, ev.(flow.AppCall))
	return flow.Result{Response: e.response}
}

const (
	appIP     = "10.0.1.7"
	outsideIP = "203.0.113.10"
	challenge = "0123456789abcdef0123456789abcdef"
)

type server struct {
	engine *fakeEngine
	logs   bytes.Buffer
	h      http.Handler
}

func newServer(t *testing.T, legacy bool) *server {
	t.Helper()
	s := &server{engine: &fakeEngine{response: flow.Response{Kind: flow.AppJSON, Status: http.StatusOK, Body: ory.OAuth2RedirectTo{RedirectTo: "http://d/oauth2/auth?ref=r"}}}}
	mux := http.NewServeMux()
	Register(mux, Options{
		Engine:          s.engine,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		LegacyV1Paths:   legacy,
		Logger:          slog.New(slog.NewJSONHandler(&s.logs, nil)),
		LogIP:           "full",
	})
	s.h = httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(nil))
	return s
}

func (s *server) do(method, target, from, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = from + ":4321"
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	return w
}

func TestAllowlist(t *testing.T) {
	s := newServer(t, true)
	for _, path := range []string{"/admin/oauth2/auth/requests/login", "/oauth2/auth/requests/consent/accept"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "accept") {
			method = http.MethodPut
		}
		w := s.do(method, path+"?login_challenge="+challenge, outsideIP, "{}")
		var b errorBody
		_ = json.Unmarshal(w.Body.Bytes(), &b)
		if w.Code != http.StatusForbidden || b.Error != "request_forbidden" || b.Description != "The request is not allowed." || b.StatusCode != 403 ||
			b.TraceID == "" || b.TraceID != w.Header().Get("X-Trace-ID") {
			t.Errorf("%s from outside: %d %s", path, w.Code, w.Body)
		}
	}
	if len(s.engine.events) != 0 {
		t.Errorf("the engine was called: %+v", s.engine.events)
	}
	if !strings.Contains(s.logs.String(), `"msg":"security.ip_rejected","surface":"emulated","ip":"203.0.113.10"`) {
		t.Errorf("logs: %s", s.logs.String())
	}
	// The unknown client (an unreadable X-Forwarded-For) is no app.
	if w := s.do(http.MethodGet, "/admin/oauth2/auth/requests/login", "not-an-address", ""); w.Code != http.StatusForbidden {
		t.Errorf("unknown client: %d", w.Code)
	}
}

func TestEvents(t *testing.T) {
	s := newServer(t, true)
	for _, tc := range []struct {
		method, path, body string
		op                 flow.AppOp
	}{
		{http.MethodGet, "/admin/oauth2/auth/requests/login?login_challenge=" + challenge, "", flow.AppGetLogin},
		{http.MethodPut, "/admin/oauth2/auth/requests/login/accept?login_challenge=" + challenge, `{"subject":"alice"}`, flow.AppAcceptLogin},
		{http.MethodPut, "/admin/oauth2/auth/requests/login/reject?login_challenge=" + challenge, `{"error":"access_denied"}`, flow.AppRejectLogin},
		{http.MethodGet, "/admin/oauth2/auth/requests/consent?consent_challenge=" + challenge, "", flow.AppGetConsent},
		{http.MethodPut, "/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + challenge, `{}`, flow.AppAcceptConsent},
		{http.MethodPut, "/oauth2/auth/requests/consent/reject?consent_challenge=" + challenge, `{"error":"x"}`, flow.AppRejectConsent},
	} {
		s.engine.events = nil
		w := s.do(tc.method, tc.path, appIP, tc.body)
		if w.Code != http.StatusOK || w.Body.String() != `{"redirect_to":"http://d/oauth2/auth?ref=r"}` || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body)
		}
		if len(s.engine.events) != 1 {
			t.Fatalf("%s: events %+v", tc.path, s.engine.events)
		}
		ev := s.engine.events[0]
		if ev.Op != tc.op || ev.Challenge != challenge || string(ev.Body) != tc.body || ev.Caller == nil {
			t.Errorf("%s: event %+v", tc.path, ev)
		}
	}
	// The challenge in the other kind's parameter is no challenge: EMU-1.
	s.engine.events = nil
	s.do(http.MethodGet, "/admin/oauth2/auth/requests/consent?login_challenge="+challenge, appIP, "")
	if ev := s.engine.events[0]; ev.Challenge != "" {
		t.Errorf("consent read with a login_challenge: %+v", ev)
	}
}

func TestLegacyPaths(t *testing.T) {
	s := newServer(t, true)
	for range 2 {
		w := s.do(http.MethodGet, "/oauth2/auth/requests/login?login_challenge="+challenge, appIP, "")
		if w.Code != http.StatusOK || w.Header().Get("Deprecation") != "@1793577600" ||
			w.Header().Get("Link") != `</admin/oauth2/auth/requests/login>; rel="successor-version"` {
			t.Errorf("v1: %d %v", w.Code, w.Header())
		}
	}
	if n := strings.Count(s.logs.String(), `"msg":"emulated.legacy_path"`); n != 1 {
		t.Errorf("%d warnings for one address; logs %s", n, s.logs.String())
	}
	if w := s.do(http.MethodGet, "/admin/oauth2/auth/requests/login?login_challenge="+challenge, appIP, ""); w.Header().Get("Deprecation") != "" {
		t.Error("v2 deprecated")
	}
	off := newServer(t, false)
	if w := off.do(http.MethodGet, "/oauth2/auth/requests/login?login_challenge="+challenge, appIP, ""); w.Code != http.StatusNotFound {
		t.Errorf("v1 off: %d", w.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	s := newServer(t, false)
	path := "/admin/oauth2/auth/requests/login/accept?login_challenge=" + challenge
	if w := s.do(http.MethodPut, path, appIP, strings.Repeat(" ", maxBody)); w.Code != http.StatusOK {
		t.Errorf("1 MiB: %d", w.Code)
	}
	w := s.do(http.MethodPut, path, appIP, strings.Repeat(" ", maxBody+1))
	var b errorBody
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	if w.Code != http.StatusRequestEntityTooLarge || b.Error != "invalid_request" || b.Description != "E1001" || b.StatusCode != 413 {
		t.Errorf("over 1 MiB: %d %s", w.Code, w.Body)
	}
}

func TestIdentify(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("the app's certificate")}
	sum := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	sources := []netip.Prefix{netip.MustParsePrefix("10.0.1.7/32")}
	for _, tc := range []struct {
		name string
		app  store.App
		ip   string
		tls  *tls.ConnectionState
		want bool
	}{
		{"network, from its source", store.App{AuthMode: "network", AllowedSources: sources}, "10.0.1.7", nil, true},
		{"network, from another", store.App{AuthMode: "network", AllowedSources: sources}, "10.0.1.8", nil, false},
		{"network, no sources: the allowlist", store.App{AuthMode: "network"}, "10.0.1.8", nil, true},
		{"mtls, its certificate", store.App{AuthMode: "mtls", ClientCertFingerprint: fingerprint}, "10.0.1.8", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, true},
		{"mtls, another", store.App{AuthMode: "mtls", ClientCertFingerprint: strings.Repeat("0", 64)}, "10.0.1.7", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, false},
		{"mtls, no certificate", store.App{AuthMode: "mtls", ClientCertFingerprint: fingerprint}, "10.0.1.7", &tls.ConnectionState{}, false},
		{"mtls, no TLS", store.App{AuthMode: "mtls", ClientCertFingerprint: fingerprint}, "10.0.1.7", nil, false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.TLS = tc.tls
		if got := identify(r, netip.MustParseAddr(tc.ip))(tc.app); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

func TestWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resp    flow.Response
		status  int
		body    string // its start, the trace id following
		header  string
		noTrace bool
	}{
		{"EMU-2, Symfony's unknown challenge, no trace id", flow.Response{Kind: flow.AppJSON, Status: 404,
			Body: flow.AppError{Error: "missing_session_error", Description: "Could not find session metadata in cache", StatusCode: 404}},
			404, `{"error":"missing_session_error","error_description":"Could not find session metadata in cache","status_code":404}`, "", true},
		{"EMU-1, with its trace id", flow.Response{Kind: flow.AppJSON, Status: 404,
			Body: flow.AppError{Error: "invalid_request", Description: "request_failed", StatusCode: 404}},
			404, `{"error":"invalid_request","error_description":"request_failed","status_code":404,"trace_id":"`, "", false},
		{"E1004, Hydra saturated", flow.Response{Kind: flow.AppJSON, Status: 500, Overloaded: true,
			Body: flow.AppError{Error: "server_error", Description: "E1004", StatusCode: 500}},
			503, `{"error":"server_error","error_description":"E1004","status_code":503,"trace_id":"`, "1", false},
		{"a page from the engine: a bug", flow.Response{Kind: flow.ErrorPage, Code: flow.E1002},
			500, `{"error":"server_error","error_description":"E1000","status_code":500,"trace_id":"`, "", false},
		{"a login request, as the engine gives it", flow.Response{Kind: flow.AppJSON, Status: 200, Body: map[string]any{"challenge": "c"}},
			200, `{"challenge":"c"}`, "", true},
		{"a redirect_to in 410", flow.Response{Kind: flow.AppJSON, Status: 410, Body: ory.OAuth2RedirectTo{RedirectTo: "u"}},
			410, `{"redirect_to":"u"}`, "", true},
	} {
		s := newServer(t, false)
		s.engine.response = tc.resp
		w := s.do(http.MethodGet, "/admin/oauth2/auth/requests/login?login_challenge="+challenge, appIP, "")
		got := w.Body.String()
		if w.Code != tc.status || !strings.HasPrefix(got, tc.body) || w.Header().Get("Retry-After") != tc.header ||
			!tc.noTrace && got != tc.body+w.Header().Get("X-Trace-ID")+`"}` || tc.noTrace && got != tc.body {
			t.Errorf("%s: %d %s, Retry-After %q", tc.name, w.Code, got, w.Header().Get("Retry-After"))
		}
	}
}
