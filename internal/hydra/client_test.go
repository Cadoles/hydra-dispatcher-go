package hydra

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

func newTestClient(t *testing.T, url string, maxInFlight int, timeout time.Duration) *Client {
	t.Helper()
	c, err := New(config.Hydra{AdminURL: url, Timeout: config.Duration(timeout), MaxInFlight: maxInFlight}, config.TLS{MinVersion: "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeHydra answers the admin API with canned responses keyed by
// "METHOD path", and records what it received.
type fakeHydra struct {
	t         *testing.T
	responses map[string]func(w http.ResponseWriter, r *http.Request)
	got       []*http.Request
	bodies    []string
}

func (f *fakeHydra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.got = append(f.got, r)
	f.bodies = append(f.bodies, string(b))
	h, ok := f.responses[r.Method+" "+r.URL.Path]
	if !ok {
		f.t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestLoginFlowCalls(t *testing.T) {
	loginRequest := string(body(t, hydra22+"login_request.json"))
	fake := &fakeHydra{t: t, responses: map[string]func(http.ResponseWriter, *http.Request){
		"GET /admin/oauth2/auth/requests/login":          reply(200, loginRequest),
		"PUT /admin/oauth2/auth/requests/login/accept":   reply(200, `{"redirect_to":"http://public.hydra.test/oauth2/auth?login_verifier=v"}`),
		"PUT /admin/oauth2/auth/requests/login/reject":   reply(200, `{"redirect_to":"http://oidc.client.test/cb?error=access_denied"}`),
		"GET /admin/oauth2/auth/requests/consent":        reply(200, string(body(t, hydra22+"consent_request.json"))),
		"PUT /admin/oauth2/auth/requests/consent/accept": reply(200, `{"redirect_to":"http://public.hydra.test/oauth2/auth?consent_verifier=v"}`),
		"PUT /admin/oauth2/auth/requests/consent/reject": reply(200, `{"redirect_to":"http://oidc.client.test/cb?error=access_denied"}`),
		"GET /admin/oauth2/auth/requests/logout":         reply(200, string(body(t, symfony21+"13-logout/0029-hydra-GET-admin_oauth2_auth_requests_logout.json"))),
		"PUT /admin/oauth2/auth/requests/logout/accept":  reply(200, `{"redirect_to":"http://public.hydra.test/oauth2/sessions/logout?logout_verifier=v"}`),
		"PUT /admin/oauth2/auth/requests/logout/reject":  reply(204, ""),
		"GET /health/ready":                              reply(200, `{"status":"ok"}`),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv.URL+"/", 4, time.Second) // the SDK must not call //admin/...
	ctx := httpx.WithTraceID(context.Background(), "4bf92f3577b34da6a3ce929d0e0e4736")

	lr, err := c.LoginRequest(ctx, "L+/=")
	if err != nil || lr.Client.GetClientId() == "" || len(lr.RequestedScope) != 3 {
		t.Fatalf("LoginRequest = %+v, %v", lr, err)
	}
	if to, err := c.AcceptLogin(ctx, "L", ory.AcceptOAuth2LoginRequest{Subject: "alice", Amr: []string{"pwd"}}); err != nil || !strings.Contains(to, "login_verifier") {
		t.Errorf("AcceptLogin = %q, %v", to, err)
	}
	if to, err := c.RejectLogin(ctx, "L", ory.RejectOAuth2Request{Error: ory.PtrString("access_denied")}); err != nil || !strings.Contains(to, "access_denied") {
		t.Errorf("RejectLogin = %q, %v", to, err)
	}
	if cr, err := c.ConsentRequest(ctx, "C"); err != nil || cr.GetSubject() != "alice" {
		t.Errorf("ConsentRequest = %+v, %v", cr, err)
	}
	if to, err := c.AcceptConsent(ctx, "C", ory.AcceptOAuth2ConsentRequest{GrantScope: []string{"openid"}}); err != nil || to == "" {
		t.Errorf("AcceptConsent = %q, %v", to, err)
	}
	if to, err := c.RejectConsent(ctx, "C", ory.RejectOAuth2Request{}); err != nil || to == "" {
		t.Errorf("RejectConsent = %q, %v", to, err)
	}
	if lo, err := c.LogoutRequest(ctx, "U"); err != nil || lo.GetSid() == "" {
		t.Errorf("LogoutRequest = %+v, %v", lo, err)
	}
	if to, err := c.AcceptLogout(ctx, "U"); err != nil || to == "" {
		t.Errorf("AcceptLogout = %q, %v", to, err)
	}
	if err := c.RejectLogout(ctx, "U"); err != nil {
		t.Errorf("RejectLogout = %v", err)
	}
	if err := c.Ready(ctx); err != nil {
		t.Errorf("Ready = %v", err)
	}

	first := fake.got[0]
	if first.URL.Query().Get("login_challenge") != "L+/=" {
		t.Errorf("login_challenge sent as %q", first.URL.RawQuery)
	}
	for i, r := range fake.got {
		if r.Header.Get("X-Trace-ID") != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Errorf("call %d (%s %s) without the trace id", i, r.Method, r.URL.Path)
		}
	}
	var accept map[string]any
	if err := json.Unmarshal([]byte(fake.bodies[1]), &accept); err != nil || accept["subject"] != "alice" {
		t.Errorf("accept body = %s", fake.bodies[1])
	}
}

// cutBody answers status with a body shorter than announced, then hangs up.
func cutBody(status int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"redirect_to\":", status, http.StatusText(status))
		_ = buf.Flush()
	}
}

func TestErrors(t *testing.T) {
	const challenge = "SENTINEL-CHALLENGE"
	tests := []struct {
		name         string
		handler      func(http.ResponseWriter, *http.Request)
		wantUnavail  bool
		wantStatus   int
		wantRedirect string
	}{
		{"already handled", reply(410, `{"redirect_to":"http://oidc.client.test/cb?error=x"}`), false, 410, "http://oidc.client.test/cb?error=x"},
		{"unknown challenge", reply(404, `{"error":"Not Found","error_description":"Unable to locate the resource"}`), false, 404, ""},
		{"server error", reply(500, `{"error":"boom"}`), true, 0, ""},
		{"unexpected 200", reply(200, `{"unexpected":true}`), true, 0, ""},
		{"empty 200", reply(200, ""), true, 0, ""},
		{"null 200", reply(200, "null"), true, 0, ""},
		{"oversized 200", reply(200, `{"challenge":"`+strings.Repeat("a", maxBody)+`"}`), true, 0, ""},
		// Hydra's public port, or a proxy: a broken setup, not an unknown challenge.
		{"404 page", http.NotFound, true, 0, ""},
		{"4xx cut short", cutBody(410), true, 0, ""},
		{"redirect", http.RedirectHandler("/elsewhere", http.StatusTemporaryRedirect).ServeHTTP, true, 0, ""},
		{"too slow", func(w http.ResponseWriter, _ *http.Request) { time.Sleep(200 * time.Millisecond) }, true, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(tt.handler))
			defer srv.Close()
			c := newTestClient(t, srv.URL, 4, 50*time.Millisecond)
			_, getErr := c.LoginRequest(context.Background(), challenge)
			_, acceptErr := c.AcceptLogin(context.Background(), challenge, ory.AcceptOAuth2LoginRequest{Subject: "alice"})

			for _, err := range []error{getErr, acceptErr} {
				if got := errors.Is(err, ErrUnavailable); got != tt.wantUnavail {
					t.Fatalf("err = %v, ErrUnavailable %v, want %v", err, got, tt.wantUnavail)
				}
				if strings.Contains(err.Error(), challenge) {
					t.Errorf("the challenge is in the error: %v", err)
				}
				if tt.wantStatus == 0 {
					continue
				}
				var reqErr *RequestError
				if !errors.As(err, &reqErr) || reqErr.Status != tt.wantStatus || reqErr.RedirectTo() != tt.wantRedirect || len(reqErr.Body) == 0 {
					t.Errorf("err = %#v, want a RequestError %d redirecting to %q with Hydra's body", err, tt.wantStatus, tt.wantRedirect)
				}
			}
		})
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // refused connections
	_, err := newTestClient(t, srv.URL, 4, time.Second).LoginRequest(context.Background(), challenge)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), challenge) {
		t.Errorf("connection refused: err = %v, want ErrUnavailable without the challenge", err)
	}
}

// Past hydra.max_in_flight, calls fail at once rather than queue; /ready is
// not one of them.
func TestInFlightCap(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, 1, 5*time.Second)

	done := make(chan error, 1)
	go func() { done <- c.RejectLogout(context.Background(), "U") }()
	<-entered
	if err := c.RejectLogout(context.Background(), "U"); !errors.Is(err, ErrOverloaded) {
		t.Errorf("second call = %v, want ErrOverloaded", err)
	}
	if err := c.Ready(context.Background()); err != nil {
		t.Errorf("Ready with the cap full = %v, want ok: load is not Hydra down", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Errorf("first call = %v", err)
	}

	func() {
		defer func() { _ = recover() }()
		_, _ = call(c, "panics", func() (struct{}, *http.Response, error) { panic("boom") })
	}()
	go func() { <-entered }()
	if err := c.RejectLogout(context.Background(), "U"); err != nil {
		t.Errorf("call after release and panic = %v, want the slot back", err)
	}
}

// Every call the cap lets through gets its connection: a lower limit in the
// transport would queue calls out of the cap's sight.
func TestConnectionsFollowTheCap(t *testing.T) {
	const n = 300 // above the 256 connections per host the transport used to allow
	var arrived atomic.Int32
	var queued atomic.Bool
	all := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if arrived.Add(1) == n {
			close(all)
		}
		select {
		case <-all:
		case <-time.After(2 * time.Second):
			queued.Store(true)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, n, 10*time.Second)

	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := c.RejectLogout(context.Background(), "U"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if queued.Load() {
		t.Errorf("the %d calls did not reach Hydra together", n)
	}
}

// Probes share one call and its answer for readyTTL.
func TestReady(t *testing.T) {
	var calls, status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		reply(int(status.Load()), `{"status":"ok"}`)(w, r)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, 1, time.Second)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := c.Ready(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Errorf("Ready = %v, want ErrUnavailable", err)
			}
		})
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("%d calls to Hydra for 20 probes, want 1", n)
	}

	status.Store(http.StatusOK)
	c.readyAt = time.Now().Add(-readyTTL)
	if err := c.Ready(context.Background()); err != nil || calls.Load() != 2 {
		t.Errorf("Ready after readyTTL = %v after %d calls, want ok after 2", err, calls.Load())
	}
}

func TestTLSWithDedicatedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	withCA, err := New(config.Hydra{AdminURL: srv.URL, Timeout: config.Duration(time.Second), MaxInFlight: 1}, config.TLS{MinVersion: "1.3", CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	if err := withCA.Ready(context.Background()); err != nil {
		t.Errorf("with the CA: %v", err)
	}
	if err := newTestClient(t, srv.URL, 1, time.Second).Ready(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("without the CA: err = %v, want the certificate refused", err)
	}

	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.Hydra{AdminURL: srv.URL, MaxInFlight: 1}, config.TLS{CAFile: empty}); err == nil {
		t.Error("CA file without certificate: want an error")
	}
}

// In TLS 1.2, only ECDHE with an AEAD, as the ANSSI TLS guide recommends.
func TestTLS12Suites(t *testing.T) {
	for _, tt := range []struct {
		suite uint16
		ok    bool
	}{
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true},
		{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, true},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, false}, // enabled by Go's defaults
	} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tt.suite}}
		srv.StartTLS()
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := New(config.Hydra{AdminURL: srv.URL, Timeout: config.Duration(time.Second), MaxInFlight: 1}, config.TLS{MinVersion: "1.2", CAFile: ca})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Ready(context.Background()); (err == nil) != tt.ok {
			t.Errorf("%s: Ready = %v, want ok %v", tls.CipherSuiteName(tt.suite), err, tt.ok)
		}
		srv.Close()
	}
}
