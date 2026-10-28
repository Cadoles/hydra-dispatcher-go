package hydra

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
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
		// Hydra 2.2 and later, on an expired login or consent request.
		{"expired", reply(401, `{"error":"request_unauthorized","error_description":"The request could not be authorized.","error_hint":"The login request has expired, please try again.","status_code":401}`), false, 401, ""},
		{"another subject", reply(403, `{"error":"request_forbidden","error_hint":"Field 'subject' does not match subject from previous authentication."}`), false, 403, ""},
		{"conflict", reply(409, `{"error":"Conflict","error_description":"The login request was already used and can no longer be changed."}`), false, 409, ""},
		{"refused body", reply(400, `{"error":"invalid_request"}`), false, 400, ""},
		{"server error", reply(500, `{"error":"boom"}`), true, 0, ""},
		// A gateway quoting the URL it was asked: the challenge stays out.
		{"server error quoting the request", func(w http.ResponseWriter, r *http.Request) {
			reply(502, `{"error":"bad_gateway","error_description":"upstream failed for `+r.URL.RequestURI()+` (`+r.URL.Query().Get("login_challenge")+`)"}`)(w, r)
		}, true, 0, ""},
		{"unexpected 200", reply(200, `{"unexpected":true}`), true, 0, ""},
		{"empty 200", reply(200, ""), true, 0, ""},
		{"null 200", reply(200, "null"), true, 0, ""},
		{"incomplete 200", reply(200, `{"challenge":"C","client":{},"request_url":"","skip":false,"subject":"","redirect_to":""}`), true, 0, ""},
		{"XML 200", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<html><body>blocked</body></html>")
		}, true, 0, ""},
		{"oversized 200", reply(200, `{"challenge":"`+strings.Repeat("a", maxBody)+`"}`), true, 0, ""},
		// Hydra's public port, or a proxy: a broken setup, not an unknown challenge.
		{"404 page", http.NotFound, true, 0, ""},
		// A gateway in front of the admin API, whose JSON is not Hydra's.
		{"gateway refusal", reply(401, `{"error":"unauthorized"}`), true, 0, ""},
		{"gateway rate limit", reply(429, `{"error":"rate_limited"}`), true, 0, ""},
		{"null error", reply(404, `{"error":null}`), true, 0, ""},
		{"redirect_to outside a 410", reply(404, `{"redirect_to":"http://oidc.client.test/cb"}`), true, 0, ""},
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
	// A gateway's credentials in admin_url stay out too.
	adminURL := strings.Replace(srv.URL, "://", "://dispatcher:SENTINEL-PASSWORD@", 1)
	_, err := newTestClient(t, adminURL, 4, time.Second).LoginRequest(context.Background(), challenge)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), challenge) || strings.Contains(err.Error(), "SENTINEL-PASSWORD") {
		t.Errorf("connection refused: err = %v, want ErrUnavailable without the challenge nor the password", err)
	}
}

// A 5xx keeps Hydra's error and its description, which the SDK's message
// leaves out, bounded and without the request's query values.
func TestServerErrorCause(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(500, `{"error":"server_error","error_description":"pq: connection refused (`+r.URL.RawQuery+`, `+r.URL.Query().Get("login_challenge")+`)`+strings.Repeat(" x", 500)+`"}`)(w, r)
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv.URL, 4, time.Second).LoginRequest(context.Background(), "L+/=")
	msg := err.Error()
	if !strings.Contains(msg, "(server_error: pq: connection refused (login_challenge=…, …) x x") ||
		strings.Contains(msg, "L+/=") || strings.Contains(msg, "L%2B%2F%3D") || len(msg) > 400 {
		t.Errorf("err = %v, want Hydra's error and description, bounded, without the challenge", err)
	}
}

// ErrUnavailable keeps its cause: a caller that gave up is not Hydra down,
// and hydra.timeout feeds hydra_rejected_total{reason="timeout"}.
func TestErrorCauses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestClient(t, srv.URL, 4, time.Second).LoginRequest(ctx, "L")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Errorf("caller gone: err = %v, want ErrUnavailable and context.Canceled", err)
	}

	_, err = newTestClient(t, srv.URL, 4, 50*time.Millisecond).LoginRequest(context.Background(), "L")
	var netErr net.Error
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("hydra.timeout: err = %v, want ErrUnavailable and a timeout", err)
	}

	// The same once the headers are in: the SDK reads the body inside the call.
	slowBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"challenge":`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer slowBody.Close()
	_, err = newTestClient(t, slowBody.URL, 4, 50*time.Millisecond).LoginRequest(context.Background(), "L")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("hydra.timeout in the body: err = %v, want ErrUnavailable and a timeout", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err = newTestClient(t, slowBody.URL, 4, time.Second).LoginRequest(ctx, "L")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Errorf("caller gone in the body: err = %v, want ErrUnavailable and context.Canceled", err)
	}
}

// 2 s for the TLS handshake, whatever hydra.timeout.
func TestTLSHandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // accepts, never answers
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	start := time.Now()
	err = newTestClient(t, "https://"+ln.Addr().String(), 1, 10*time.Second).RejectLogout(context.Background(), "U")
	var netErr net.Error
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &netErr) || !netErr.Timeout() || time.Since(start) > 3*time.Second {
		t.Errorf("err = %v after %v, want a timeout after 2 s", err, time.Since(start))
	}
}

// silentProxy forwards TCP connections to target. silence makes those
// opened so far swallow everything, without a reset, as when Hydra's node is
// gone; later ones still forward.
func silentProxy(t *testing.T, target string) (addr string, silence func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var silent []*atomic.Bool
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			s := new(atomic.Bool)
			mu.Lock()
			conns, silent = append(conns, client, server), append(silent, s)
			mu.Unlock()
			forward := func(dst, src net.Conn) {
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 && !s.Load() {
						if _, err := dst.Write(buf[:n]); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go forward(server, client)
			go forward(client, server)
		}
	}()
	return ln.Addr().String(), func() {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range silent {
			s.Store(true)
		}
	}
}

// Over HTTP/2, a connection that stops answering is dropped after an
// unanswered ping, rather than taking every call multiplexed on it until
// TCP gives up.
func TestDeadHTTP2Connection(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	addr, silence := silentProxy(t, srv.Listener.Addr().String())
	c, err := New(config.Hydra{AdminURL: "https://" + addr, Timeout: config.Duration(200 * time.Millisecond), MaxInFlight: 4},
		config.TLS{MinVersion: "1.3", CAFile: caFile(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RejectLogout(context.Background(), "U"); err != nil {
		t.Fatal(err)
	}

	silence()
	deadline := time.Now().Add(6 * time.Second)
	for {
		err := c.RejectLogout(context.Background(), "U")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("calls still fail on the dead connection: %v", err)
		}
	}
}

// caFile writes the certificate of a TLS test server, as a dedicated CA.
func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return ca
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

// A probe that gives up, waiting for its turn or while calling Hydra, leaves
// no answer behind for the next one.
func TestReadyGivesUp(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		reply(http.StatusOK, `{"status":"ok"}`)(w, r)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, 1, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Ready(ctx) }()
	<-entered
	waiting, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err := c.Ready(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("probe waiting for its turn = %v, want its deadline", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("probe cancelled while calling = %v, want context.Canceled", err)
	}
	close(release)
	if err := c.Ready(context.Background()); err != nil {
		t.Errorf("next probe = %v, want Hydra's answer, not a cached cancellation", err)
	}
}

// With a dedicated CA, and HTTP/2 negotiated as Hydra serves it over TLS.
func TestTLSWithDedicatedCA(t *testing.T) {
	protos := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case protos <- r.Proto:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	withCA, err := New(config.Hydra{AdminURL: srv.URL, Timeout: config.Duration(time.Second), MaxInFlight: 1}, config.TLS{MinVersion: "1.3", CAFile: caFile(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	if err := withCA.Ready(context.Background()); err != nil {
		t.Errorf("with the CA: %v", err)
	} else if proto := <-protos; proto != "HTTP/2.0" {
		t.Errorf("with the CA: Hydra called over %s, want HTTP/2.0", proto)
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
		c, err := New(config.Hydra{AdminURL: srv.URL, Timeout: config.Duration(time.Second), MaxInFlight: 1}, config.TLS{MinVersion: "1.2", CAFile: caFile(t, srv)})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Ready(context.Background()); (err == nil) != tt.ok {
			t.Errorf("%s: Ready = %v, want ok %v", tls.CipherSuiteName(tt.suite), err, tt.ok)
		}
		srv.Close()
	}
}
