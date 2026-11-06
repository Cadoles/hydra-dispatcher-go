package hydra

import (
	"bufio"
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
	"unicode/utf8"

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
		"DELETE /admin/oauth2/auth/sessions/login":       reply(204, ""),
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
	if err := c.RevokeLoginSession(ctx, "the-session"); err != nil {
		t.Errorf("RevokeLoginSession = %v", err)
	}
	if got := fake.got[len(fake.got)-1].URL.Query().Get("sid"); got != "the-session" {
		t.Errorf("sid sent as %q", got)
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
		// Hydra's own 4xx (unknown, handled, expired, refused) are the
		// recorded answers of TestRecordedHydraAnswers; these are the rest.
		{"another Hydra 4xx", reply(403, `{"error":"request_forbidden"}`), false, 403, ""},
		{"server error", reply(500, `{"error":"boom"}`), true, 500, ""},
		// A gateway quoting the URL it was asked: the challenge stays out.
		{"server error quoting the request", func(w http.ResponseWriter, r *http.Request) {
			reply(502, `{"error":"bad_gateway","error_description":"upstream failed for `+r.URL.RequestURI()+` (`+r.URL.Query().Get("login_challenge")+`)"}`)(w, r)
		}, true, 502, ""},
		{"unexpected 200", reply(200, `{"unexpected":true}`), true, 200, ""},
		{"empty 200", reply(200, ""), true, 200, ""},
		{"null 200", reply(200, "null"), true, 200, ""},
		{"incomplete 200", reply(200, `{"challenge":"C","client":{},"request_url":"","skip":false,"subject":"","redirect_to":""}`), true, 200, ""},
		{"XML 200", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<html><body>blocked</body></html>")
		}, true, 200, ""},
		{"oversized 200", reply(200, `{"challenge":"`+strings.Repeat("a", maxBody)+`"}`), true, 200, ""},
		// Hydra's public port, or a proxy: a broken setup, not an unknown challenge.
		{"404 page", http.NotFound, true, 404, ""},
		// A gateway in front of the admin API, whose JSON is not Hydra's.
		{"gateway refusal", reply(401, `{"error":"unauthorized"}`), true, 401, ""},
		{"gateway rate limit", reply(429, `{"error":"rate_limited"}`), true, 429, ""},
		{"null error", reply(404, `{"error":null}`), true, 404, ""},
		// Hydra's members by their exact names: a struct takes any case.
		{"error of another case", reply(404, `{"Error":"not_found"}`), true, 404, ""},
		{"redirect_to of another case", reply(410, `{"Redirect_To":"http://oidc.client.test/cb"}`), true, 410, ""},
		{"redirect_to outside a 410", reply(404, `{"redirect_to":"http://oidc.client.test/cb"}`), true, 404, ""},
		{"4xx cut short", cutBody(410), true, 410, ""},
		{"redirect", http.RedirectHandler("/elsewhere", http.StatusTemporaryRedirect).ServeHTTP, true, 307, ""},
		// No answer: no status.
		{"too slow", func(w http.ResponseWriter, _ *http.Request) { time.Sleep(200 * time.Millisecond) }, true, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(tt.handler))
			defer srv.Close()
			c := newTestClient(t, srv.URL, 4, 50*time.Millisecond)
			_, getErr := c.LoginRequest(context.Background(), challenge)
			_, acceptErr := c.AcceptLogin(context.Background(), challenge, ory.AcceptOAuth2LoginRequest{Subject: "alice"})

			for op, err := range map[string]error{"get_login_request": getErr, "accept_login": acceptErr} {
				if got := errors.Is(err, ErrUnavailable); got != tt.wantUnavail {
					t.Fatalf("err = %v, ErrUnavailable %v, want %v", err, got, tt.wantUnavail)
				}
				if strings.Contains(err.Error(), challenge) {
					t.Errorf("the challenge is in the error: %v", err)
				}
				var reqErr *RequestError
				var unavailable *UnavailableError
				switch {
				case tt.wantUnavail:
					if !errors.As(err, &unavailable) || unavailable.Op != op || unavailable.Status != tt.wantStatus {
						t.Errorf("err = %#v, want an UnavailableError of %s with status %d", err, op, tt.wantStatus)
					}
				case !errors.As(err, &reqErr) || reqErr.Op != op || reqErr.Status != tt.wantStatus || reqErr.RedirectTo() != tt.wantRedirect || len(reqErr.Body) == 0:
					t.Errorf("err = %#v, want a RequestError %d of %s redirecting to %q with Hydra's body", err, tt.wantStatus, op, tt.wantRedirect)
				}
			}
		})
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // refused connections
	// A gateway's credentials in admin_url stay out too.
	adminURL := strings.Replace(srv.URL, "://", "://dispatcher:SENTINEL-PASSWORD@", 1)
	_, err := newTestClient(t, adminURL, 4, time.Second).LoginRequest(context.Background(), challenge)
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) || unavailable.Status != 0 || strings.Contains(err.Error(), challenge) || strings.Contains(err.Error(), "SENTINEL-PASSWORD") {
		t.Errorf("connection refused: err = %v, want ErrUnavailable without status, the challenge nor the password", err)
	}
}

// Hydra's error document reaches the login apps as Hydra wrote it.
func TestRequestErrorBodyAsServed(t *testing.T) {
	const sent = "{ \"error\" : \"request_forbidden\",\n  \"error_hint\": \"Field 'subject' does not match.\", \"x_hydra_next\": 12345678901234567891 }\n"
	srv := httptest.NewServer(http.HandlerFunc(reply(http.StatusForbidden, sent)))
	defer srv.Close()
	_, err := newTestClient(t, srv.URL, 1, time.Second).AcceptLogin(context.Background(), "L", ory.AcceptOAuth2LoginRequest{Subject: "alice"})
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || string(reqErr.Body) != sent {
		t.Errorf("err = %v, want a RequestError with the body as sent", err)
	}
}

// A body cut short says so, whatever the status: neither a document missing
// nor a cause.
func TestUnreadBody(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusBadGateway} {
		srv := httptest.NewServer(http.HandlerFunc(cutBody(status)))
		_, err := newTestClient(t, srv.URL, 1, time.Second).LoginRequest(context.Background(), "L")
		srv.Close()
		if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), fmt.Sprintf("status %d while reading the body: ", status)) {
			t.Errorf("%d cut short: err = %v", status, err)
		}
	}
}

// RejectLogout reads no body: any 2xx is done, the rest is classified as for
// the other calls.
func TestRejectLogoutAnswers(t *testing.T) {
	for _, tt := range []struct {
		status      int
		body        string
		wantStatus  int // of the error, 0 for none
		wantUnavail bool
	}{
		{204, "", 0, false},
		{200, `{"unexpected":true}`, 0, false},
		{404, `{"error":"Not Found","error_description":"Unable to locate the resource"}`, 404, false},
		{307, "", 307, true},
		{500, `{"error":"boom"}`, 500, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(reply(tt.status, tt.body)))
		err := newTestClient(t, srv.URL, 1, time.Second).RejectLogout(context.Background(), "U")
		srv.Close()
		var reqErr *RequestError
		var unavailable *UnavailableError
		switch {
		case tt.wantStatus == 0 && err != nil,
			tt.wantStatus != 0 && tt.wantUnavail && (!errors.As(err, &unavailable) || unavailable.Status != tt.wantStatus),
			tt.wantStatus != 0 && !tt.wantUnavail && (!errors.As(err, &reqErr) || reqErr.Status != tt.wantStatus):
			t.Errorf("%d %s: err = %v", tt.status, tt.body, err)
		}
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

	// /health/ready names its failed checks instead.
	ready := httptest.NewServer(http.HandlerFunc(reply(503, `{"errors":{"migrations":"pending","database":"dial tcp: connection refused"}}`)))
	defer ready.Close()
	err = newTestClient(t, ready.URL, 4, time.Second).Ready(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 503 (database: dial tcp: connection refused; migrations: pending)") {
		t.Errorf("Ready = %v, want the failed checks", err)
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

// What no call can show in a test. Hydra is called directly, never through
// HTTP_PROXY: setting it would not tell, as ProxyFromEnvironment skips
// loopback addresses and reads the environment once per process. Idle
// connections are closed before Hydra closes them, after 120 s.
func TestTransportSettings(t *testing.T) {
	transport, err := newTransport(config.Hydra{Timeout: config.Duration(time.Second), MaxInFlight: 1}, config.TLS{MinVersion: "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil {
		t.Error("the transport takes a proxy")
	}
	if d := transport.IdleConnTimeout; d <= 0 || d >= 120*time.Second {
		t.Errorf("IdleConnTimeout = %v, want below Hydra's 120 s", d)
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
	if n := c.InFlight(); n != 1 {
		t.Errorf("InFlight = %d during the first call, want 1", n)
	}
	close(release)
	if err := <-done; err != nil {
		t.Errorf("first call = %v", err)
	}
	if n := c.InFlight(); n != 0 {
		t.Errorf("InFlight = %d once done, want 0", n)
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
// transport would queue calls out of the cap's sight. Over HTTP/2, past the
// 250 streams Go's server (Hydra's) allows per connection, the client opens
// another rather than wait for a stream.
func TestConnectionsFollowTheCap(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			const n = 300 // above the 256 connections per host the transport used to allow
			var arrived atomic.Int32
			var queued, otherProto atomic.Bool
			all := make(chan struct{})
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if h2 && r.ProtoMajor != 2 {
					otherProto.Store(true)
				}
				if arrived.Add(1) == n {
					close(all)
				}
				select {
				case <-all:
				case <-time.After(2 * time.Second):
					queued.Store(true)
				}
			}))
			tlsConfig := config.TLS{MinVersion: "1.2"}
			if h2 {
				srv.EnableHTTP2 = true
				srv.StartTLS()
				tlsConfig = config.TLS{MinVersion: "1.3", CAFile: caFile(t, srv)}
			} else {
				srv.Start()
			}
			defer srv.Close()
			c, err := New(config.Hydra{AdminURL: srv.URL, Timeout: config.Duration(10 * time.Second), MaxInFlight: n}, tlsConfig)
			if err != nil {
				t.Fatal(err)
			}

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
			if otherProto.Load() {
				t.Error("a call did not go over HTTP/2")
			}
		})
	}
}

// Connections are kept for the next calls, up to the cap: Go's default of 2
// idle connections per host would open one per call under load.
func TestIdleConnectionsKept(t *testing.T) {
	const n = 16
	var opened atomic.Int32
	var mu sync.Mutex
	waiting, release := 0, make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Each wave's calls are held until all have arrived: n connections.
		mu.Lock()
		wave := release
		if waiting++; waiting == n {
			close(release)
			waiting, release = 0, make(chan struct{})
		}
		mu.Unlock()
		select {
		case <-wave:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	c := newTestClient(t, srv.URL, n, 5*time.Second)

	for range 2 {
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				if err := c.RejectLogout(context.Background(), "U"); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	}
	if got := opened.Load(); got != n {
		t.Errorf("%d connections opened for two waves of %d calls, want %d", got, n, n)
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

// /health/ready has no 4xx and answers JSON: anything else is Hydra
// unavailable, even an error document.
func TestReadyAnswers(t *testing.T) {
	for _, tt := range []struct {
		status            int
		contentType, body string
	}{
		{http.StatusNotFound, "application/json", `{"error":"Not Found","error_description":"Unable to locate the resource"}`},
		{http.StatusGone, "application/json", `{"redirect_to":"http://oidc.client.test/cb"}`},
		{http.StatusOK, "text/plain", "ok"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tt.contentType)
			w.WriteHeader(tt.status)
			_, _ = io.WriteString(w, tt.body)
		}))
		err := newTestClient(t, srv.URL, 1, time.Second).Ready(context.Background())
		srv.Close()
		var unavailable *UnavailableError
		if !errors.As(err, &unavailable) || unavailable.Op != "ready" || unavailable.Status != tt.status {
			t.Errorf("%d %s: Ready = %#v, want an UnavailableError of ready with that status", tt.status, tt.body, err)
		}
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

// What the log says of a failed call: never a server's free text, which serverCause
// only masks of the request's own query values.
func TestFailure(t *testing.T) {
	const challenge, sid, email = "secret-challenge", "secret-sid", "alice@example.com"
	for _, tt := range []struct {
		name    string
		handler http.HandlerFunc
		status  int
		cause   string
	}{
		{"a 500, its document quoting a sid and a subject", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"failed for ` + sid + ` ` + email + `"}`))
		}, 500, "500 Internal Server Error"},
		{"a 404 from elsewhere", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(email))
		}, 404, "without Hydra's error document: 404 Not Found"},
		{"a 200 cut short", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"subject":"` + email + `"`))
		}, 200, "unexpected end of JSON input"},
		{"a redirect quoting the challenge", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://elsewhere.invalid/?c="+challenge, http.StatusFound)
		}, 302, "302 Found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			c := newTestClient(t, srv.URL, 4, time.Second)
			_, err := c.LogoutRequest(context.Background(), challenge)
			op, status, cause := Failure(err)
			if op != "get_logout_request" || status != tt.status || cause != tt.cause {
				t.Errorf("Failure: %q %d %q, want the status %d and the cause %q", op, status, cause, tt.status, tt.cause)
			}
			for _, secret := range []string{challenge, sid, email, srv.URL} {
				if strings.Contains(cause, secret) {
					t.Errorf("%q in the cause %q", secret, cause)
				}
			}
		})
	}
	t.Run("no answer", func(t *testing.T) {
		c := newTestClient(t, "http://127.0.0.1:1", 4, time.Second)
		err := c.RevokeLoginSession(context.Background(), sid)
		op, status, cause := Failure(err)
		if op != "revoke_login_session" || status != 0 || !strings.Contains(cause, "connection refused") || strings.Contains(cause, sid) {
			t.Errorf("Failure: %q %d %q", op, status, cause)
		}
	})
	t.Run("a refusal, without its body", func(t *testing.T) {
		if op, status, cause := Failure(&RequestError{Op: "accept_login", Status: 409, Body: []byte(email)}); op != "accept_login" || status != 409 || cause != "" {
			t.Errorf("Failure: %q %d %q", op, status, cause)
		}
	})
	t.Run("a cause at most maxCause", func(t *testing.T) {
		// Cut inside a character: maxCause is even, and é two bytes.
		_, _, cause := Failure(&UnavailableError{Op: "op", err: errors.New("x" + strings.Repeat("é", maxCause))})
		if len(cause) > maxCause+len("…") || !utf8.ValidString(cause) || !strings.HasSuffix(cause, "…") {
			t.Errorf("%d bytes: %q", len(cause), cause)
		}
	})
	t.Run("the time of the call", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer srv.Close()
		_, err := newTestClient(t, srv.URL, 4, time.Second).LogoutRequest(context.Background(), challenge)
		if d := Elapsed(err); d < 20*time.Millisecond {
			t.Errorf("Elapsed %s", d)
		}
		if d := Elapsed(errors.New(email)); d != 0 {
			t.Errorf("not a call: Elapsed %s", d)
		}
	})
	t.Run("not a call", func(t *testing.T) {
		if op, status, cause := Failure(errors.New(email)); op != "" || status != 0 || cause != "" {
			t.Errorf("Failure: %q %d %q", op, status, cause)
		}
	})
}

// rawAnswer answers each connection with the bytes given, whatever the request; REQ
// stands for the request's first line.
func rawAnswer(t *testing.T, answer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				first, _ := r.ReadString('\n')
				for {
					if l, err := r.ReadString('\n'); err != nil || l == "\r\n" {
						break
					}
				}
				_, _ = c.Write([]byte(strings.ReplaceAll(answer, "REQ", strings.TrimSpace(first))))
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

// What a server or a gateway answers, on every call, never reaches the cause of the
// log: no value it quotes, whatever carries it, and a bounded length (Q64).
func TestFailureKeepsNoValue(t *testing.T) {
	const challenge, value, element = "the-challenge-0123456789", "the-sid-alice@example.org", "the-sid-alice"
	answer := func(status, contentType, body string, headers ...string) string {
		return fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n%s",
			status, contentType, len(body), strings.Join(append(headers, ""), "\r\n"), body)
	}
	long := strings.Repeat("x", 3000)
	ctx := context.Background()
	calls := map[string]func(c *Client) error{
		"get_login": func(c *Client) error { _, err := c.LoginRequest(ctx, challenge); return err },
		"accept_login": func(c *Client) error {
			_, err := c.AcceptLogin(ctx, challenge, ory.AcceptOAuth2LoginRequest{Subject: "s"})
			return err
		},
		"reject_login": func(c *Client) error { _, err := c.RejectLogin(ctx, challenge, ory.RejectOAuth2Request{}); return err },
		"get_consent":  func(c *Client) error { _, err := c.ConsentRequest(ctx, challenge); return err },
		"accept_consent": func(c *Client) error {
			_, err := c.AcceptConsent(ctx, challenge, ory.AcceptOAuth2ConsentRequest{})
			return err
		},
		"reject_consent": func(c *Client) error {
			_, err := c.RejectConsent(ctx, challenge, ory.RejectOAuth2Request{})
			return err
		},
		"get_logout":    func(c *Client) error { _, err := c.LogoutRequest(ctx, challenge); return err },
		"accept_logout": func(c *Client) error { _, err := c.AcceptLogout(ctx, challenge); return err },
		"reject_logout": func(c *Client) error { return c.RejectLogout(ctx, challenge) },
		"revoke":        func(c *Client) error { return c.RevokeLoginSession(ctx, challenge) },
	}
	for name, raw := range map[string]string{
		"a 5xx document":                answer("500 Internal Server Error", "application/json", `{"error":"server_error","error_description":"`+value+`"}`),
		"a 5xx, its status line":        answer("502 upstream said "+value, "text/plain", value),
		"a 5xx document, its line":      answer("502 upstream said "+value, "application/json", `{"error":"x"}`),
		"a long status line":            answer("502 "+long, "text/plain", "x"),
		"a 4xx, its status line":        answer("403 refused "+value, "text/plain", value),
		"a 429 document":                answer("429 Too Many Requests", "application/json", `{"error":"slow","error_description":"`+value+`"}`),
		"a redirect, its status line":   answer("302 moved "+value, "text/plain", "", "Location: http://elsewhere.invalid/"),
		"a Location unread":             answer("302 Found", "text/plain", "", "Location: http://[bad/?sid="+value),
		"a 200, not JSON":               answer("200 OK", "application/json", "sid="+value),
		"a 200, a date":                 answer("200 OK", "application/json", `{"challenge":"c","subject":"s","sid":"i","request_url":"http://x","requested_at":"`+value+`"}`),
		"no HTTP":                       "sid=" + value + "\r\n",
		"no HTTP, the request repeated": "REQ upstream error\r\n",
		"no HTTP, long":                 long + "\r\n",
		"an unread status":              "HTTP/1.1 abc " + value + "\r\n\r\n",
		"an unread header":              "HTTP/1.1 200 OK\r\n" + value + "\r\n\r\n",
		"an unread length":              "HTTP/1.1 200 OK\r\nContent-Length: " + value + "\r\n\r\n",
		"a 200 XML, an element":         answer("200 OK", "application/xml", "<"+element+"/>"),
		"a 200 XML, closed by another":  answer("200 OK", "application/xml", "<a>x</"+element+">"),
		"a 200 XML, a broken element":   answer("200 OK", "application/xml", "</"+value+">"),
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, rawAnswer(t, raw), 16, 2*time.Second)
			for op, call := range calls {
				err := call(c)
				if err == nil {
					continue // 200 without a body to read: the reject and the delete
				}
				_, _, cause := Failure(err)
				if strings.Contains(cause, element) || strings.Contains(cause, challenge) || len(cause) > maxCause+len("…") {
					t.Errorf("%s: the cause %q", op, cause)
				}
			}
		})
	}
}

// Error, which ready.check_failed writes, holds what the cause holds, its own bound
// included, and the failed checks of /health/ready; encoding/json's '<' is no citation.
func TestErrorKeepsNoValue(t *testing.T) {
	const value = "the-sid-alice"
	for name, raw := range map[string]string{
		"no HTTP":     "sid=" + value + "\r\n",
		"long":        strings.Repeat("x", 3000) + value + "\r\n",
		"status line": "HTTP/1.1 502 upstream said " + value + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		"a header":    "HTTP/1.1 200 OK\r\n" + value + "\r\n\r\n",
	} {
		err := newTestClient(t, rawAnswer(t, raw), 4, 2*time.Second).Ready(context.Background())
		if err == nil || strings.Contains(err.Error(), value) || len(err.Error()) > 2*maxCause {
			t.Errorf("%s: %d bytes: %v", name, len(fmt.Sprint(err)), err)
		}
	}
	if msg := (&UnavailableError{Op: "op", Status: 500}).Error(); msg != "op: hydra unavailable: status 500" {
		t.Errorf("no underlying error: %q", msg)
	}
	if msg := (&UnavailableError{Op: "op", err: errors.New(strings.Repeat("x", 3*maxCause))}).Error(); len(msg) > 2*maxCause {
		t.Errorf("no bound: %d bytes", len(msg))
	}
	// What stays says something, without a loose end.
	for raw, want := range map[string]string{
		"sid=" + value + "\r\n": "net/http: HTTP/1.x transport connection broken: malformed HTTP response",
		"HTTP/1.1 599 " + value + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n": "599",
	} {
		err := newTestClient(t, rawAnswer(t, raw), 4, 2*time.Second).Ready(context.Background())
		if _, _, cause := Failure(err); cause != want {
			t.Errorf("the cause %q, want %q", cause, want)
		}
	}
	html := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<html>"
	_, err := newTestClient(t, rawAnswer(t, html), 4, 2*time.Second).LogoutRequest(context.Background(), "x")
	if _, _, cause := Failure(err); !strings.Contains(cause, "invalid character '<'") {
		t.Errorf("the cause of an HTML answer: %q", cause)
	}
}
