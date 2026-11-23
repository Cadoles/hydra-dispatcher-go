package webhook

import (
	"context"
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

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The transport of the HTTP calls: no proxy, an idle connection closed after 30 s
// (Q84), a ping on a silent HTTP/2 connection (R28).
func TestTransportSettings(t *testing.T) {
	transport := newClient(t).http.Transport.(*http.Transport)
	switch {
	case transport.Proxy != nil:
		t.Error("the transport takes a proxy")
	case transport.IdleConnTimeout != httpx.IdleConnTimeout || httpx.IdleConnTimeout != 30*time.Second:
		t.Errorf("IdleConnTimeout = %v, want 30 s", transport.IdleConnTimeout)
	case transport.HTTP2 == nil || transport.HTTP2.SendPingTimeout != httpTimeout || transport.HTTP2.PingTimeout != httpx.PingTimeout:
		t.Errorf("HTTP2 = %+v, want a ping after %v of silence", transport.HTTP2, httpTimeout)
	}
}

// A receiver that closes its idle connections before the client does, as a balancer
// whose idle timeout is under ours: the next call opens a connection, and passes (Q84).
func TestIdleConnectionsClosedFirst(t *testing.T) {
	var opened atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	srv.Config.IdleTimeout = 50 * time.Millisecond
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	c := newClient(t)
	for i := range 3 {
		if a := c.Login(context.Background(), loginCall(srv.URL)); a.Err != nil {
			t.Fatalf("call %d: %v", i, a.Err)
		}
		time.Sleep(150 * time.Millisecond) // the receiver closes the connection
	}
	if n := opened.Load(); n != 3 {
		t.Errorf("%d connections for 3 calls, each after the receiver closed the last one", n)
	}
}

// The frozen proxy of R28, over HTTP/2: the receiver stops answering on its
// connection, without a reset. One call fails, after the delay of a call; the ping,
// sent then, drops the connection when it stays unanswered, and the next call, a
// reload of page E1006, goes through a new one. Without the ping, every call failed,
// on the same connection. A call made within the delay of the ping after the
// failure still meets the frozen connection, and fails too.
func TestDeadHTTP2Connection(t *testing.T) {
	var proto atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int32(r.ProtoMajor))
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	addr, freeze, accepted := frozenProxy(t, srv.Listener.Addr().String())
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writePEM(t, caFile, srv)
	c, err := New(config.Webhooks{CAFile: caFile, ProcessTimeout: config.Duration(time.Second), MaxProcesses: 1}, "1.3", testKey)
	if err != nil {
		t.Fatal(err)
	}
	// The delay of a call and that of the ping, 5 s and 2 s, shortened in the same
	// ratio; HYDRA_DISPATCHER_REAL_DELAYS plays them as they are.
	tlsConfig, err := httpx.ClientTLS("1.3", caFile)
	if err != nil {
		t.Fatal(err)
	}
	timeout, ping := 250*time.Millisecond, 100*time.Millisecond
	if os.Getenv("HYDRA_DISPATCHER_REAL_DELAYS") != "" {
		timeout, ping = httpTimeout, httpx.PingTimeout
	}
	c.http = newHTTPClient(tlsConfig, timeout, ping)
	defer c.http.CloseIdleConnections()
	url := "https://" + addr

	if a := c.Login(context.Background(), loginCall(url)); a.Err != nil {
		t.Fatal(a.Err)
	}
	if p := proto.Load(); p != 2 {
		t.Fatalf("HTTP/%d, want HTTP/2", p)
	}
	freeze()
	if a := c.Login(context.Background(), loginCall(url)); a.Err == nil {
		t.Fatal("a call passed through the frozen connection")
	}
	time.Sleep(ping + ping/2) // the user reads page E1006, and reloads it
	if a := c.Login(context.Background(), loginCall(url)); a.Err != nil {
		t.Errorf("the call after the failure: %v, want a new connection", a.Err)
	}
	if n := accepted(); n != 2 {
		t.Errorf("%d connections, want a new one after the failure", n)
	}
}

// frozenProxy forwards TCP to target until freeze: then the connections open stop
// forwarding, neither closed nor reset, as a peer gone or a frozen proxy; new ones
// forward. accepted counts the connections.
func frozenProxy(t *testing.T, target string) (addr string, freeze func(), accepted func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var frozen []*atomic.Bool
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
			f := new(atomic.Bool)
			mu.Lock()
			conns, frozen = append(conns, client, server), append(frozen, f)
			mu.Unlock()
			forward := func(dst, src net.Conn) {
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 && !f.Load() {
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
			for _, f := range frozen {
				f.Store(true)
			}
		}, func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(frozen)
		}
}

// A webhook run as a local program is warned of when secrets come from the environment
// (Q87), never otherwise.
func TestProgramWarnings(t *testing.T) {
	for _, tt := range []struct {
		login, consent string
		fromEnv        []string
		want           string
	}{
		{"/opt/hook", "", []string{"secrets.cookie_key"}, "setting login_accept_webhook_url runs a local program"},
		{"file:///opt/hook", "/opt/other", []string{"store.dsn"}, "settings login_accept_webhook_url and consent_accept_webhook_url run local programs"},
		{"https://hooks/login", "https://hooks/consent", []string{"secrets.cookie_key"}, ""},
		{"/opt/hook", "", nil, ""},
		{"", "", []string{"secrets.cookie_key"}, ""},
	} {
		s := store.DefaultSettings()
		s.LoginAcceptWebhookURL, s.ConsentAcceptWebhookURL = tt.login, tt.consent
		w := ProgramWarnings(s, tt.fromEnv)
		if tt.want == "" && len(w) > 0 || tt.want != "" && (len(w) != 1 || !strings.Contains(w[0], tt.want)) {
			t.Errorf("%q %q %q: %q", tt.login, tt.consent, tt.fromEnv, w)
		}
	}
}
