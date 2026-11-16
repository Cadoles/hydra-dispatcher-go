package skipcheck

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

var (
	testKeyHex = strings.Repeat("ab", 32)
	testKey, _ = hex.DecodeString(testKeyHex)
	otherKey   = []byte(strings.Repeat("x", 32))
)

type snapshots struct{ s *store.Snapshot }

func (s snapshots) Snapshot() *store.Snapshot { return s.s }

// app answers as the app of the pre-check would: it checks the request's
// signature, then calls answer with what it received.
type app struct {
	t      *testing.T
	answer func(w http.ResponseWriter, got request)
	hits   atomic.Int32
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	ts := r.Header.Get(headerTimestamp)
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get(headerSignature) != sign(testKey, ts, body) {
		a.t.Errorf("request: %s %q %q", r.Method, r.Header.Get("Content-Type"), r.Header.Get(headerSignature))
	}
	var got request
	if err := json.Unmarshal(body, &got); err != nil {
		a.t.Errorf("body: %v", err)
	}
	a.answer(w, got)
}

// reply writes a signed answer, by key at the time at.
func reply(w http.ResponseWriter, key []byte, at time.Time, body string) {
	ts := strconv.FormatInt(at.Unix(), 10)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(headerTimestamp, ts)
	w.Header().Set(headerSignature, sign(key, ts, []byte(body)))
	_, _ = io.WriteString(w, body)
}

// newClient is a client of the app 2fa at url, declaring signals.
func newClient(url string, signals ...string) *Client {
	apps := []store.App{{ID: "2fa", LoginURL: "http://2fa.test/login", ConsentURL: "http://2fa.test/consent", Method: "otp",
		SkipCheckURL: url, SkipCheckKey: testKeyHex, SkipCheckSignals: signals}}
	return New(snapshots{store.NewSnapshot(apps, nil, store.DefaultSettings())}, nil)
}

var testCall = flow.SkipCheckCall{K: 2, App: "2fa", Subject: "alice", Device: "dev-2fa", ClientID: "portal", Flow: "sql-2fa",
	Claims: map[string]any{"email": json.RawMessage(`"alice@example.org"`)}, DeviceAt: time.Now().Add(-time.Hour).Unix()}

// browser is the context of a browser's request, as the middleware of the
// dispatcher gives it.
func browser(t *testing.T, remote string, headers map[string]string) context.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/dispatcher/loop", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	var ctx context.Context
	httpx.RealIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).ServeHTTP(httptest.NewRecorder(), r)
	return ctx
}

// A skip (P27b): the request signed, its members those of the protocol; the
// answer signed, its nonce back; its subject, context and tokens taken.
func TestCheckSkips(t *testing.T) {
	a := &app{t: t}
	a.answer = func(w http.ResponseWriter, got request) {
		if got.Version != 1 || len(got.Nonce) != 32 || got.Subject != "alice" || got.Device != "dev-2fa" || got.ClientID != "portal" ||
			got.Flow != "sql-2fa" || got.Step != "2fa" || got.Claims["email"] != "alice@example.org" || got.Attestation != nil || len(got.Signals) != 0 {
			t.Errorf("request: %+v", got)
		}
		reply(w, testKey, time.Now(), `{"nonce":"`+got.Nonce+`","skip":true,"subject":"alice","context":{"device":"known"},"id_token":{"email":"alice@example.org"},"access_token":null}`)
	}
	srv := httptest.NewServer(a)
	defer srv.Close()
	got := newClient(srv.URL).Check(context.Background(), testCall)
	if !got.Skip || got.Result != flow.SkipSkipped || got.Subject != "alice" || string(got.Context["device"]) != `"known"` ||
		string(got.IDToken["email"]) != `"alice@example.org"` || got.AccessToken != nil || got.Elapsed <= 0 {
		t.Errorf("answer: %+v", got)
	}
}

// The signals the app declares, and those alone, from the browser's request:
// the address truncated or whole, the User-Agent, the client hints, the
// languages, the age of the device.
func TestCheckSignals(t *testing.T) {
	headers := map[string]string{"User-Agent": "Firefox/140", "Accept-Language": "fr-FR,fr;q=0.9", "Sec-CH-UA-Platform": `"Linux"`, "Sec-CH-UA-Mobile": "?0", "Cookie": "secret=1"}
	for name, tt := range map[string]struct {
		remote  string
		signals []string
		want    string
	}{
		"none":     {"203.0.113.77:4000", nil, `{}`},
		"ip v4":    {"203.0.113.77:4000", []string{"ip"}, `{"ip":"203.0.113.0/24"}`},
		"ip v6":    {"[2001:db8:1:2:3::9]:4000", []string{"ip"}, `{"ip":"2001:db8:1::/48"}`},
		"full_ip":  {"203.0.113.77:4000", []string{"full_ip"}, `{"ip":"203.0.113.77"}`},
		"browser":  {"203.0.113.77:4000", []string{"user_agent", "accept_language", "client_hints"}, `{"accept_language":"fr-FR,fr;q=0.9","client_hints":{"Sec-CH-UA-Mobile":"?0","Sec-CH-UA-Platform":"\"Linux\""},"user_agent":"Firefox/140"}`},
		"no hints": {"203.0.113.77:4000", []string{"client_hints", "unknown"}, `{"client_hints":{}}`},
		"age":      {"203.0.113.77:4000", []string{"device_age"}, `{"device_age":3600}`},
	} {
		var signals string
		a := &app{t: t}
		srv := httptest.NewServer(a)
		h := headers
		if name == "no hints" {
			h = map[string]string{}
		}
		c := newClient(srv.URL, tt.signals...)
		now := time.Unix(testCall.DeviceAt+3600, 0)
		c.now = func() time.Time { return now }
		a.answer = func(w http.ResponseWriter, got request) {
			b, _ := json.Marshal(got.Signals)
			signals = string(b)
			reply(w, testKey, now, `{"nonce":"`+got.Nonce+`","skip":false}`)
		}
		if got := c.Check(browser(t, tt.remote, h), testCall); got.Result != flow.SkipDeclined || signals != tt.want {
			t.Errorf("%s: %s, %+v", name, signals, got)
		}
		srv.Close()
	}
}

// Every answer that is not a valid skip runs the step: declined when valid,
// failed otherwise, its cause named.
func TestCheckFails(t *testing.T) {
	ok := func(w http.ResponseWriter, got request, body string) { reply(w, testKey, time.Now(), body) }
	for name, tt := range map[string]struct {
		answer func(w http.ResponseWriter, got request)
		result string
		cause  string
	}{
		"declined":    {func(w http.ResponseWriter, g request) { ok(w, g, `{"nonce":"`+g.Nonce+`","skip":false}`) }, flow.SkipDeclined, ""},
		"skip absent": {func(w http.ResponseWriter, g request) { ok(w, g, `{"nonce":"`+g.Nonce+`"}`) }, flow.SkipDeclined, ""},
		"other key": {func(w http.ResponseWriter, g request) {
			reply(w, otherKey, time.Now(), `{"nonce":"`+g.Nonce+`","skip":true}`)
		}, flow.SkipFailed, "signature"},
		"unsigned": {func(w http.ResponseWriter, g request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"nonce":"`+g.Nonce+`","skip":true}`)
		}, flow.SkipFailed, "timestamp"},
		"stale": {func(w http.ResponseWriter, g request) {
			reply(w, testKey, time.Now().Add(-6*time.Minute), `{"nonce":"`+g.Nonce+`","skip":true}`)
		}, flow.SkipFailed, "timestamp"},
		"other nonce": {func(w http.ResponseWriter, g request) {
			ok(w, g, `{"nonce":"`+strings.Repeat("0", 32)+`","skip":true}`)
		}, flow.SkipFailed, "nonce"},
		"status": {func(w http.ResponseWriter, g request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
		}, flow.SkipFailed, "status"},
		"redirect": {func(w http.ResponseWriter, g request) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusFound)
		}, flow.SkipFailed, "status"},
		"html": {func(w http.ResponseWriter, g request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<p>ok</p>")
		}, flow.SkipFailed, "content_type"},
		"too large": {func(w http.ResponseWriter, g request) {
			ok(w, g, `{"nonce":"`+g.Nonce+`","skip":true,"pad":"`+strings.Repeat("a", maxAnswer)+`"}`)
		}, flow.SkipFailed, "too_large"},
		"not json": {func(w http.ResponseWriter, g request) { ok(w, g, `skip`) }, flow.SkipFailed, "form"},
		"context": {func(w http.ResponseWriter, g request) {
			ok(w, g, `{"nonce":"`+g.Nonce+`","skip":true,"context":["a"]}`)
		}, flow.SkipFailed, "form"},
		"slow": {func(w http.ResponseWriter, g request) {
			time.Sleep(Timeout + 100*time.Millisecond)
			ok(w, g, `{"nonce":"`+g.Nonce+`","skip":true}`)
		}, flow.SkipFailed, "timeout"},
	} {
		srv := httptest.NewServer(&app{t: t, answer: tt.answer})
		got := newClient(srv.URL).Check(context.Background(), testCall)
		if got.Skip || got.Result != tt.result || got.Cause != tt.cause {
			t.Errorf("%s: %+v", name, got)
		}
		srv.Close()
	}

	// Nothing to call: the app gone, its key unreadable, nobody listening.
	if got := newClient("http://127.0.0.1:1/skip").Check(context.Background(), flow.SkipCheckCall{App: "gone"}); got.Cause != "no_url" {
		t.Errorf("gone: %+v", got)
	}
	c := newClient("http://127.0.0.1:1/skip")
	c.config.Snapshot().Apps[0].SkipCheckKey = "short"
	if got := c.Check(context.Background(), testCall); got.Cause != "key" {
		t.Errorf("key: %+v", got)
	}
	if got := newClient("http://127.0.0.1:1/skip").Check(context.Background(), testCall); got.Result != flow.SkipFailed || got.Cause != "unreachable" {
		t.Errorf("unreachable: %+v", got)
	}
}
