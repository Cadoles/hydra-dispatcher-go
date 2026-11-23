package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(config.Webhooks{ProcessTimeout: config.Duration(5 * time.Second), MaxProcesses: 4}, "1.2", testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.http.CloseIdleConnections)
	return c
}

// browserContext is the context of a request from a browser: the chain's
// middlewares fill what the payload says of it.
func browserContext(t *testing.T, remote, userAgent string) context.Context {
	t.Helper()
	var ctx context.Context
	h := httpx.Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() }), httpx.RealIP(nil), httpx.Trace(nil))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	r.Header.Set("User-Agent", userAgent)
	h.ServeHTTP(httptest.NewRecorder(), r)
	return ctx
}

const testClient = `{"client_id":"c1","client_name":"The client","logo_uri":"http://logo","tos_uri":"http://tos","policy_uri":"http://policy","client_secret":"never sent"}`

func loginCall(location string) flow.Call {
	return flow.Call{Op: flow.LoginHook, Challenge: "login-challenge", Hook: &flow.HookCall{Location: location, Client: json.RawMessage(testClient)},
		AcceptLogin: ory.AcceptOAuth2LoginRequest{
			Subject: "alice", Acr: ory.PtrString("2"), Amr: []string{"pwd", "otp"},
			Context: flow.Object{"k": json.RawMessage(`12345678901234567890`)}, Remember: ory.PtrBool(true), RememberFor: ory.PtrInt64(3600),
		}}
}

func consentCall(location string) flow.Call {
	return flow.Call{Op: flow.ConsentHook, Challenge: "consent-challenge",
		Hook: &flow.HookCall{Location: location, Client: json.RawMessage(testClient), Subject: "alice", ACR: "2", AMR: []string{"pwd"}, Context: flow.Object{"k": json.RawMessage(`1`)}},
		AcceptConsent: ory.AcceptOAuth2ConsentRequest{GrantScope: []string{"openid"}, GrantAccessTokenAudience: []string{"api"},
			Session: &ory.AcceptOAuth2ConsentRequestSession{AccessToken: flow.Object{"a": json.RawMessage(`1`)}, IdToken: flow.Object{"i": json.RawMessage(`2`)}}}}
}

// receiver is a webhook over HTTP: it keeps what it gets, and answers with answer.
type receiver struct {
	*httptest.Server
	mu      sync.Mutex
	headers http.Header
	body    []byte
	hits    atomic.Int32
}

func newReceiver(t *testing.T, status int, contentType, answer string) *receiver {
	t.Helper()
	r := &receiver{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.headers, r.body = req.Header.Clone(), body
		r.mu.Unlock()
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(r.Close)
	return r
}

// The payloads are Symfony's (AcceptRequestWebhookService), member for member and in
// its order; the consent's adds context (Q38). challenge stays L.
func TestPayloads(t *testing.T) {
	ctx := browserContext(t, "203.0.113.9:1234", "Firefox")
	browser := `"browser":{"ip":"203.0.113.9","user-agent":"Firefox"}`
	client := `"client":{"client_id":"c1","client_name":"The client","logo_uri":"http://logo","tos_uri":"http://tos","policy_uri":"http://policy"}`
	t.Run("login", func(t *testing.T) {
		r := newReceiver(t, 200, "application/json", `{}`)
		if a := newClient(t).Login(ctx, loginCall(r.URL)); a.Err != nil {
			t.Fatal(a.Err)
		}
		want := `{"challenge":"login-challenge","subject":"alice","acr":"2","amr":["pwd","otp"],"context":{"k":12345678901234567890},"remember":true,"remember_for":3600,` + browser + `,` + client + `}`
		if string(r.body) != want {
			t.Errorf("payload\n got %s\nwant %s", r.body, want)
		}
	})
	t.Run("consent", func(t *testing.T) {
		r := newReceiver(t, 200, "application/json", `{}`)
		if a := newClient(t).Consent(ctx, consentCall(r.URL)); a.Err != nil {
			t.Fatal(a.Err)
		}
		want := `{"challenge":"consent-challenge","subject":"alice","acr":"2","amr":["pwd"],"context":{"k":1},"grant_scope":["openid"],"grant_access_token_audience":["api"],"access_token":{"a":1},"id_token":{"i":2},` + browser + `,` + client + `}`
		if string(r.body) != want {
			t.Errorf("payload\n got %s\nwant %s", r.body, want)
		}
	})
	t.Run("what is unknown is null, a list stays a list", func(t *testing.T) {
		r := newReceiver(t, 200, "application/json", `{}`)
		call := loginCall(r.URL)
		call.Hook.Client = json.RawMessage(`null`)
		call.AcceptLogin.Amr = nil
		if a := newClient(t).Login(context.Background(), call); a.Err != nil {
			t.Fatal(a.Err)
		}
		for _, want := range []string{`"amr":[]`, `"browser":{"ip":null,"user-agent":null}`, `"client":{"client_id":null,"client_name":null,"logo_uri":null,"tos_uri":null,"policy_uri":null}`} {
			if !strings.Contains(string(r.body), want) {
				t.Errorf("no %s in %s", want, r.body)
			}
		}
	})
}

// The signature a receiver checks (Durcissements, webhooks signés).
func TestSignature(t *testing.T) {
	r := newReceiver(t, 200, "application/json", `{}`)
	c := newClient(t)
	at := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return at }
	ctx := httpx.WithTraceID(context.Background(), "trace-1")
	if a := c.Login(ctx, loginCall(r.URL)); a.Err != nil {
		t.Fatal(a.Err)
	}
	if got := r.headers.Get(HeaderTimestamp); got != strconv.FormatInt(at.Unix(), 10) {
		t.Errorf("timestamp %q", got)
	}
	mac := hmac.New(sha256.New, testKey)
	fmt.Fprintf(mac, "%d.%s", at.Unix(), r.body)
	if got, want := r.headers.Get(HeaderSignature), hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("signature %q, want %q", got, want)
	}
	for name, want := range map[string]string{"Content-Type": "application/json", "User-Agent": userAgent, "X-Trace-Id": "trace-1"} {
		if got := r.headers.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// A changed member of what was sent does not verify: the receiver can refuse it.
func TestSignatureCoversTheBody(t *testing.T) {
	if sign(testKey, "1", []byte(`{"subject":"alice"}`)) == sign(testKey, "1", []byte(`{"subject":"bob"}`)) {
		t.Error("the body is not signed")
	}
	if sign(testKey, "1", []byte(`{}`)) == sign(testKey, "2", []byte(`{}`)) {
		t.Error("the timestamp is not signed")
	}
	// The dot keeps the timestamp from sliding into the body.
	if sign(testKey, "1", []byte(`2.x`)) == sign(testKey, "12", []byte(`.x`)) {
		t.Error("timestamp and body are not told apart")
	}
}

func hookError(t *testing.T, err error) *flow.HookError {
	t.Helper()
	var e *flow.HookError
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want a HookError", err)
	}
	return e
}

// What the answer holds: the members replace those sent, unknown ones are ignored (Q68),
// [] is an empty object (Q69), a wrong type fails the authentication.
func TestLoginAnswers(t *testing.T) {
	str := ory.PtrString
	for name, tc := range map[string]struct {
		answer string
		want   flow.LoginHookAnswer
		cause  string
	}{
		"all the members": {answer: `{"subject":"bob","acr":"3","amr":["otp"],"context":{"a":1},"remember":false,"remember_for":60}`,
			want: flow.LoginHookAnswer{Subject: str("bob"), ACR: str("3"), AMR: []string{"otp"}, Context: json.RawMessage(`{"a":1}`), Remember: ory.PtrBool(false), RememberFor: ory.PtrInt64(60)}},
		"nothing":               {answer: `{}`},
		"an empty list":         {answer: `[]`},
		"null clears":           {answer: `{"acr":null,"remember":null,"remember_for":null}`, want: flow.LoginHookAnswer{NullACR: true, NullRemember: true, NullRememberFor: true}},
		"context null":          {answer: `{"context":null}`, want: flow.LoginHookAnswer{Context: json.RawMessage(`null`)}},
		"context an empty list": {answer: `{"context":[]}`, want: flow.LoginHookAnswer{Context: json.RawMessage(`{}`)}},
		"amr empty":             {answer: `{"amr":[]}`, want: flow.LoginHookAnswer{AMR: []string{}}},
		"unknown members":       {answer: `{"status":"ok","challenge":"x","browser":{"ip":"1"},"subject":"bob"}`, want: flow.LoginHookAnswer{Subject: str("bob")}},

		"context a list":       {answer: `{"context":["a"]}`, cause: "member context is neither an object nor null"},
		"context a string":     {answer: `{"context":"a"}`, cause: "member context is neither an object nor null"},
		"subject null":         {answer: `{"subject":null}`, cause: "member subject is not a string"},
		"subject a number":     {answer: `{"subject":1}`, cause: "member subject is not a string"},
		"subject empty":        {answer: `{"subject":""}`, cause: "member subject is empty"},
		"acr a number":         {answer: `{"acr":1}`, cause: "member acr is not a string or null"},
		"amr null":             {answer: `{"amr":null}`, cause: "member amr is not a list of strings"},
		"amr a string":         {answer: `{"amr":"pwd"}`, cause: "member amr is not a list of strings"},
		"amr of numbers":       {answer: `{"amr":[1]}`, cause: "member amr is not a list of strings"},
		"remember a string":    {answer: `{"remember":"yes"}`, cause: "member remember is not a boolean or null"},
		"remember_for a float": {answer: `{"remember_for":1.5}`, cause: "member remember_for is not an integer or null"},
		"a list":               {answer: `["subject"]`, cause: "the answer is not a JSON object"},
		"a scalar":             {answer: `1`, cause: "the answer is not a JSON object"},
		"null":                 {answer: `null`, cause: "the answer is not a JSON object"},
		"not JSON":             {answer: `{"subject":`, cause: "the answer is not a JSON object"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newReceiver(t, 200, "application/json", tc.answer)
			got := newClient(t).Login(context.Background(), loginCall(r.URL))
			if tc.cause != "" {
				e := hookError(t, got.Err)
				if e.Cause != tc.cause || e.Status != 200 || e.Host != strings.TrimPrefix(r.URL, "http://") {
					t.Errorf("error %+v, want the cause %q", e, tc.cause)
				}
				if strings.Contains(e.Error(), "bob") {
					t.Errorf("a value in the cause: %v", e)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("answer %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestConsentAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		answer string
		want   flow.ConsentHookAnswer
		cause  string
	}{
		"all the members": {answer: `{"grant_scope":["openid","email"],"grant_access_token_audience":["api2"],"access_token":{"a":1},"id_token":{"i":2}}`,
			want: flow.ConsentHookAnswer{GrantScope: []string{"openid", "email"}, GrantAudience: []string{"api2"}, AccessToken: json.RawMessage(`{"a":1}`), IDToken: json.RawMessage(`{"i":2}`)}},
		"nothing":           {answer: `{}`},
		"empty lists":       {answer: `{"access_token":[],"id_token":[]}`, want: flow.ConsentHookAnswer{AccessToken: json.RawMessage(`{}`), IDToken: json.RawMessage(`{}`)}},
		"unknown members":   {answer: `{"subject":"x"}`},
		"claims a list":     {answer: `{"id_token":["a"]}`, cause: "member id_token is not an object"},
		"claims null":       {answer: `{"access_token":null}`, cause: "member access_token is not an object"},
		"grant_scope null":  {answer: `{"grant_scope":null}`, cause: "member grant_scope is not a list of strings"},
		"audience a string": {answer: `{"grant_access_token_audience":"api"}`, cause: "member grant_access_token_audience is not a list of strings"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newReceiver(t, 200, "application/json", tc.answer)
			got := newClient(t).Consent(context.Background(), consentCall(r.URL))
			if tc.cause != "" {
				if e := hookError(t, got.Err); e.Cause != tc.cause {
					t.Errorf("cause %q, want %q", e.Cause, tc.cause)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("answer %+v, want %+v", got, tc.want)
			}
		})
	}
}

// What an HTTP answer must be: 200 and application/json, as Symfony.
func TestHTTPRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		status      int
		contentType string
		answer      string
		cause       string
		code        int
	}{
		"a 500":           {500, "application/json", `{}`, "status 500", 500},
		"a 403 refuses":   {403, "application/json", `{"error":"bob is refused"}`, "status 403", 403},
		"a 204":           {204, "", ``, "status 204", 204},
		"a redirect":      {302, "application/json", ``, "status 302", 302},
		"text":            {200, "text/plain", `{}`, "the answer is not application/json", 200},
		"no content type": {200, "", `{}`, "the answer is not application/json", 200},
		"an empty body":   {200, "application/json", ``, "the answer is empty", 200},
		"over 1 MiB":      {200, "application/json", `{"x":"` + strings.Repeat("x", maxAnswer) + `"}`, "the answer is over 1 MiB", 200},
	} {
		t.Run(name, func(t *testing.T) {
			r := newReceiver(t, tc.status, tc.contentType, tc.answer)
			e := hookError(t, newClient(t).Login(context.Background(), loginCall(r.URL)).Err)
			if e.Cause != tc.cause || e.Status != tc.code {
				t.Errorf("error %+v, want %d %q", e, tc.code, tc.cause)
			}
			if strings.Contains(e.Error(), "bob") {
				t.Errorf("the answer in the cause: %v", e)
			}
		})
	}
	t.Run("a content type in capitals, with a charset", func(t *testing.T) {
		r := newReceiver(t, 200, "Application/JSON; charset=utf-8", `{"subject":"bob"}`)
		if a := newClient(t).Login(context.Background(), loginCall(r.URL)); a.Err != nil || *a.Subject != "bob" {
			t.Errorf("answer %+v", a)
		}
	})
	t.Run("a redirect is not followed", func(t *testing.T) {
		other := newReceiver(t, 200, "application/json", `{"subject":"mallory"}`)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
		}))
		defer srv.Close()
		e := hookError(t, newClient(t).Login(context.Background(), loginCall(srv.URL)).Err)
		if e.Status != 307 || other.hits.Load() != 0 {
			t.Errorf("error %+v, %d calls elsewhere", e, other.hits.Load())
		}
	})
}

// The log line of a call that failed names the host, nothing of the URL's path, query
// or user (Journalisation).
func TestURLStaysOutOfTheCause(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := strings.Replace(srv.URL, "http://", "http://user:secret@", 1) + "/hook?token=secret"
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // refused: the transport names what it dialled
	e := hookError(t, newClient(t).Login(context.Background(), loginCall(u)).Err)
	if strings.Contains(e.Error(), "secret") || strings.Contains(e.Cause, "token") || e.Host != host || e.Status != 0 {
		t.Errorf("error %+v", e)
	}
}

// A call past 5 s fails; a client gone cancels it, which Err tells (Q72).
func TestDelays(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	t.Run("timeout", func(t *testing.T) {
		c := newClient(t)
		c.http.Timeout = 50 * time.Millisecond
		e := hookError(t, c.Login(context.Background(), loginCall(srv.URL)).Err)
		if errors.Is(e, context.Canceled) || e.Elapsed < 50*time.Millisecond || !strings.Contains(e.Cause, "deadline exceeded") {
			t.Errorf("error %+v", e)
		}
	})
	t.Run("client gone", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(20*time.Millisecond, cancel)
		e := hookError(t, newClient(t).Login(ctx, loginCall(srv.URL)).Err)
		if !errors.Is(e, context.Canceled) {
			t.Errorf("error %+v", e)
		}
	})
	if httpTimeout != 5*time.Second {
		t.Errorf("httpTimeout = %v, the doc says 5 s", httpTimeout)
	}
}

// A connection the server closes between two calls, a keep-alive shorter than ours, does
// not fail the second login: the call is replayed (Q72).
func TestStaleConnectionReplayed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if hits.Add(1) == 2 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c := newClient(t)
	for i := range 2 {
		if a := c.Login(context.Background(), loginCall(srv.URL)); a.Err != nil {
			t.Fatalf("call %d: %v", i, a.Err)
		}
	}
	if hits.Load() != 3 {
		t.Errorf("%d attempts, want 3", hits.Load())
	}
}

func TestDedicatedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"subject":"bob"}`)
	}))
	defer srv.Close()
	t.Run("the system's authorities do not know it", func(t *testing.T) {
		if e := hookError(t, newClient(t).Login(context.Background(), loginCall(srv.URL)).Err); !strings.Contains(e.Cause, "certificate") {
			t.Errorf("error %+v", e)
		}
	})
	t.Run("webhooks.ca_file does", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		writePEM(t, caFile, srv)
		c, err := New(config.Webhooks{CAFile: caFile, ProcessTimeout: config.Duration(time.Second), MaxProcesses: 1}, "1.2", testKey)
		if err != nil {
			t.Fatal(err)
		}
		if a := c.Login(context.Background(), loginCall(srv.URL)); a.Err != nil {
			t.Error(a.Err)
		}
	})
	t.Run("an empty file is refused", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(caFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(config.Webhooks{CAFile: caFile, MaxProcesses: 1}, "1.2", testKey); err == nil || !strings.Contains(err.Error(), "webhooks.ca_file") {
			t.Errorf("err = %v", err)
		}
	})
}

// script writes an executable shell script.
func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// A program: the payload on stdin, the answer on stdout, exit code 0.
func TestProcess(t *testing.T) {
	ctx := browserContext(t, "203.0.113.9:1234", "Firefox")
	t.Run("the payload on stdin, the answer on stdout", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "stdin")
		a := newClient(t).Login(ctx, loginCall(script(t, `cat > `+out+`; echo '{"subject":"bob"}'`)))
		if a.Err != nil || *a.Subject != "bob" {
			t.Fatalf("answer %+v", a)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(got), `{"challenge":"login-challenge","subject":"alice",`) || !strings.HasSuffix(string(got), "}\n") {
			t.Errorf("stdin %s", got)
		}
	})
	t.Run("a command with arguments", func(t *testing.T) {
		path := script(t, `cat > /dev/null; printf '{"subject":"%s"}' "$1"`)
		if a := newClient(t).Login(ctx, loginCall(path+` "b c"`)); a.Err != nil || *a.Subject != "b c" {
			t.Errorf("answer %+v", a)
		}
	})
	t.Run("a file:// URL", func(t *testing.T) {
		if a := newClient(t).Login(ctx, loginCall("file://"+script(t, `echo '{"subject":"bob"}'`))); a.Err != nil || *a.Subject != "bob" {
			t.Errorf("answer %+v", a)
		}
	})
	t.Run("nothing on stdout changes nothing, as Symfony", func(t *testing.T) {
		a := newClient(t).Login(ctx, loginCall(script(t, `cat > /dev/null; echo`)))
		if !reflect.DeepEqual(a, flow.LoginHookAnswer{}) {
			t.Errorf("answer %+v", a)
		}
	})
	t.Run("the environment is reduced", func(t *testing.T) {
		t.Setenv("DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY", "secret")
		t.Setenv("PATH", os.Getenv("PATH"))
		a := newClient(t).Login(ctx, loginCall(script(t, `printf '{"subject":"[%s]","acr":"%s"}' "$DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY" "${PATH:+set}"`)))
		if a.Err != nil || *a.Subject != "[]" || *a.ACR != "set" {
			t.Errorf("answer %+v", a)
		}
	})
	t.Run("an exit code", func(t *testing.T) {
		path := script(t, `echo 'alice failed' >&2; echo '{"subject":"bob"}'; exit 3`)
		e := hookError(t, newClient(t).Login(ctx, loginCall(path+" --token=secret")).Err)
		if e.Status != 3 || e.Cause != "exit code 3" || e.Host != "hook.sh" {
			t.Errorf("error %+v", e)
		}
		if strings.Contains(e.Error(), "alice") || strings.Contains(e.Error(), "secret") {
			t.Errorf("stderr or an argument in the cause: %v", e)
		}
	})
	t.Run("a program that does not exist", func(t *testing.T) {
		e := hookError(t, newClient(t).Login(ctx, loginCall("/nonexistent/hook --token=secret")).Err)
		if e.Cause != "the program does not exist" || e.Host != "hook" {
			t.Errorf("error %+v", e)
		}
		e = hookError(t, newClient(t).Login(ctx, loginCall("no-such-program-anywhere")).Err)
		if e.Cause != "the program does not exist" {
			t.Errorf("error %+v", e)
		}
	})
	t.Run("what stdout holds is checked as an answer", func(t *testing.T) {
		for answer, cause := range map[string]string{
			`not json`:            "the answer is not a JSON object",
			`["a"]`:               "the answer is not a JSON object",
			`null`:                "the answer is not a JSON object",
			`{"context":["a"]}`:   "member context is neither an object nor null",
			`{"subject":{"a":1}}`: "member subject is not a string",
		} {
			e := hookError(t, newClient(t).Login(ctx, loginCall(script(t, `echo '`+answer+`'`))).Err)
			if e.Cause != cause {
				t.Errorf("%s: cause %q, want %q", answer, e.Cause, cause)
			}
		}
	})
	t.Run("over 1 MiB", func(t *testing.T) {
		e := hookError(t, newClient(t).Login(ctx, loginCall(script(t, `yes aaaaaaaaaaaaaaaa`))).Err)
		if e.Cause != "the answer is over 1 MiB" {
			t.Errorf("error %+v", e)
		}
	})
	t.Run("the consent webhook", func(t *testing.T) {
		a := newClient(t).Consent(ctx, consentCall(script(t, `echo '{"id_token":{"hook":true}}'`)))
		if a.Err != nil || string(a.IDToken) != `{"hook":true}` {
			t.Errorf("answer %+v", a)
		}
	})
}

// A program past webhooks.process_timeout is killed with what it started: a child that
// keeps stdout does not hold the request. A client gone kills it too (Q72).
func TestProcessDelays(t *testing.T) {
	short := func(t *testing.T) *Client {
		c := newClient(t)
		c.timeout = 100 * time.Millisecond
		return c
	}
	t.Run("timeout, a child holding stdout", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "pid")
		path := script(t, `sleep 30 &
echo $! > `+pidFile+`
wait`)
		start := time.Now()
		e := hookError(t, short(t).Login(context.Background(), loginCall(path)).Err)
		if e.Cause != "timeout" || errors.Is(e, context.Canceled) {
			t.Errorf("error %+v", e)
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("took %v", took)
		}
		data, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		if !childEnds(pid) {
			t.Errorf("the child %d outlived the program", pid)
		}
	})
	t.Run("exit 0, a child left on stdout: the answer stands", func(t *testing.T) {
		path := script(t, `echo '{"subject":"bob"}'
sleep 30 &`)
		c := newClient(t)
		start := time.Now()
		a := c.Login(context.Background(), loginCall(path))
		if a.Err != nil || *a.Subject != "bob" {
			t.Errorf("answer %+v", a)
		}
		// The child dies with its group at the end of the program: no WaitDelay (Q86).
		if took := time.Since(start); took > waitDelay/2 {
			t.Errorf("took %v", took)
		}
	})
	// Q86: what a program leaves behind dies with it, rather than live on, then end a
	// zombie under a PID 1 that does not reap (revue R28). Detached from stdout, the
	// child held nothing: it used to outlive the program.
	t.Run("exit 0, a child detached", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "pid")
		path := script(t, `sleep 30 >/dev/null 2>&1 &
echo $! > `+pidFile+`
echo '{"subject":"bob"}'`)
		a := newClient(t).Login(context.Background(), loginCall(path))
		if a.Err != nil || *a.Subject != "bob" {
			t.Fatalf("answer %+v", a)
		}
		data, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for childAlive(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("the child %d outlived the program", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	t.Run("client gone", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(20*time.Millisecond, cancel)
		c := newClient(t)
		start := time.Now()
		e := hookError(t, c.Login(ctx, loginCall(script(t, `sleep 30`))).Err)
		if !errors.Is(e, context.Canceled) {
			t.Errorf("error %+v", e)
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("took %v", took)
		}
	})
}

// childAlive tells whether a process runs, a zombie being dead: its parent, gone,
// leaves it to be reaped.
// childEnds tells whether the process pid ends within two seconds: a SIGKILL
// is delivered after kill returns, and /proc read at once may still show the
// child running.
func childEnds(pid int) bool {
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if !childAlive(pid) {
			return true
		}
	}
	return false
}

func childAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// pid (comm) state ...
	text := string(data)
	at := strings.LastIndexByte(text, ')')
	return at < 0 || at+2 >= len(text) || text[at+2] != 'Z'
}

// webhooks.max_processes: a program over the cap waits for a slot, at most
// webhooks.process_timeout.
func TestMaxProcesses(t *testing.T) {
	c, err := New(config.Webhooks{ProcessTimeout: config.Duration(200 * time.Millisecond), MaxProcesses: 1}, "1.2", testKey)
	if err != nil {
		t.Fatal(err)
	}
	c.slots <- struct{}{} // the one slot, taken
	t.Run("no slot within the delay", func(t *testing.T) {
		start := time.Now()
		e := hookError(t, c.Login(context.Background(), loginCall(script(t, `echo '{}'`))).Err)
		if e.Cause != "too many processes" || time.Since(start) < 200*time.Millisecond {
			t.Errorf("error %+v", e)
		}
	})
	t.Run("a client gone while waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if e := hookError(t, c.Login(ctx, loginCall(script(t, `echo '{}'`))).Err); !errors.Is(e, context.Canceled) {
			t.Errorf("error %+v", e)
		}
	})
	t.Run("a slot freed in time", func(t *testing.T) {
		time.AfterFunc(20*time.Millisecond, func() { <-c.slots })
		if a := c.Login(context.Background(), loginCall(script(t, `echo '{"subject":"bob"}'`))); a.Err != nil || *a.Subject != "bob" {
			t.Errorf("answer %+v", a)
		}
		if len(c.slots) != 0 {
			t.Errorf("%d slots still taken", len(c.slots))
		}
	})
}

// The command line is cut as Symfony's str_getcsv does: these results come from PHP
// (str_getcsv($c, ' ', '"', '\\'), empty fields filtered), 8.x.
func TestSplitCommand(t *testing.T) {
	for line, want := range map[string][]string{
		`/bin/hook --env=prod`:   {`/bin/hook`, `--env=prod`},
		`/bin/hook "a b" c`:      {`/bin/hook`, `a b`, `c`},
		`/bin/hook --name="a b"`: {`/bin/hook`, `--name="a`, `b"`},
		`/bin/hook  two  spaces`: {`/bin/hook`, `two`, `spaces`},
		`"/opt/my hook" -x`:      {`/opt/my hook`, `-x`},
		`/bin/hook "a""b"`:       {`/bin/hook`, `a"b`},
		`/bin/hook "a\"b c"`:     {`/bin/hook`, `a\"b c`},
		`/bin/hook a\ b`:         {`/bin/hook`, `a\`, `b`},
		`"a b"c d`:               {`a bc`, `d`},
		`"unterminated x y`:      {`unterminated x y`},
		`a"b c`:                  {`a"b`, `c`},
		`x "" y`:                 {`x`, `y`},
		` lead`:                  {`lead`},
		"a\tb c":                 {"a\tb", `c`},
		`"a\\" b`:                {`a\\`, `b`},
		`x "a\"" y`:              {`x`, `a\"`, `y`},
	} {
		if got := splitCommand(line); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}
}

// A webhook that could not be called refuses the snapshot (Q70).
func TestCheck(t *testing.T) {
	const allow, refuse, signed, unsigned = true, false, true, false
	for name, tc := range map[string]struct {
		location          string
		allowHTTP, signed bool
		want              string
	}{
		"none":                     {"", refuse, unsigned, ""},
		"https, signed":            {"https://hooks/login", refuse, signed, ""},
		"https, no key":            {"https://hooks/login", refuse, unsigned, "needs secrets.webhook_signing_key"},
		"http refused":             {"http://hooks/login", refuse, signed, "needs tls.allow_http"},
		"http in capitals refused": {"HTTP://hooks/login", refuse, signed, "needs tls.allow_http"},
		"http allowed":             {"http://hooks/login", allow, signed, ""},
		"http allowed, no key":     {"http://hooks/login", allow, unsigned, "needs secrets.webhook_signing_key"},
		"a program needs no key":   {"/bin/hook --x", refuse, unsigned, ""},
		"a file needs no key":      {"file:///bin/hook", refuse, unsigned, ""},
	} {
		t.Run(name, func(t *testing.T) {
			for _, s := range []store.Settings{{LoginAcceptWebhookURL: tc.location}, {ConsentAcceptWebhookURL: tc.location}} {
				err := Check(s, tc.allowHTTP, tc.signed)
				if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
					t.Errorf("%+v: err = %v, want %q", s, err, tc.want)
				}
			}
		})
	}
}

// writePEM writes the certificate of srv to path.
func writePEM(t *testing.T, path string, srv *httptest.Server) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
