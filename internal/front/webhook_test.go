package front

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/config"
	"github.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"github.com/Cadoles/hydra-dispatcher-go/internal/webhook"
)

// hookReceiver is a webhook receiver as the doc asks for one: it refuses a signature
// that does not verify, a timestamp over 5 minutes old, and answers what its test says.
type hookReceiver struct {
	*httptest.Server
	mu       sync.Mutex
	payloads map[string]map[string]any
	answers  map[string]string
	bad      []string
}

func newHookReceiver(t *testing.T, key []byte, answers map[string]string) *hookReceiver {
	t.Helper()
	r := &hookReceiver{payloads: map[string]map[string]any{}, answers: answers}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var ts int64
		_, _ = fmt.Sscan(req.Header.Get(webhook.HeaderTimestamp), &ts)
		mac := hmac.New(sha256.New, key)
		fmt.Fprintf(mac, "%s.%s", req.Header.Get(webhook.HeaderTimestamp), body)
		r.mu.Lock()
		defer r.mu.Unlock()
		if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(req.Header.Get(webhook.HeaderSignature))) || time.Since(time.Unix(ts, 0)).Abs() > 5*time.Minute {
			r.bad = append(r.bad, req.URL.Path)
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Error(err)
		}
		r.payloads[req.URL.Path] = payload
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, r.answers[req.URL.Path])
	}))
	t.Cleanup(r.Close)
	return r
}

// worldWithHooks is the world of the pages, with the real client of the webhooks towards
// the receiver: settings, signature, payloads and answers, from the browser's request to
// Hydra's accept.
func worldWithHooks(t *testing.T, answers map[string]string) (*world, *hookReceiver) {
	t.Helper()
	key := []byte("webhook-key-webhook-key-webhook-k")
	r := newHookReceiver(t, key, answers)
	snap := testSnapshot()
	snap.Settings.LoginAcceptWebhookURL = r.URL + "/login"
	snap.Settings.ConsentAcceptWebhookURL = r.URL + "/consent"
	w := newWorld(t, worldOptions{base: base, snapshot: snap})
	client, err := webhook.New(config.Webhooks{ProcessTimeout: config.Duration(time.Second), MaxProcesses: 1}, "1.2", key)
	if err != nil {
		t.Fatal(err)
	}
	w.o.Webhooks = client
	w.o.Log = slog.New(slog.NewJSONHandler(&w.logs, nil))
	return w, r
}

// One step through the pages, up to the final accept, with the browser's User-Agent.
func (w *world) toFinalAccept(t *testing.T) *http.Response {
	t.Helper()
	w.app(w.choose("hydra-sql"), "alice", `{"email":"alice@example.org"}`)
	return w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil, "User-Agent", "Firefox")
}

// The webhooks through the pages: their members replace what goes to Hydra.
func TestWebhooksThroughThePages(t *testing.T) {
	w, r := worldWithHooks(t, map[string]string{
		"/login":   `{"subject":"alice2","acr":"3","amr":["hook"],"context":{"mapped":true,"x_dispatcher_ref":"forged"},"status":"ok"}`,
		"/consent": `{"id_token":{"hook":"yes"},"access_token":[],"grant_scope":["openid","hook"]}`,
	})
	if u := location(t, w.toFinalAccept(t), http.StatusSeeOther); u.String() != verifierURL {
		t.Fatalf("final accept: %s", u)
	}
	login := r.payloads["/login"]
	if login["challenge"] != hydraL || login["subject"] != "alice" {
		t.Errorf("payload %v", login)
	}
	if browser, _ := login["browser"].(map[string]any); browser["user-agent"] != "Firefox" || browser["ip"] == nil {
		t.Errorf("browser %v", login["browser"])
	}
	if client, _ := login["client"].(map[string]any); client["client_id"] == nil {
		t.Errorf("client %v", login["client"])
	}
	accept := w.hydra.accepted
	if accept.Subject != "alice2" || accept.GetAcr() != "3" || strings.Join(accept.Amr, ",") != "hook" {
		t.Errorf("accept %+v", accept)
	}
	ctx, _ := json.Marshal(accept.Context)
	if want := `{"mapped":true,"x_dispatcher_ref":"` + flow.Ref(hydraL) + `"}`; string(ctx) != want {
		t.Errorf("context %s, want %s: the webhook's members of the dispatcher dropped (Q38)", ctx, want)
	}

	if u := location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil, "User-Agent", "Firefox"), http.StatusSeeOther); u.String() != callbackURL {
		t.Fatalf("consent: %s", u)
	}
	consent := r.payloads["/consent"]
	if consent["challenge"] != hydraC || consent["subject"] != "alice2" {
		t.Errorf("payload %v", consent)
	}
	if ctx, _ := consent["context"].(map[string]any); ctx["mapped"] != true || ctx["x_dispatcher_ref"] != nil {
		t.Errorf("context %v (Q38)", consent["context"])
	}
	body := w.hydra.consent
	if strings.Join(body.GrantScope, ",") != "openid,hook" {
		t.Errorf("grant_scope %v", body.GrantScope)
	}
	idt, _ := json.Marshal(body.Session.IdToken)
	act, _ := json.Marshal(body.Session.AccessToken)
	if string(idt) != `{"hook":"yes"}` || string(act) != `{}` {
		t.Errorf("id_token %s, access_token %s", idt, act)
	}
	if len(r.bad) != 0 {
		t.Errorf("signatures refused: %v", r.bad)
	}
}

// A webhook that fails: page E1006 in 502, nothing written nor rejected, and a reload
// calls it again, which then answers (Q23, FIN-4).
func TestWebhookFailsThenReload(t *testing.T) {
	answers := map[string]string{"/login": `{"context":["a"]}`}
	w, r := worldWithHooks(t, answers)
	resp := w.toFinalAccept(t)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(text(t, resp), "E1006") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, call := range w.hydra.calls {
		if call == "accept_login" || call == "reject_login" {
			t.Errorf("%s made after a webhook that failed", call)
		}
	}
	for _, want := range []string{`"msg":"webhook.failed"`, `"kind":"login"`, `"host":"` + strings.TrimPrefix(r.URL, "http://") + `"`, `"status":200`, `member context is neither an object nor null`, `"msg":"flow.error"`} {
		if !strings.Contains(w.logs.String(), want) {
			t.Errorf("no %s in the log:\n%s", want, w.logs.String())
		}
	}
	r.mu.Lock()
	answers["/login"] = `{}`
	r.mu.Unlock()
	if u := location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther); u.String() != verifierURL {
		t.Errorf("reload: %s", u)
	}
}

// A signature the receiver refuses is a webhook that fails: no login goes on.
func TestWebhookRefusesTheSignature(t *testing.T) {
	w, r := worldWithHooks(t, map[string]string{"/login": `{}`})
	other, err := webhook.New(config.Webhooks{ProcessTimeout: config.Duration(time.Second), MaxProcesses: 1}, "1.2", []byte("another-key-another-key-another-k"))
	if err != nil {
		t.Fatal(err)
	}
	w.o.Webhooks = other
	resp := w.toFinalAccept(t)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d", resp.StatusCode)
	}
	if len(r.bad) != 1 || !strings.Contains(w.logs.String(), `"status":401`) {
		t.Errorf("refused %v, log %s", r.bad, w.logs.String())
	}
}

// The skip calls both webhooks again, on what the cookie keeps: the login webhook with
// the cookie's context, the consent webhook with the same, never the consent request's,
// which holds the marker (SKP-1, SKC-1, Q38).
func TestWebhooksOnASkip(t *testing.T) {
	w, r := worldWithHooks(t, map[string]string{"/login": `{"context":{"mapped":true}}`, "/consent": `{"id_token":{"hook":"yes"}}`})
	if u := location(t, w.toFinalAccept(t), http.StatusSeeOther); u.String() != verifierURL {
		t.Fatalf("final accept: %s", u)
	}
	if u := location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther); u.String() != callbackURL {
		t.Fatalf("consent: %s", u)
	}
	if _, ok := w.cookies[rememberCookie]; !ok {
		t.Fatalf("no remember cookie: %v", w.cookies)
	}

	w.hydra.skip, w.hydra.consentSkip, w.hydra.calls = true, true, nil
	r.mu.Lock()
	r.payloads = map[string]map[string]any{}
	r.answers["/login"] = `{"context":{"at_skip":true}}`
	r.mu.Unlock()
	if u := location(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil), http.StatusSeeOther); u.String() != verifierURL {
		t.Fatalf("skip: %s", u)
	}
	if got := r.payloads["/login"]; got == nil || fmt.Sprint(got["context"]) != "map[mapped:true]" {
		t.Errorf("login webhook, the cookie's context: %v", got)
	}
	// Hydra serves the marker in the consent request's context, beside what the webhook
	// returned at the skip: neither goes to the consent webhook.
	if u := location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther); u.String() != callbackURL {
		t.Fatalf("consent: %s", u)
	}
	if got := r.payloads["/consent"]; got == nil || fmt.Sprint(got["context"]) != "map[mapped:true]" {
		t.Errorf("consent webhook, the cookie's context: %v", got)
	}
	if idt, _ := json.Marshal(w.hydra.consent.Session.IdToken); string(idt) != `{"hook":"yes"}` {
		t.Errorf("id_token %s", idt)
	}
	if len(r.bad) != 0 {
		t.Errorf("signatures refused: %v", r.bad)
	}
}
