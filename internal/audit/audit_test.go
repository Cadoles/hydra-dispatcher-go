package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

const sentinel = "alice@sentinel.example"

// requestContext is the context of a request from 203.0.113.9, with its trace id.
func requestContext(t *testing.T) context.Context {
	t.Helper()
	var ctx context.Context
	h := httpx.Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() }), httpx.RealIP(nil), httpx.Trace(nil))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	h.ServeHTTP(httptest.NewRecorder(), r)
	return ctx
}

// lines plays o and returns what the log wrote, one map a line.
func lines(t *testing.T, clear bool, o flow.Observation) (string, []map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	l := New(slog.New(httpx.LogHandler(slog.NewJSONHandler(&buf, nil))).With("log_type", "audit"), []byte("0123456789abcdef0123456789abcdef"), clear)
	l.Observe(requestContext(t), o)
	var out []map[string]any
	for line := range strings.Lines(buf.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return buf.String(), out
}

func flowOfTwoSteps() *flow.Flow {
	return &flow.Flow{FlowID: "f", Subject: sentinel, Current: 2,
		Hydra: flow.LoginSnapshot{Client: json.RawMessage(`{"client_id":"c1"}`)},
		Steps: []flow.Step{{App: "sql"}, {App: "2fa", Check: "equal"}}}
}

// The events of the doc, their fields, the full IP, the pseudonym; what is not an event
// of security writes nothing.
func TestEvents(t *testing.T) {
	f := flowOfTwoSteps()
	rp := true
	logoutRead := &flow.LogoutRead{Request: &ory.OAuth2LogoutRequest{Subject: ory.PtrString(sentinel), Client: &ory.OAuth2Client{ClientId: ory.PtrString("c2")}}}
	for name, tc := range map[string]struct {
		o    flow.Observation
		msg  string
		want map[string]any
	}{
		"a login accepted": {flow.Observation{Before: f, After: f, Reports: []flow.Report{{Event: "hydra.login_accepted"}}}, "auth.succeeded",
			map[string]any{"flow": "f", "steps": float64(2), "result": "accepted", "client_id": "c1", "skip": false}},
		"a skip accepted, the subject sent": {flow.Observation{
			Answers: flow.Answers{Accept: &flow.Done{Call: flow.Call{AcceptLogin: ory.AcceptOAuth2LoginRequest{Subject: sentinel}}, RedirectTo: "http://x"}},
			Reports: []flow.Report{{Event: "hydra.login_accepted", Flow: "f"}}}, "auth.succeeded",
			map[string]any{"flow": "f", "skip": true}},
		"a reject of A3": {flow.Observation{Before: f, After: f, Reports: []flow.Report{{Event: "flow.rejected", Detail: "not_ours:login", Audit: true}}}, "auth.failed",
			map[string]any{"result": "rejected", "reason": "not_ours:login", "level": "WARN", "client_id": "c1"}},
		"a reject of the user": {flow.Observation{Before: f, Reports: []flow.Report{{Event: "flow.rejected", Detail: "user"}}}, "auth.failed",
			map[string]any{"reason": "user", "level": "INFO"}},
		"a consent without a flow rejected, Hydra's subject": {flow.Observation{
			Answers: flow.Answers{Consent: &flow.ConsentRead{Request: &ory.OAuth2ConsentRequest{Subject: ory.PtrString(sentinel), Client: &ory.OAuth2Client{ClientId: ory.PtrString("c3")}}}},
			Reports: []flow.Report{{Event: "flow.rejected", Detail: "no_ref"}}}, "auth.failed",
			map[string]any{"reason": "no_ref", "client_id": "c3"}},
		"a skip ignored": {flow.Observation{Before: f, Reports: []flow.Report{{Event: "skip.ignored", Kind: "login", Reason: "scopes"}}}, "skip.ignored",
			map[string]any{"kind": "login", "reason": "scopes", "client_id": "c1"}},
		"a skip accepted": {flow.Observation{Before: f, Reports: []flow.Report{{Event: "skip.accepted", Kind: "consent", Flow: "f2"}}}, "skip.accepted",
			map[string]any{"kind": "consent", "flow": "f2"}},
		"EMU-12, a rule of a step": {flow.Observation{Before: f, Reports: []flow.Report{{Event: "step.subject_mismatch", Audit: true}}}, "step.subject_mismatch",
			map[string]any{"flow": "f", "app": "2fa", "rule": "equal", "level": "WARN"}},
		"EMU-14, a second accept": {flow.Observation{Before: func() *flow.Flow { g := flowOfTwoSteps(); g.Current = 1; return g }(), Reports: []flow.Report{{Event: "step.subject_mismatch", Audit: true}}}, "step.subject_mismatch",
			map[string]any{"app": "sql", "rule": "same_accept"}},
		"a step skipped (phase 4)": {flow.Observation{Before: f, After: f, Reports: []flow.Report{{Event: flow.EventStepSkipped, App: "2fa", Result: flow.SkipSkipped}}}, "step.skipped",
			map[string]any{"flow": "f", "app": "2fa", "client_id": "c1", "level": "INFO"}},
		"a logout": {flow.Observation{Answers: flow.Answers{Logout: logoutRead}, Reports: []flow.Report{{Event: "logout.started", Audit: true, RP: &rp, Apps: 3}}}, "logout.started",
			map[string]any{"client_id": "c2", "rp_initiated": true, "apps": float64(3), "again": false}},
		"a session deleted": {flow.Observation{Answers: flow.Answers{Login: &flow.LoginRead{Request: &ory.OAuth2LoginRequest{Subject: sentinel}}}, Reports: []flow.Report{{Event: "logout.session_revoked", Audit: true}}}, "logout.session_revoked", nil},
		"EMU-4": {flow.Observation{Reports: []flow.Report{{Event: "security.ip_rejected", Detail: "emulated: app outside its sources"}}}, "security.ip_rejected",
			map[string]any{"surface": "emulated", "level": "WARN"}},
	} {
		t.Run(name, func(t *testing.T) {
			text, got := lines(t, false, tc.o)
			if len(got) != 1 || got[0]["msg"] != tc.msg {
				t.Fatalf("lines %s", text)
			}
			if got[0]["ip"] != "203.0.113.9" || got[0]["trace_id"] == nil || got[0]["log_type"] != "audit" {
				t.Errorf("line %s", text)
			}
			for k, v := range tc.want {
				if got[0][k] != v {
					t.Errorf("%s = %v, want %v: %s", k, got[0][k], v, text)
				}
			}
			if strings.Contains(text, sentinel) {
				t.Errorf("the subject in clear: %s", text)
			}
		})
	}
}

func TestNotOfSecurity(t *testing.T) {
	text, _ := lines(t, false, flow.Observation{Before: flowOfTwoSteps(), Reports: []flow.Report{
		{Event: "flow.started", Detail: "choice"}, {Event: "flow.error", Detail: "E1004"}, {Event: "challenge.invalid", Detail: "forged"},
		{Event: "hydra.consent_accepted"}, {Event: "step.login_accepted", Detail: "sql"},
	}})
	if text != "" {
		t.Errorf("wrote %s", text)
	}
}

// The pseudonym: stable, the key's, 128 bits; pseudonymize_subject: false writes the
// subject.
func TestPseudonym(t *testing.T) {
	a, b := New(nil, []byte("key-a"), false), New(nil, []byte("key-b"), false)
	p := a.subject(sentinel)
	if len(p) != pseudonymSize || p != a.subject(sentinel) || p == b.subject(sentinel) || p == a.subject("bob") {
		t.Errorf("pseudonym %q", p)
	}
	if a.subject("") != "" {
		t.Errorf("no subject: %q", a.subject(""))
	}
	if got := New(nil, nil, true).subject(sentinel); got != sentinel {
		t.Errorf("clear: %q", got)
	}
	text, got := lines(t, true, flow.Observation{Before: flowOfTwoSteps(), Reports: []flow.Report{{Event: "hydra.login_accepted"}}})
	if len(got) != 1 || got[0]["subject"] != sentinel {
		t.Errorf("clear: %s", text)
	}
}

func TestBlocked(t *testing.T) {
	var buf bytes.Buffer
	l := New(slog.New(httpx.LogHandler(slog.NewJSONHandler(&buf, nil))), []byte("k"), false)
	l.Blocked(requestContext(t))
	if !strings.Contains(buf.String(), `"msg":"security.rate_limited"`) || !strings.Contains(buf.String(), `"ip":"203.0.113.9"`) {
		t.Errorf("line %s", buf.String())
	}
}

// A login to the admin UI: granted at info, refused at warn with its reason;
// a logout; the address of the request.
func TestAdminLogin(t *testing.T) {
	var buf bytes.Buffer
	l := New(slog.New(httpx.LogHandler(slog.NewJSONHandler(&buf, nil))).With("log_type", "audit"), []byte("0123456789abcdef0123456789abcdef"), false)
	ctx := requestContext(t)
	l.AdminLogin(ctx, "alice", "password", "granted", "")
	l.AdminLogin(ctx, "(unknown)", "password", "refused", "invalid_credentials")
	l.AdminLogout(ctx, "alice", "local")
	var got []map[string]any
	for line := range bytes.Lines(buf.Bytes()) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	if len(got) != 3 || got[0]["msg"] != "admin.login" || got[0]["level"] != "INFO" || got[0]["user"] != "alice" || got[0]["reason"] != nil ||
		got[1]["level"] != "WARN" || got[1]["reason"] != "invalid_credentials" || got[1]["user"] != "(unknown)" ||
		got[2]["msg"] != "admin.logout" || got[2]["result"] != "local" || got[0]["ip"] == nil || got[0]["ip"] == "" {
		t.Errorf("lines: %v", got)
	}
}
