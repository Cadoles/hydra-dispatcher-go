package front

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/audit"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
)

// Sentinels in a whole authentication, then the pages after its end and a challenge
// unknown to Hydra: none reaches the application log, the access log or the audit log,
// whose subject is pseudonymised (Journalisation, Données personnelles). The skip, the
// logout, a webhook and Hydra failing, a panic, Sentry, the spans, /metrics and the
// headers sent are played on the whole handler: TestSentinelsOnTheWholeHandler, in
// cmd/hydra-dispatcher (revue R29, P12d).
func TestSentinelsInTheThreeStreams(t *testing.T) {
	const (
		subject = "sentinel.subject@example.org"
		claim   = "sentinel-claim-value"
	)
	var app, access, audited bytes.Buffer
	w := newWorld(t)
	w.logs.Reset()
	w.o.Log = slog.New(httpx.LogHandler(slog.NewJSONHandler(&app, &slog.HandlerOptions{Level: slog.LevelDebug}))).With("log_type", "app")
	key := []byte("0123456789abcdef0123456789abcdef")
	w.o.Observers = []flow.Observer{audit.New(slog.New(httpx.LogHandler(slog.NewJSONHandler(&audited, nil))).With("log_type", "audit"), key, false)}
	accessLogger := slog.New(httpx.LogHandler(slog.NewJSONHandler(&access, nil))).With("log_type", "access")
	w.h = httpx.AccessLog(accessLogger, 1, "full")(w.h)

	w.hydra.consentSkip = true
	w.app(w.choose("hydra-sql"), subject, `{"email":"`+claim+`"}`)
	location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther)

	// The pages after the end, and a challenge unknown to Hydra.
	w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil)
	w.do(http.MethodGet, "/?login_challenge=forged-forged-forged", nil)

	cookies := make([]string, 0, len(w.cookies))
	for _, value := range w.cookies {
		cookies = append(cookies, value)
	}
	sentinels := append([]string{subject, claim, hydraL, hydraC}, cookies...)
	for name, stream := range map[string]string{"app": app.String() + w.logs.String(), "access": access.String(), "audit": audited.String()} {
		if stream == "" {
			t.Errorf("%s: nothing written", name)
		}
		for _, s := range sentinels {
			if s != "" && strings.Contains(stream, s) {
				t.Errorf("%s holds %q:\n%s", name, s, stream)
			}
		}
	}
	// The lines of debug (Q132): the name of the claim, never its value.
	for _, want := range []string{`"msg":"flow.transition"`, `"msg":"claims.merged"`, `"id_token":["email"]`, `"msg":"claims.filtered"`} {
		if !strings.Contains(app.String(), want) {
			t.Errorf("no %s in the application log:\n%s", want, app.String())
		}
	}
	for _, want := range []string{`"msg":"auth.succeeded"`, `"log_type":"audit"`, `"subject":"`} {
		if !strings.Contains(audited.String(), want) {
			t.Errorf("no %s in the audit log:\n%s", want, audited.String())
		}
	}
}
