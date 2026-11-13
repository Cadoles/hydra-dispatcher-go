package hydra

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/loglevel"
)

// hydra.request at the level debug for each call (Q132), succeeded or not: its
// operation, its status, its duration, the flow and the app of its request;
// never its challenge nor its body.
func TestRequestLines(t *testing.T) {
	fake := &fakeHydra{t: t, responses: map[string]func(http.ResponseWriter, *http.Request){
		"PUT /admin/oauth2/auth/requests/login/accept": reply(200, `{"redirect_to":"http://public.hydra.test/oauth2/auth?login_verifier=secret-verifier"}`),
		"GET /admin/oauth2/auth/requests/consent":      reply(404, `{"error":"Not Found","error_description":"Unable to locate the resource"}`),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv.URL, 4, time.Second)
	var logs bytes.Buffer
	c.Log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := loglevel.WithScope(context.Background(), "main", "sql")
	if _, err := c.AcceptLogin(ctx, "challenge-sentinel", ory.AcceptOAuth2LoginRequest{Subject: "subject-sentinel"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConsentRequest(context.Background(), "challenge-sentinel"); err == nil {
		t.Fatal("a 404 answered")
	}
	got := logs.String()
	for _, want := range []string{
		`"level":"DEBUG","msg":"hydra.request","operation":"accept_login","status":200,"duration_ms":`,
		`,"flow":"main","app":"sql"}`,
		`"msg":"hydra.request","operation":"get_consent_request","status":404,"duration_ms":`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %s:\n%s", want, got)
		}
	}
	for _, s := range []string{"sentinel", "verifier"} {
		if strings.Contains(got, s) {
			t.Errorf("%s in the lines:\n%s", s, got)
		}
	}
	// Above the level debug, none.
	logs.Reset()
	c.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	_, _ = c.AcceptLogin(ctx, "challenge-sentinel", ory.AcceptOAuth2LoginRequest{Subject: "subject-sentinel"})
	if logs.Len() > 0 {
		t.Errorf("at info: %s", logs.String())
	}
}
