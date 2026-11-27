package webhook

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/loglevel"
)

// webhook.request at the level debug for each call (Q132): the kind, the host,
// the status, the duration, the names of the claims of each member returned,
// the flow and the app of the request; never a value, a path nor a query.
func TestRequestLines(t *testing.T) {
	ctx := loglevel.WithScope(browserContext(t, "203.0.113.9:1234", "Firefox"), "main", "sql")
	c := newClient(t)
	var logs bytes.Buffer
	c.Log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ok := newReceiver(t, http.StatusOK, "application/json", `{"id_token":{"email":"value-sentinel","name":null},"access_token":{}}`)
	if a := c.Consent(ctx, consentCall(ok.URL+"/hook/path-sentinel?q=query-sentinel")); a.Err != nil {
		t.Fatal(a.Err)
	}
	failed := newReceiver(t, http.StatusInternalServerError, "application/json", `{}`)
	if a := c.Login(ctx, loginCall(failed.URL+"/hook")); a.Err == nil {
		t.Fatal("a 500 answered")
	}
	if a := c.Login(ctx, loginCall(script(t, `cat > /dev/null; echo '{"subject":"bob"}'`))); a.Err != nil {
		t.Fatal(a.Err)
	}
	got := logs.String()
	host := strings.TrimPrefix(ok.URL, "http://")
	for _, want := range []string{
		`"msg":"webhook.request","kind":"consent","host":"` + host + `","status":200,"duration_ms":`,
		`,"id_token":["email","name"],"access_token":[],"flow":"main","app":"sql"}`,
		`"msg":"webhook.request","kind":"login","host":"` + strings.TrimPrefix(failed.URL, "http://") + `","status":500,"duration_ms":`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %s:\n%s", want, got)
		}
	}
	// A program: its name, status 0.
	if lines := strings.Split(strings.TrimSpace(got), "\n"); len(lines) != 3 || !strings.Contains(lines[2], `"kind":"login","host":"hook.sh","status":0,`) {
		t.Errorf("the program's line:\n%s", got)
	}
	for _, s := range []string{"sentinel", "alice", "bob"} {
		if strings.Contains(got, s) {
			t.Errorf("%s in the lines:\n%s", s, got)
		}
	}
}
