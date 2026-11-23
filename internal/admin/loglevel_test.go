package admin

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The level of the application log (P25): the configured one, the window of
// debug opened for a duration in a scope, past its end none, closed by null.
func TestLogLevel(t *testing.T) {
	r := newResources(t)
	// The clock of the tokens too: the real one, to the second.
	start := time.Now().UTC().Truncate(time.Second)
	now := start
	r.api.o.Now = func() time.Time { return now }
	at := func(d time.Duration) string { return start.Add(d).Format(time.RFC3339) }
	r.writer.apps = []store.App{{ID: "sql"}}
	r.writer.flows = []store.Flow{{ID: "main"}}
	r.writer.publish()
	type window struct {
		Until     string  `json:"until"`
		Flow      *string `json:"flow"`
		App       *string `json:"app"`
		TraceID   *string `json:"traceId"`
		UpdatedBy string  `json:"updatedBy"`
	}
	read := func(w interface{ Result() *http.Response }, body []byte) (string, *window) {
		t.Helper()
		var l struct {
			Level string  `json:"level"`
			Debug *window `json:"debug"`
		}
		if err := json.Unmarshal(body, &l); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		return l.Level, l.Debug
	}
	get := func() (string, *window) {
		t.Helper()
		w := r.do(r.reader, http.MethodGet, Prefix+"/log-level", "", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"debug":`) {
			t.Fatalf("get: %d %s", w.Code, w.Body)
		}
		return read(w, w.Body.Bytes())
	}
	if level, d := get(); level != "info" || d != nil {
		t.Fatalf("at first: %s %+v", level, d)
	}

	w := r.do(r.all, http.MethodPut, Prefix+"/log-level", "", `{"debug":{"duration":"30m","flow":"main","app":"sql","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("open: %d %s", w.Code, w.Body)
	}
	if _, d := read(w, w.Body.Bytes()); d == nil || d.Until != at(30*time.Minute) || *d.Flow != "main" || *d.App != "sql" || *d.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || d.UpdatedBy != "api_client:all" {
		t.Fatalf("opened: %s", w.Body)
	}
	if _, d := get(); d == nil || d.Until != at(30*time.Minute) {
		t.Errorf("read back: %+v", d)
	}
	// Past its end, none; the tokens issued again at that time.
	now = now.Add(30 * time.Minute)
	for _, c := range []struct {
		id    string
		token *string
	}{{"all", &r.all}, {"reader", &r.reader}, {"flows", &r.flows}} {
		client, _ := r.writer.config.Snapshot().APIClient(c.id)
		tok, err := r.keys.Issue(issuer, c.id, client.Scopes, 15*time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		*c.token = tok
	}
	if _, d := get(); d != nil {
		t.Errorf("ended: %+v", d)
	}
	// Without a duration, 15 minutes; without a scope, every line.
	w = r.do(r.all, http.MethodPut, Prefix+"/log-level", "", `{"debug":{}}`)
	if _, d := read(w, w.Body.Bytes()); w.Code != http.StatusOK || d == nil || d.Until != at(45*time.Minute) || d.Flow != nil || d.App != nil || d.TraceID != nil {
		t.Fatalf("default: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"flow":null,"app":null,"traceId":null`) {
		t.Errorf("a scope absent is null: %s", w.Body)
	}
	// Closed.
	w = r.do(r.all, http.MethodPut, Prefix+"/log-level", "", `{"debug":null}`)
	if _, d := read(w, w.Body.Bytes()); w.Code != http.StatusOK || d != nil || r.writer.debug != nil {
		t.Fatalf("closed: %d %s", w.Code, w.Body)
	}

	for body, want := range map[string][]string{
		`{"debug":{"duration":"2h"}}`:                             {"debug.duration"},
		`{"debug":{"duration":"0s"}}`:                             {"debug.duration"},
		`{"debug":{"duration":"-1m"}}`:                            {"debug.duration"},
		`{"debug":{"duration":"soon"}}`:                           {"debug.duration"},
		`{"debug":{"flow":"other"}}`:                              {"debug.flow"},
		`{"debug":{"app":"other"}}`:                               {"debug.app"},
		`{"debug":{"flow":"../x"}}`:                               {"debug.flow"},
		`{"debug":{"traceId":"4BF92F35"}}`:                        {"debug.traceId"},
		`{"debug":{"traceId":"` + strings.Repeat("0", 32) + `"}}`: {"debug.traceId"},
		`{"debug":{"level":"debug"}}`:                             {"debug.level"},
		`{"level":"debug"}`:                                       {"level"},
		`{}`:                                                      {"debug"},
		`{"debug":null,"other":1}`:                                {"other"},
	} {
		w := r.do(r.all, http.MethodPut, Prefix+"/log-level", "", body)
		if w.Code != http.StatusUnprocessableEntity || !slices.Equal(paths(t, w), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	for _, body := range []string{`{"debug":"15m"}`, `{"debug":{"duration":15}}`, `[]`} {
		if w := r.do(r.all, http.MethodPut, Prefix+"/log-level", "", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if r.writer.debug != nil {
		t.Errorf("a refused write wrote: %+v", r.writer.debug)
	}
	// A maximum shorter than 15 minutes is the default.
	r.api.o.DebugMaxDuration = 5 * time.Minute
	w = r.do(r.all, http.MethodPut, Prefix+"/log-level", "", `{"debug":{"flow":null}}`)
	if _, d := read(w, w.Body.Bytes()); w.Code != http.StatusOK || d == nil || d.Until != at(35*time.Minute) {
		t.Errorf("shorter maximum: %d %s", w.Code, w.Body)
	}

	// admin:debug writes, admin:read reads.
	if w := r.do(r.reader, http.MethodPut, Prefix+"/log-level", "", `{"debug":null}`); w.Code != http.StatusForbidden {
		t.Errorf("admin:read writes: %d", w.Code)
	}
	if w := r.do(r.flows, http.MethodGet, Prefix+"/log-level", "", ""); w.Code != http.StatusForbidden {
		t.Errorf("admin:flows reads: %d", w.Code)
	}
	audit := strings.Join(r.wrote, "\n")
	for _, want := range []string{
		"all PUT log-level  debug,debug.duration,debug.flow,debug.app,debug.traceId",
		"all PUT log-level  debug\n",
		"all PUT log-level  debug,debug.flow",
	} {
		if !strings.Contains(audit+"\n", want) {
			t.Errorf("audit lacks %q:\n%s", want, audit)
		}
	}
	if strings.Count(audit, "log-level") != 4 {
		t.Errorf("a refused write audited:\n%s", audit)
	}
}
