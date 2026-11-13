package adminui

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// The screen of the level (P25): a window opened for a duration offered, in a
// scope of known flows and apps, then closed; the viewer reads it.
func TestLogLevelScreen(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/log-level", nil).Body.String()
	for _, want := range []string{"<strong>info</strong>", "No window of debug is open.", `<option value="15m" selected>15m</option>`,
		`<option value="1h">1h</option>`, `<option value="simple">simple</option>`, `<option value="pwd">pwd</option>`,
		`<a href="/admin/log-level" aria-current="page">Log level</a>`} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %s:\n%s", want, page)
		}
	}
	if strings.Contains(page, `value="close"`) || strings.Contains(page, `<option value="2h"`) {
		t.Errorf("page:\n%s", page)
	}
	csrf := token(t, b.do(http.MethodGet, "/admin/log-level", nil))
	open := url.Values{"csrf": {csrf}, "action": {"open"}, "duration": {"30m"}, "flow": {"simple"}, "app": {"pwd"}, "trace_id": {" 4bf92f3577b34da6a3ce929d0e0e4736 "}}
	if w := b.do(http.MethodPost, "/admin/log-level", open); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/log-level?done=opened" {
		t.Fatalf("open: %d\n%s", w.Code, w.Body)
	}
	if d := r.config.debug; d == nil || !d.Until.Equal(r.now.Add(30*time.Minute)) || d.Flow != "simple" || d.App != "pwd" ||
		d.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || d.UpdatedBy != "admin:alice" {
		t.Fatalf("window: %+v", r.config.debug)
	}
	page = b.do(http.MethodGet, "/admin/log-level?done=opened", nil).Body.String()
	for _, want := range []string{"The window of debug is open", `<time datetime="2027-01-15T08:30:00Z">2027-01-15 08:30:00 UTC</time>`,
		"opened by admin:alice", "the flow <code>simple</code>, the app <code>pwd</code>, the request <code>4bf92f3577b34da6a3ce929d0e0e4736</code>.",
		`value="close"`, "Another window, in place of this one"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %s:\n%s", want, page)
		}
	}
	// The viewer reads it, without a button.
	v := r.browser()
	v.login("victor", password, "")
	page = v.do(http.MethodGet, "/admin/log-level", nil).Body.String()
	if !strings.Contains(page, "opened by admin:alice") || strings.Contains(page, `value="close"`) || !strings.Contains(page, "<fieldset disabled>") {
		t.Errorf("viewer:\n%s", page)
	}
	if w := v.do(http.MethodPost, "/admin/log-level", url.Values{"csrf": {token(t, v.do(http.MethodGet, "/admin/log-level", nil))}, "action": {"close"}}); w.Code != http.StatusForbidden || r.config.debug == nil {
		t.Errorf("viewer closes: %d", w.Code)
	}
	// Past its end, none.
	until := r.config.debug.Until
	r.config.debug.Until = r.now
	if page := b.do(http.MethodGet, "/admin/log-level", nil).Body.String(); !strings.Contains(page, "No window of debug is open.") {
		t.Errorf("ended:\n%s", page)
	}
	r.config.debug.Until = until

	// Refused: a duration not offered, an unknown flow, a trace id that is none.
	for _, c := range []struct {
		field, value, want string
	}{
		{"duration", "2h", "is not one of those offered"},
		{"duration", "", "is not one of those offered"},
		{"flow", "other", `&#34;other&#34; is no flow`},
		{"app", "other", `&#34;other&#34; is no app`},
		{"trace_id", "4BF92F35", "is not a trace id"},
	} {
		form := url.Values{"csrf": {csrf}, "action": {"open"}, "duration": {"15m"}}
		form.Set(c.field, c.value)
		w := b.do(http.MethodPost, "/admin/log-level", form)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s=%s: %d\n%s", c.field, c.value, w.Code, w.Body)
		}
		// The form keeps what was typed.
		if c.field == "trace_id" && !strings.Contains(w.Body.String(), `value="4BF92F35"`) {
			t.Errorf("trace id lost:\n%s", w.Body)
		}
	}
	if r.config.debug == nil || r.config.debug.Flow != "simple" {
		t.Errorf("a refused write wrote: %+v", r.config.debug)
	}
	// Closed; the default duration, 15 minutes, every line.
	if w := b.do(http.MethodPost, "/admin/log-level", url.Values{"csrf": {csrf}, "action": {"close"}}); w.Code != http.StatusSeeOther || r.config.debug != nil {
		t.Fatalf("close: %d %+v", w.Code, r.config.debug)
	}
	if w := b.do(http.MethodPost, "/admin/log-level", url.Values{"csrf": {csrf}, "duration": {"15m"}}); w.Code != http.StatusSeeOther ||
		r.config.debug == nil || r.config.debug.Flow != "" || !r.config.debug.Until.Equal(r.now.Add(15*time.Minute)) {
		t.Fatalf("every line: %d %+v", w.Code, r.config.debug)
	}
	if page := b.do(http.MethodGet, "/admin/log-level", nil).Body.String(); !strings.Contains(page, "Its scope: every line.") {
		t.Errorf("every line:\n%s", page)
	}
	want := []string{"write alice log-level  open duration,flow,app,trace_id", "write alice log-level  close ", "write alice log-level  open duration"}
	if got := slices.DeleteFunc(r.wrote(), func(s string) bool { return !strings.Contains(s, "log-level") }); !slices.Equal(got, want) {
		t.Errorf("audit: %q", got)
	}
}

// The durations offered: those up to the maximum, and it.
func TestDebugChoices(t *testing.T) {
	for max, want := range map[time.Duration]string{
		time.Hour:        "5m 15m 30m 1h",
		2 * time.Hour:    "5m 15m 30m 1h 2h",
		10 * time.Minute: "5m 10m",
		90 * time.Minute: "5m 15m 30m 1h 1h30m",
		time.Minute:      "1m",
	} {
		var got []string
		for _, d := range debugChoices(max) {
			got = append(got, shortDuration(d))
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s: %q, want %q", max, got, want)
		}
	}
}
