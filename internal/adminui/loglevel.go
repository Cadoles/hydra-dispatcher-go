package adminui

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The screen of the level of the application log (P25), /admin/log-level:
// the level configured, the window of debug open, a form to open one, in a
// scope, and to close it. Written by the role admin, without a
// re-authentication: the lines of debug hold names, never values.

// defaultDebug is the duration a window is offered first, the doc's.
const defaultDebug = 15 * time.Minute

// debugChoices are the durations offered, those up to the maximum, and it.
func debugChoices(max time.Duration) []time.Duration {
	var l []time.Duration
	for _, d := range []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour} {
		if d <= max {
			l = append(l, d)
		}
	}
	if !slices.Contains(l, max) && max > 0 {
		l = append(l, max)
	}
	return l
}

// shortDuration writes d as 15m or 1h, not 15m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

type durationChoice struct {
	Value    string
	Selected bool
}

// windowView is the window open, as the page shows it.
type windowView struct {
	Until, UntilISO, UpdatedBy string
	Flow, App, TraceID         string
}

type logLevelPage struct {
	Configured string
	Window     *windowView
	Durations  []durationChoice
	Flows      []string
	Apps       []string
	// The fields of the form.
	Flow, App, TraceID string
	Errors             fieldErrors
}

var windowFormFields = []string{"duration", "flow", "app", "trace_id"}

func (ui *UI) registerLogLevel() {
	ui.mux.Handle("GET /admin/log-level", ui.authed(anyRole, ui.logLevel))
	if ui.o.Writer != nil {
		ui.mux.Handle("POST /admin/log-level", ui.authed(adminRole, ui.setLogLevel))
	}
}

// logLevelPage is the page of snap, the form r filled when it is given.
func (ui *UI) logLevelPage(snap *store.Snapshot, r *http.Request, errs fieldErrors) logLevelPage {
	p := logLevelPage{Configured: ui.o.LogLevel, Errors: errs}
	if w := snap.Debug; w.Open(ui.o.Now()) {
		p.Window = &windowView{Until: w.Until.UTC().Format("2006-01-02 15:04:05 UTC"), UntilISO: w.Until.UTC().Format(time.RFC3339),
			UpdatedBy: w.UpdatedBy, Flow: w.Flow, App: w.App, TraceID: w.TraceID}
	}
	chosen := shortDuration(min(defaultDebug, ui.o.DebugMaxDuration))
	if r != nil {
		chosen, p.Flow, p.App, p.TraceID = r.PostFormValue("duration"), r.PostFormValue("flow"), r.PostFormValue("app"), strings.TrimSpace(r.PostFormValue("trace_id"))
	}
	for _, d := range debugChoices(ui.o.DebugMaxDuration) {
		p.Durations = append(p.Durations, durationChoice{Value: shortDuration(d), Selected: shortDuration(d) == chosen})
	}
	for _, f := range snap.Flows {
		p.Flows = append(p.Flows, f.ID)
	}
	for _, a := range snap.Apps {
		p.Apps = append(p.Apps, a.ID)
	}
	return p
}

func (ui *UI) logLevel(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "log_level", "Log level", "log-level", ui.logLevelPage(ui.o.Config.Snapshot(), nil, nil))
}

// setLogLevel opens a window, or closes the one open: on every instance, the
// window being the database's.
func (ui *UI) setLogLevel(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "log_level", "Log level", "log-level", ui.logLevelPage(snap, r, errs))
	}
	if r.PostFormValue("action") == "close" {
		if err := ui.o.Writer.SetDebugWindow(r.Context(), author(s.account.Username), nil); err != nil {
			ui.failed(w, r, s, err, windowFormFields, again)
			return
		}
		ui.wrote(r.Context(), s, "log-level", "", "close", nil)
		http.Redirect(w, r, ui.base+"/log-level?done=closed", http.StatusSeeOther)
		return
	}
	choices := debugChoices(ui.o.DebugMaxDuration)
	i := slices.IndexFunc(choices, func(d time.Duration) bool { return shortDuration(d) == r.PostFormValue("duration") })
	if i < 0 {
		again(http.StatusUnprocessableEntity, fieldErrors{"duration": {"is not one of those offered"}})
		return
	}
	window := &store.DebugWindow{Until: ui.o.Now().Add(choices[i]), Flow: r.PostFormValue("flow"), App: r.PostFormValue("app"),
		TraceID: strings.TrimSpace(r.PostFormValue("trace_id"))}
	if err := ui.o.Writer.SetDebugWindow(r.Context(), author(s.account.Username), window); err != nil {
		ui.failed(w, r, s, err, windowFormFields, again)
		return
	}
	fields := []string{"duration"}
	for _, f := range []struct{ name, value string }{{"flow", window.Flow}, {"app", window.App}, {"trace_id", window.TraceID}} {
		if f.value != "" {
			fields = append(fields, f.name)
		}
	}
	ui.wrote(r.Context(), s, "log-level", "", "open", fields)
	http.Redirect(w, r, ui.base+"/log-level?done=opened", http.StatusSeeOther)
}
