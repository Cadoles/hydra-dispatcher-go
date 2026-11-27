package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The level of the application log (P25), /admin/v1/log-level: the level the
// configuration sets, and the window of debug, opened for a duration in a
// scope, closed by null (Q131). The window is the database's: every instance
// sees it, and answers the same.

// DefaultDebug is the duration of a window that gives none, the doc's;
// observability.debug_max_duration when it is shorter.
const DefaultDebug = 15 * time.Minute

// logLevelJSON is the representation of the level: every field present.
type logLevelJSON struct {
	Level string      `json:"level"`
	Debug *windowJSON `json:"debug"`
}

type windowJSON struct {
	Until     string  `json:"until"`
	Flow      *string `json:"flow"`
	App       *string `json:"app"`
	TraceID   *string `json:"traceId"`
	UpdatedBy string  `json:"updatedBy"`
}

// orNull is s, null for "".
func orNull(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// logLevel is the representation of the level of the moment: a window past
// its end is none.
func (a *API) logLevel() logLevelJSON {
	j := logLevelJSON{Level: a.o.LogLevel}
	if w := a.o.Config.Snapshot().Debug; w.Open(a.o.Now()) {
		j.Debug = &windowJSON{Until: w.Until.UTC().Format(time.RFC3339), Flow: orNull(w.Flow), App: orNull(w.App), TraceID: orNull(w.TraceID), UpdatedBy: w.UpdatedBy}
	}
	return j
}

var windowFields = []string{"duration", "flow", "app", "traceId"}

// DebugDuration reads the duration of a window, "" for the default: a Go
// duration, positive, max at most.
func DebugDuration(s string, max time.Duration) (time.Duration, error) {
	if s == "" {
		return min(DefaultDebug, max), nil
	}
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		return 0, fmt.Errorf("%q is not a duration: 15m, 1h", s)
	case d <= 0:
		return 0, fmt.Errorf("is %s: a window lasts", s)
	case d > max:
		return 0, fmt.Errorf("is %s, longer than observability.debug_max_duration, %s", d, max)
	}
	return d, nil
}

// readWindow reads the window of a body, nil for null.
func (a *API) readWindow(b body) (*store.DebugWindow, []string, error) {
	if err := b.unknown([]string{"debug"}, "level"); err != nil {
		return nil, nil, err
	}
	if b.has("level") {
		return nil, nil, requestViolations{{Field: "level", Message: "is observability.log_level, which the configuration sets: open a window of debug instead"}}
	}
	if !b.has("debug") {
		return nil, nil, requestViolations{{Field: "debug", Message: "is required: a window to open, {\"duration\": \"15m\"}, or null to close the one open"}}
	}
	if b.null("debug") {
		return nil, []string{"debug"}, nil
	}
	var d body
	if err := json.Unmarshal(b["debug"], &d); err != nil || d == nil {
		return nil, nil, typeError("debug", "object", b["debug"])
	}
	if err := d.unknown(windowFields); err != nil {
		var v requestViolations
		errors.As(err, &v)
		for i := range v {
			v[i].Field = "debug." + v[i].Field
		}
		return nil, nil, v
	}
	var values [4]string
	for i, f := range windowFields {
		if !d.has(f) {
			continue
		}
		s, err := d.str(f)
		if err != nil {
			return nil, nil, typeError("debug."+f, "string", d[f])
		}
		values[i] = s
	}
	duration, err := DebugDuration(values[0], a.o.DebugMaxDuration)
	if err != nil {
		return nil, nil, requestViolations{{Field: "debug.duration", Message: err.Error()}}
	}
	fields := []string{"debug"}
	for _, f := range windowFields {
		if d.has(f) {
			fields = append(fields, "debug."+f)
		}
	}
	return &store.DebugWindow{Until: a.o.Now().Add(duration), Flow: values[1], App: values[2], TraceID: values[3]}, fields, nil
}

func (a *API) registerLogLevel() {
	a.Handle("GET "+Prefix+"/log-level", Debug, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeResource(w, http.StatusOK, a.logLevel())
	}))
	a.Handle("PUT "+Prefix+"/log-level", Debug, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(w, r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		window, fields, err := a.readWindow(b)
		if err == nil {
			err = a.o.Writer.SetDebugWindow(r.Context(), author(r), window)
		}
		var v domain.Violations
		if errors.As(err, &v) {
			// The fields of the store are those of the window.
			for i := range v {
				v[i].Field = "debug." + v[i].Field
			}
		}
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		a.wrote(r, Debug, "", fields)
		writeResource(w, http.StatusOK, a.logLevel())
	}))
}
