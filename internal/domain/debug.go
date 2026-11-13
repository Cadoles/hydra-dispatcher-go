package domain

import (
	"strings"
	"time"
)

// DebugWindow is the window of debug of the application log (P25, Q131):
// until when its lines of debug pass, and its scope, each field given
// narrowing it to the lines that hold it.
type DebugWindow struct {
	Until   time.Time
	Flow    string
	App     string
	TraceID string
	// UpdatedBy is who opened it, as updated_by of the other tables.
	UpdatedBy string
}

// Open tells whether w is open at now: nil, or ended, it is not.
func (w *DebugWindow) Open(now time.Time) bool { return w != nil && now.Before(w.Until) }

// Check checks w: an end, a flow and an app as their ids, a trace id of
// W3C Trace Context.
func (w DebugWindow) Check(fail Fail) {
	if w.Until.IsZero() {
		fail("until", "is required")
	}
	for _, f := range []struct{ field, id string }{{"flow", w.Flow}, {"app", w.App}} {
		if f.id != "" && !ValidID(f.id) {
			fail(f.field, "%q is not an id", f.id)
		}
	}
	if w.TraceID != "" && !TraceID(w.TraceID) {
		fail("trace_id", "%q is not a trace id: 32 lowercase hexadecimal digits, not all zero", w.TraceID)
	}
}

// TraceID tells whether s is a trace id of W3C Trace Context, as the
// trace_id of the lines writes it: 32 lowercase hexadecimal digits, not all
// zero.
func TraceID(s string) bool {
	return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == "" && strings.Trim(s, "0") != ""
}
