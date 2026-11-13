//go:build integration

package store

import (
	"context"
	"testing"
	"time"
)

// The window of debug (P25, Q131): opened, replaced, closed, read in the
// snapshot, on another instance within a second; its flow and its app known,
// a deletion of them never held back.
func TestDebugWindowOnPostgres(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	other := newInstance(t, p)
	if err := p.CreateApp(ctx, "test", testApp("sql")); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateFlow(ctx, "test", testFlow("main", "sql")); err != nil {
		t.Fatal(err)
	}
	until := time.Date(2026, 11, 13, 10, 15, 0, 0, time.UTC)
	w := &DebugWindow{Until: until, Flow: "main", App: "sql", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736"}
	if err := p.SetDebugWindow(ctx, "admin:alice", w); err != nil {
		t.Fatal(err)
	}
	snap, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := snap.Debug; d == nil || !d.Until.Equal(until) || d.Until.Location() != time.UTC || d.Flow != "main" || d.App != "sql" ||
		d.TraceID != w.TraceID || d.UpdatedBy != "admin:alice" {
		t.Fatalf("read: %+v", snap.Debug)
	}
	if !within(time.Second, func() bool { d := other.live.Snapshot().Debug; return d != nil && d.Flow == "main" }) {
		t.Fatal("the window was not seen on the other instance within 1 s")
	}
	// Another, in place of the first, without a scope.
	if err := p.SetDebugWindow(ctx, "api_client:ops", &DebugWindow{Until: until.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if snap, err = p.Snapshot(ctx); err != nil || snap.Debug == nil || snap.Debug.Flow != "" || snap.Debug.TraceID != "" ||
		!snap.Debug.Until.Equal(until.Add(time.Hour)) || snap.Debug.UpdatedBy != "api_client:ops" {
		t.Fatalf("replaced: %+v, %v", snap.Debug, err)
	}
	// Refused: an unknown flow, an unknown app, a trace id that is none.
	for _, c := range []struct {
		w     DebugWindow
		field string
	}{
		{DebugWindow{Until: until, Flow: "other"}, "flow"},
		{DebugWindow{Until: until, App: "other"}, "app"},
		{DebugWindow{Until: until, TraceID: "4BF92F3577B34DA6A3CE929D0E0E4736"}, "trace_id"},
		{DebugWindow{Flow: "main"}, "until"},
	} {
		if err := p.SetDebugWindow(ctx, "test", &c.w); !violated(err, c.field) {
			t.Errorf("%+v: %v", c.w, err)
		}
	}
	if err := p.SetDebugWindow(ctx, "", &DebugWindow{Until: until}); err == nil {
		t.Error("without an author")
	}
	// The table refuses what the store would not write.
	if _, err := p.db.Exec(`UPDATE debug_window SET trace_id = 'not a trace'`); err == nil {
		t.Error("the table took a trace id that is none")
	}
	if _, err := p.db.Exec(`INSERT INTO debug_window (id, until) VALUES (2, now())`); err == nil {
		t.Error("the table took a second window")
	}
	// The flow of a window deleted: the window stays, the flow goes.
	if err := p.SetDebugWindow(ctx, "test", &DebugWindow{Until: until, Flow: "main", App: "sql"}); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteFlow(ctx, "main"); err != nil {
		t.Fatalf("the flow of the window deleted: %v", err)
	}
	if err := p.DeleteApp(ctx, "sql"); err != nil {
		t.Fatalf("the app of the window deleted: %v", err)
	}
	// Closed, here and there.
	if err := p.SetDebugWindow(ctx, "test", nil); err != nil {
		t.Fatal(err)
	}
	if snap, err = p.Snapshot(ctx); err != nil || snap.Debug != nil {
		t.Fatalf("closed: %+v, %v", snap.Debug, err)
	}
	if !within(time.Second, func() bool { return other.live.Snapshot().Debug == nil }) {
		t.Error("the close was not seen on the other instance within 1 s")
	}
	if err := p.SetDebugWindow(ctx, "test", nil); err != nil {
		t.Errorf("closed twice: %v", err)
	}
}
