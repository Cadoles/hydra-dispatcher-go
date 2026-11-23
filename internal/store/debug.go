package store

import (
	"context"
	"database/sql"
	"fmt"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/domain"
)

// DebugWindow is the window of debug of the application log (P25, Q131).
type DebugWindow = domain.DebugWindow

// readDebugWindow reads the window of debug, nil for none; one past its end
// too, which its reader leaves aside.
func readDebugWindow(ctx context.Context, q querier) (*DebugWindow, error) {
	rows, err := q.QueryContext(ctx, `SELECT until, coalesce(flow, ''), coalesce(app, ''), coalesce(trace_id, ''), coalesce(updated_by, '')
		FROM debug_window`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var w DebugWindow
	if err := rows.Scan(&w.Until, &w.Flow, &w.App, &w.TraceID, &w.UpdatedBy); err != nil {
		return nil, err
	}
	w.Until = w.Until.UTC()
	return &w, rows.Err()
}

// SetDebugWindow opens the window w by the author by, in place of the one
// before; nil closes it. The flow and the app of its scope are known.
func (p *Postgres) SetDebugWindow(ctx context.Context, by string, w *DebugWindow) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		if w == nil {
			_, err := tx.ExecContext(ctx, `DELETE FROM debug_window`)
			return err
		}
		if v := domain.Collect(w.Check); v != nil {
			return v
		}
		var v domain.Violations
		if w.Flow != "" {
			if _, found, err := findFlow(ctx, tx, w.Flow); err != nil {
				return err
			} else if !found {
				v = append(v, domain.Violation{Field: "flow", Message: fmt.Sprintf("%q is no flow", w.Flow)})
			}
		}
		if w.App != "" {
			if _, found, err := findApp(ctx, tx, p.secrets, w.App); err != nil {
				return err
			} else if !found {
				v = append(v, domain.Violation{Field: "app", Message: fmt.Sprintf("%q is no app", w.App)})
			}
		}
		if v != nil {
			return v
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO debug_window (id, until, flow, app, trace_id, updated_at, updated_by) VALUES (1, $1, $2, $3, $4, now(), $5)
			ON CONFLICT (id) DO UPDATE SET until = EXCLUDED.until, flow = EXCLUDED.flow, app = EXCLUDED.app, trace_id = EXCLUDED.trace_id,
				updated_at = now(), updated_by = EXCLUDED.updated_by`,
			w.Until, nullable(w.Flow), nullable(w.App), nullable(w.TraceID), by)
		return err
	})
}

// nullable is s, NULL for "".
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
