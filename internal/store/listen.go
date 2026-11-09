package store

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The waits of Listen between two connections, doubled from one to the next.
const (
	listenRetryMin = time.Second
	listenRetryMax = 30 * time.Second
)

// listenIdle is how long the connection of Listen may stay silent before a
// ping: a server gone without a reset would otherwise hold it, every
// notification lost, until TCP gives up. The tests shorten it.
var listenIdle = RefreshEvery

// Listen calls changed at each write of any instance, bootstrap's included,
// until ctx ends: on a connection of its own, outside the pool, in LISTEN on
// the channel the writes notify at their commit (Q99). changed asks for a
// refresh, Live.Changed. It is called too each time the connection is made
// again: the writes of the time without it notified no one. A connection
// lost or refused is made again after 1 s, then up to 30 s; config.listen_failed
// is logged once, config.listen_recovered when it listens again. The refresh
// of Live every RefreshEvery remains the net: behind PgBouncer in transaction
// mode, say, where LISTEN sees nothing.
func (p *Postgres) Listen(ctx context.Context, changed func(), logger *slog.Logger) {
	retry, failed := listenRetryMin, false
	for {
		err := p.listen(ctx, func() {
			if failed {
				logger.InfoContext(ctx, "config.listen_recovered")
			}
			retry, failed = listenRetryMin, false
			changed()
		}, changed)
		if ctx.Err() != nil {
			return
		}
		if !failed {
			logger.WarnContext(ctx, "config.listen_failed", "cause", err.Error(), "refresh_every", RefreshEvery.String())
			failed = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(2*retry, listenRetryMax)
	}
}

// listen connects, listens, calls listening, then changed at each
// notification, until an error or the end of ctx.
func (p *Postgres) listen(ctx context.Context, listening, changed func()) error {
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := pgx.ConnectConfig(connectCtx, p.cfg.Copy())
	cancel()
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		return err
	}
	listening()
	for {
		waitCtx, cancel := context.WithTimeout(ctx, listenIdle)
		_, err := conn.WaitForNotification(waitCtx)
		cancel()
		switch {
		case err == nil:
			changed()
		case ctx.Err() != nil:
			return ctx.Err()
		case pgconn.Timeout(err):
			// Silent: the connection may be gone.
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return err
			}
		default:
			return err
		}
	}
}
