package front

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sync"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

// reloader reads the theme again when one of its files changed, for ui.reload
// (Q93): the whole theme, its check redone, so that a theme that passes in
// development starts in production.
type reloader struct {
	dir    string
	check  func(*Theme) error
	logger *slog.Logger

	// mu runs one reading at a time: requests in development, not in
	// production.
	mu sync.Mutex
	// stamp is that of the files last read, theme the theme they gave, err
	// the failure of their reading or check.
	stamp string
	theme *Theme
	err   error
}

func newReloader(th *Theme, check func(*Theme) error, logger *slog.Logger) *reloader {
	stamp, _ := stampOf(th.Dir) // a failure reads it again at the first page
	return &reloader{dir: th.Dir, check: check, logger: logger, stamp: stamp, theme: th}
}

// current returns the theme, read again when a file changed; the error of the
// theme read, until a change corrects it.
func (l *reloader) current(ctx context.Context) (*Theme, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	stamp, err := stampOf(l.dir)
	if err == nil && stamp == l.stamp {
		return l.theme, l.err
	}
	l.stamp = stamp // "" on an error: read again at the next page
	th, err := LoadTheme(l.dir)
	if err == nil {
		err = l.check(th)
	}
	if err != nil {
		l.err = err
		l.logger.ErrorContext(ctx, "theme.reload_failed", "dir", l.dir, "err", err)
		return nil, err
	}
	if l.err != nil {
		l.logger.InfoContext(ctx, "theme.reloaded", "dir", l.dir)
	}
	l.theme, l.err = th, nil
	return th, nil
}

// stampOf sums up the files of dir, their names, sizes and modification
// times, links followed: a file written changes it.
func stampOf(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	fsys := root.FS()
	h := sha256.New()
	err = fs.WalkDir(fsys, ".", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := fs.Stat(fsys, name)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%q %d %d %v\n", name, info.Size(), info.ModTime().UnixNano(), info.IsDir())
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), err
}

// themeKey holds the theme of a request, read again by ui.reload.
type themeKey struct{}

// themeOf is the theme a request renders its page with: the one ui.reload read
// for it, else the one of the start.
func (h *Handler) themeOf(r *http.Request) *Theme {
	if th, ok := r.Context().Value(themeKey{}).(*Theme); ok {
		return th
	}
	return h.theme
}

// withTheme reads the theme again for each request when ui.reload is on, before
// anything else: a theme that fails answers 500 with the error of its check and
// the trace id, without running the request (Q93).
func (h *Handler) withTheme(next http.Handler) http.Handler {
	if h.reload == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		th, err := h.reload.current(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, "theme %s: refused (ui.reload), trace id %s\n\n%v\n", h.reload.dir, httpx.TraceID(r.Context()), err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), themeKey{}, th)))
	})
}
