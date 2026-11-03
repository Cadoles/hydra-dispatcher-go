// Package capture sorts what tools/recorder writes: after each scenario that
// tools/scenarios or examples/hydra-dev/e2e plays, the exchanges recorded
// since it started move to a directory of their own.
package capture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Inbox is the directory the recorder writes to, testdata/capture under
// make capture or make capture-go.
type Inbox string

// Listing returns the exchanges written so far.
func (in Inbox) Listing() (map[string]bool, error) {
	entries, err := os.ReadDir(string(in))
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names[e.Name()] = true
		}
	}
	return names, nil
}

// Collect moves into dir the exchanges written since before, a Listing, and
// returns how many. None is an error: the recorder is not running.
func (in Inbox) Collect(before map[string]bool, dir string) (int, error) {
	time.Sleep(time.Second) // the recorder writes once the exchange is over
	now, err := in.Listing()
	if err != nil {
		return 0, err
	}
	var fresh []string
	for name := range now {
		if !before[name] {
			fresh = append(fresh, name)
		}
	}
	if len(fresh) == 0 {
		return 0, fmt.Errorf("nothing recorded in %s: is make capture running?", in)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	for _, name := range fresh {
		if err := move(filepath.Join(string(in), name), filepath.Join(dir, name)); err != nil {
			return 0, err
		}
	}
	return len(fresh), nil
}

// EnsureEmpty fails when dir already holds files. The recorder numbers from
// the files left in the inbox, which Collect empties: a rerun's files would
// sit beside the earlier ones.
func EnsureEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty: remove it to record the scenario again", dir)
	}
	return nil
}

// move renames, or copies then removes across file systems.
func move(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		return err
	}
	return os.Remove(from)
}
