package capture

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestCollect moves the exchanges written since the listing, the .json
// files only, and fails when there are none.
func TestCollect(t *testing.T) {
	settle = 0
	inbox, into := t.TempDir(), t.TempDir()
	in := Inbox(inbox)
	write(t, inbox, "0001-front-GET-root.json")
	write(t, inbox, "notes.txt")
	before, err := in.Listing()
	if err != nil {
		t.Fatal(err)
	}
	if !before["0001-front-GET-root.json"] || before["notes.txt"] {
		t.Errorf("listing %v; want the .json files only", before)
	}

	write(t, inbox, "0002-hydra-GET-login.json")
	write(t, inbox, "0003-front-POST-root.json")
	dir := filepath.Join(into, "01-scenario")
	moved, err := in.Collect(before, dir)
	if err != nil || moved != 2 {
		t.Fatalf("Collect = %d, %v; want 2", moved, err)
	}
	if got := names(t, dir); !slices.Equal(got, []string{"0002-hydra-GET-login.json", "0003-front-POST-root.json"}) {
		t.Errorf("scenario directory %v", got)
	}
	if got := names(t, inbox); !slices.Equal(got, []string{"0001-front-GET-root.json", "notes.txt"}) {
		t.Errorf("inbox left with %v", got)
	}

	after, _ := in.Listing()
	if _, err := in.Collect(after, filepath.Join(into, "02-nothing")); err == nil || !strings.Contains(err.Error(), "nothing recorded") {
		t.Errorf("Collect of nothing: %v; want the recorder not running", err)
	}
}

func TestEnsureEmpty(t *testing.T) {
	root := t.TempDir()
	full := filepath.Join(root, "full")
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, full, "0001-front-GET-root.json")
	for _, tc := range []struct {
		name, dir string
		fails     bool
	}{
		{"absent", filepath.Join(root, "absent"), false},
		{"empty", t.TempDir(), false},
		{"holds files", full, true},
	} {
		if err := EnsureEmpty(tc.dir); (err != nil) != tc.fails {
			t.Errorf("%s: EnsureEmpty = %v; want an error %v", tc.name, err, tc.fails)
		}
	}
}
