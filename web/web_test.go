package web

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"
)

// The files embedded are those their fetch.sh pins: a file changed by hand,
// or a version moved without its sum, fails here, without the network the
// jobs of the CI need. Scalar for /admin/v1/docs, Pico for the admin UI.
func TestPinned(t *testing.T) {
	for _, tt := range []struct {
		script, file string
		fs           interface{ ReadFile(string) ([]byte, error) }
	}{
		{"scalar/fetch.sh", "scalar/standalone.js", Scalar},
		{"pico/fetch.sh", "pico/pico.classless.min.css", Pico},
	} {
		script, err := os.ReadFile(tt.script)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`(?m)^SHA256=([0-9a-f]{64})$`).FindSubmatch(script)
		if m == nil {
			t.Fatalf("no SHA256= in %s", tt.script)
		}
		data, err := tt.fs.ReadFile(tt.file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != string(m[1]) {
			t.Errorf("%s has the sha256 %s, %s pins %s", tt.file, got, tt.script, m[1])
		}
	}
}
