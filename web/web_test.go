package web

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"
)

// The bundle of Scalar embedded is the one fetch.sh pins: a file changed by
// hand, or a version moved without its sum, fails here, without the network
// the job of the CI needs.
func TestScalarPinned(t *testing.T) {
	script, err := os.ReadFile("scalar/fetch.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^SHA256=([0-9a-f]{64})$`).FindSubmatch(script)
	if m == nil {
		t.Fatal("no SHA256= in fetch.sh")
	}
	data, err := Scalar.ReadFile("scalar/standalone.js")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != string(m[1]) {
		t.Errorf("standalone.js has the sha256 %s, fetch.sh pins %s", got, m[1])
	}
}
