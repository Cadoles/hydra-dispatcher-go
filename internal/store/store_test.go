package store

import (
	"context"
	"strings"
	"testing"
)

// A DSN that does not parse names store.dsn; neither error shows the
// password.
func TestOpenErrors(t *testing.T) {
	for dsn, want := range map[string]string{
		"postgres://u:s3cret@127.0.0.1:badport/db":                     "store.dsn: cannot parse `postgres://u:xxxxx@127.0.0.1:badport/db`: invalid port",
		"host=127.0.0.1 user=u password=s3cret sslmode=bogus":          "store.dsn: cannot parse",
		"postgres://u:s3cret@127.0.0.1:1/db?sslmode=disable":           "database: failed to connect",
		"host=127.0.0.1 port=1 user=u password=s3cret sslmode=disable": "database: failed to connect",
	} {
		_, err := Open(context.Background(), dsn)
		if err == nil || !strings.HasPrefix(err.Error(), want) || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: err = %v, want %q and no password", dsn, err, want)
		}
	}
}
