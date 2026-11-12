package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An answer over the bound fails its read; one under it is read whole.
func TestBoundedAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 512 << 10
		if r.URL.Path == "/big" {
			n = 2 << 20
		}
		_, _ = w.Write([]byte(strings.Repeat("x", n)))
	}))
	defer srv.Close()
	c := &http.Client{Transport: BoundedAnswers(http.DefaultTransport, 1<<20)}
	for path, ok := range map[string]bool{"/small": true, "/big": false} {
		resp, err := c.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if (err == nil) != ok {
			t.Errorf("%s: %v", path, err)
		}
	}
}
