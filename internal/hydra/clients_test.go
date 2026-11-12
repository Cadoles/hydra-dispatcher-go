package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The clients of the admin API as JSON, whole: a page and its next token,
// the filter by name, a creation, a JSON Patch, a deletion, Hydra's refusals.
func TestClients(t *testing.T) {
	type seen struct{ method, path, query, body string }
	var calls []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, seen{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(b)})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/clients":
			w.Header().Add("Link", `</admin/clients?page_size=2&page_token=first>; rel="first"`)
			w.Header().Add("Link", `</admin/clients?page_size=2&page_token=eyJvZmZzZXQiOiIyIn0>; rel="next"`)
			w.Header().Set("X-Total-Count", "3")
			_, _ = w.Write([]byte(`[{"client_id":"a","jwks":{"keys":[{"kty":"EC"}]},"new_of_2.3":1},{"client_id":"b"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/clients/a b":
			_, _ = w.Write([]byte(`{"client_id":"a b"}`))
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"Unable to locate the resource","error_description":""}`))
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_id":"generated","client_secret":"s3cret"}`))
		case r.Method == http.MethodPatch && strings.Contains(string(b), "implicit"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client_metadata","error_description":"The grant is not allowed"}`))
		case r.Method == http.MethodPatch:
			_, _ = w.Write([]byte(`{"client_id":"a","client_name":"A"}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, 4, time.Second)
	ctx := context.Background()

	l, err := c.Clients(ctx, ClientsPage{Size: 2, Name: "A client"})
	if err != nil || len(l.Clients) != 2 || l.Next != "eyJvZmZzZXQiOiIyIn0" || l.Total != 3 || !strings.Contains(string(l.Clients[0]), `"new_of_2.3":1`) {
		t.Fatalf("page: %+v %v", l, err)
	}
	if calls[0].query != "client_name=A+client&page_size=2" {
		t.Errorf("query: %q", calls[0].query)
	}
	if _, err := c.Clients(ctx, ClientsPage{Size: 2, Token: "eyJvZmZzZXQiOiIyIn0"}); err != nil || !strings.Contains(calls[1].query, "page_token=eyJvZmZzZXQiOiIyIn0") {
		t.Errorf("next page: %v %q", err, calls[1].query)
	}
	if got, err := c.OAuthClient(ctx, "a b"); err != nil || string(got) != `{"client_id":"a b"}` || calls[2].path != "/admin/clients/a%20b" {
		t.Errorf("get: %s %v %q", got, err, calls[2].path)
	}
	var reqErr *RequestError
	if _, err := c.OAuthClient(ctx, "nobody"); !errors.As(err, &reqErr) || reqErr.Status != http.StatusNotFound {
		t.Errorf("absent: %v", err)
	}
	created, err := c.CreateClient(ctx, map[string]any{"client_name": "A", "client_secret": "s3cret"})
	if err != nil || !strings.Contains(string(created), `"client_id":"generated"`) || !strings.Contains(calls[4].body, `"client_name":"A"`) {
		t.Errorf("create: %s %v %+v", created, err, calls[4])
	}
	if _, err := c.PatchClient(ctx, "a", []PatchOp{{Op: "replace", Path: "/client_name", Value: "A"}, {Op: "remove", Path: "/logo_uri"}}); err != nil {
		t.Errorf("patch: %v", err)
	}
	var ops []map[string]any
	if json.Unmarshal([]byte(calls[5].body), &ops) != nil || len(ops) != 2 || ops[0]["op"] != "replace" || ops[0]["value"] != "A" || ops[1]["path"] != "/logo_uri" {
		t.Errorf("patch body: %s", calls[5].body)
	}
	if _, err := c.PatchClient(ctx, "a", []PatchOp{{Op: "add", Path: "/grant_types/-", Value: "implicit"}}); !errors.As(err, &reqErr) ||
		reqErr.Status != http.StatusBadRequest || !strings.Contains(string(reqErr.Body), "The grant is not allowed") {
		t.Errorf("refused: %v", err)
	}
	if err := c.DeleteClient(ctx, "a"); err != nil || calls[7].method != http.MethodDelete {
		t.Errorf("delete: %v", err)
	}
}

func TestNextToken(t *testing.T) {
	for links, want := range map[string]string{
		`</admin/clients?page_size=2&page_token=abc>; rel="next", </admin/clients?page_token=x>; rel="first"`: "abc",
		`</admin/clients?page_token=x>; rel="first"`:                                                          "",
		``: "",
	} {
		if got := nextToken(strings.Split(links, ", ")); got != want {
			t.Errorf("%q: %q", links, got)
		}
	}
}
