package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestWalk follows a browser's redirects: a 303 turns into a GET without its
// body, a 307 keeps the method, the body and the Origin; the cookies stay
// with their host, never copied from one hop to the next; a redirect to the
// redirect_uri ends the walk unfollowed.
func TestWalk(t *testing.T) {
	var seen []string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" cookie="+r.Header.Get("Cookie")+" origin="+r.Header.Get("Origin")+" body="+string(body))
		if r.URL.Path == "/to-callback" {
			http.Redirect(w, r, "http://oidc.client.test/auth/callback?code=x&state=s", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "page B")
	}))
	defer b.Close()
	// B under another host name: a jar keeps cookies per host, not per port.
	bURL, _ := url.Parse(b.URL)
	bHost := "localhost:" + bURL.Port()
	var seenA []string
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenA = append(seenA, r.URL.Path+" cookie="+r.Header.Get("Cookie"))
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Path: "/"})
		switch r.URL.Path {
		case "/303":
			http.Redirect(w, r, "http://"+bHost+"/after303", http.StatusSeeOther)
		case "/307":
			http.Redirect(w, r, "http://"+bHost+"/after307", http.StatusTemporaryRedirect)
		case "/callback":
			http.Redirect(w, r, "http://"+bHost+"/to-callback", http.StatusSeeOther)
		}
	}))
	defer a.Close()

	br := newBrowser("http://oidc.client.test/auth/callback", slog.New(slog.NewTextHandler(io.Discard, nil)))
	post := func(path string) page {
		t.Helper()
		u, _ := url.Parse(a.URL + path)
		p, err := br.submit(page{URL: u}, form{Action: u, Method: http.MethodPost}, url.Values{"k": {"v"}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	post("/303")
	post("/307")
	p := post("/callback")
	want := []string{
		"GET /after303 cookie= origin= body=",
		"POST /after307 cookie= origin=" + a.URL + " body=k=v",
		"GET /to-callback cookie= origin= body=",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests\n%s\nwant\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
	// The cookie A set comes back to A, and only to A.
	wantA := []string{"/303 cookie=", "/307 cookie=a=1", "/callback cookie=a=1"}
	if strings.Join(seenA, "\n") != strings.Join(wantA, "\n") {
		t.Errorf("requests to A\n%s\nwant\n%s", strings.Join(seenA, "\n"), strings.Join(wantA, "\n"))
	}
	if p.Body != "" || p.URL.String() != "http://oidc.client.test/auth/callback?code=x&state=s" || len(p.Trail) != 3 {
		t.Errorf("walk ended on %s (%d hops, body %q); want the redirect_uri, unfollowed", p.URL, len(p.Trail), p.Body)
	}
}

// TestFindClient wants exactly one client of the name.
func TestFindClient(t *testing.T) {
	for _, tc := range []struct {
		name, clients, want, wantErr string
	}{
		{"one", `[{"client_id":"a","client_name":"OIDC Test Client"},{"client_id":"b","client_name":"other"}]`, "a", ""},
		{"none", `[{"client_id":"b","client_name":"other"}]`, "", "no client named"},
		{"copies", `[{"client_id":"a","client_name":"OIDC Test Client"},{"client_id":"c","client_name":"OIDC Test Client"}]`, "", "2 clients named"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/clients" {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, tc.clients)
			}))
			defer srv.Close()
			admin, _ := url.Parse(srv.URL)
			got, err := findClient(context.Background(), srv.Client(), admin, "OIDC Test Client")
			switch {
			case tc.wantErr == "" && (err != nil || got != tc.want):
				t.Errorf("findClient = %q, %v; want %q", got, err, tc.want)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("findClient = %q, %v; want an error with %q", got, err, tc.wantErr)
			}
		})
	}
}
