package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/config"
)

// fakeSymfony answers as the admin API of Symfony did in the replay
// (testdata/symfony-admin-api): 30 a page, a map empty in [], null fields
// left out, a settings document with Symfony's keys.
func fakeSymfony(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	apps := []string{}
	for i := range 31 {
		apps = append(apps, fmt.Sprintf(`{"id":"app-%02d","loginUrl":"http:\/\/a%02d\/login","consentUrl":"http:\/\/a%02d\/consent","method":"pwd"}`, i, i, i))
	}
	apps[0] = `{"id":"app-00","loginUrl":"http:\/\/a00\/login","consentUrl":"http:\/\/a00\/consent","logoutUrl":"http:\/\/a00\/logout","method":"otp"}`
	page := func(items []string, r *http.Request) string {
		n := 1
		_, _ = fmt.Sscan(r.URL.Query().Get("page"), &n)
		lo, hi := min((n-1)*30, len(items)), min(n*30, len(items))
		return "[" + strings.Join(items[lo:hi], ",") + "]"
	}
	flows := []string{
		`{"title":{"fr":"Deux facteurs","en":"Two factors"},"description":{"fr":"SQL puis OTP"},"enabled":true,"steps":[{"id":4,"appId":"app-01","stepOrder":1},{"id":3,"appId":"app-00","stepOrder":0}],"id":"mfa"}`,
		`{"title":{"fr":"Off"},"description":{"fr":"D","en":null},"iconUrl":[],"enabled":false,"steps":[{"id":7,"appId":"app-02","stepOrder":"3"}],"id":"off"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+r.Host)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/admin/v1/token" {
			if r.FormValue("client_id") != "test" || r.FormValue("client_secret") != "s3cret" || r.FormValue("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"invalid_client","error_description":"Invalid client credentials."}`)
				return
			}
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/admin/v1/apps":
			fmt.Fprint(w, page(apps, r))
		case "/admin/v1/flows":
			fmt.Fprint(w, page(flows, r))
		case "/admin/v1/settings":
			fmt.Fprint(w, `{"id":1,"hydraPublicUrl":"http:\/\/public.hydra.test","appAutoSelect":true,"consentAutoAccept":false,"challengeTtl":3600,"sessionTtl":7200,"aggregateAmrFromLoginRequest":false,"adminAuthorizedHosts":[],"supportedLocales":["fr","en"],"defaultLocale":"fr","fallbackLocale":"en"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// loadSeed loads a seed as bootstrap does.
func loadSeed(t *testing.T, content string) config.Seed {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dispatcher.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path, []string{
		"DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test",
		"DISPATCHER_SERVER_TRUSTED_PROXIES=10.0.0.10",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=10.0.1.0/24",
		"DISPATCHER_HYDRA_ADMIN_URL=http://hydra:4445",
		"DISPATCHER_STORE_DSN=postgres://dispatcher@postgres/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32),
		"DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, content)
	}
	return cfg.Seed
}

func TestExport(t *testing.T) {
	srv, seen := fakeSymfony(t)
	var out, errOut bytes.Buffer
	err := run(context.Background(), []string{"export", "-url", srv.URL + "/", "-host", "dispatcher.hydra.test", "-client-id", "test", "-client-secret-stdin"},
		&out, &errOut, strings.NewReader("s3cret\n"))
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut.String())
	}
	seed := loadSeed(t, out.String())

	// Every page read, then the empty one; the Host given.
	if want := "GET /admin/v1/apps?page=3 dispatcher.hydra.test"; !slices.Contains(*seen, want) || len(seed.Apps) != 31 {
		t.Errorf("%d apps; requests %q", len(seed.Apps), *seen)
	}
	a := seed.Apps[0]
	if a.ID != "app-00" || a.LogoutURL != "http://a00/logout" || a.Method != "otp" || a.ReceiveClaims != nil || a.NullReceiveClaims || len(a.AllowedSources) != 0 {
		t.Errorf("app-00: %+v", a)
	}
	if strings.Contains(out.String(), "receive_claims") {
		t.Error("receive_claims written: null would give an app the Go restricted every claim back")
	}
	if len(seed.Flows) != 2 {
		t.Fatalf("flows: %+v", seed.Flows)
	}
	mfa, off := seed.Flows[0].Flow(), seed.Flows[1].Flow()
	if mfa.ID != "mfa" || mfa.Title["en"] != "Two factors" || len(mfa.Steps) != 2 || mfa.Steps[0].AppID != "app-00" || mfa.Steps[1].Position != 1 || !mfa.Enabled {
		t.Errorf("mfa: %+v", mfa)
	}
	if off.ID != "off" || off.Enabled || len(off.Description) != 1 || len(off.IconURL) != 0 || off.Steps[0].Position != 3 {
		t.Errorf("off: %+v", off)
	}
	s := seed.SeedSettings
	if s.AppAutoSelect == nil || !*s.AppAutoSelect || s.ChallengeTTL == nil || s.ChallengeTTL.Std() != time.Hour ||
		s.LoginRememberFor == nil || s.LoginRememberFor.Std() != 2*time.Hour || s.DefaultLocale == nil || *s.DefaultLocale != "fr" || s.Remember != nil {
		t.Errorf("settings: %+v", s)
	}
	if len(seed.OAuth2Clients) != 0 {
		t.Errorf("clients: %+v", seed.OAuth2Clients)
	}
	for _, w := range []string{"setting hydraPublicUrl left out", "setting adminAuthorizedHosts left out"} {
		if !strings.Contains(errOut.String(), w) {
			t.Errorf("stderr lacks %q:\n%s", w, errOut.String())
		}
	}
	if strings.Contains(out.String()+errOut.String(), "s3cret") {
		t.Error("the secret written")
	}
}

// What bootstrap would refuse is named on stderr; the seed is written still,
// for the admin to correct.
func TestExportWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/v1/token":
			fmt.Fprint(w, `{"access_token":"tok"}`)
		case r.URL.Path == "/admin/v1/settings":
			fmt.Fprint(w, `{"id":1}`)
		case r.URL.Query().Get("page") != "1":
			fmt.Fprint(w, `[]`)
		case r.URL.Path == "/admin/v1/apps":
			fmt.Fprint(w, `[{"id":"a","loginUrl":"not a url","consentUrl":"http:\/\/a\/consent","method":"pwd"}]`)
		case r.URL.Path == "/admin/v1/flows":
			fmt.Fprint(w, `[{"id":"f","title":{"fr":"F"},"description":[],"enabled":true,"steps":[{"id":1,"appId":"gone","stepOrder":0}]}]`)
		default:
			fmt.Fprint(w, `{"id":1}`)
		}
	}))
	t.Cleanup(srv.Close)
	var out, errOut bytes.Buffer
	if err := run(context.Background(), []string{"export", "-url", srv.URL, "-client-id", "c", "-client-secret-stdin"}, &out, &errOut, strings.NewReader("s")); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"app a, login_url:", "flow f, description: is required", `flow f, steps[0]: app "gone" is not declared`} {
		if !strings.Contains(errOut.String(), w) {
			t.Errorf("stderr lacks %q:\n%s", w, errOut.String())
		}
	}
	if !strings.Contains(out.String(), "- id: f") {
		t.Errorf("seed:\n%s", out.String())
	}
}

// A DSN given to accounts as an argument is not printed: it holds a password
// (revue R39).
func TestAccountsArgumentNotPrinted(t *testing.T) {
	for _, args := range [][]string{{"postgres://u:s3cret@h/db"}, {"-symfony-dsn-stdin=postgres://u:s3cret@h/db"}, {"-dry-run=s3cret"}} {
		var out, errOut bytes.Buffer
		err := run(context.Background(), append([]string{"accounts"}, args...), &out, &errOut, strings.NewReader(""))
		if !errors.Is(err, errUsage) || strings.Contains(errOut.String(), "s3cret") {
			t.Errorf("%q: %v\n%s", args, err, errOut.String())
		}
	}
}

func TestExportRefused(t *testing.T) {
	srv, _ := fakeSymfony(t)
	dir := t.TempDir()
	wrong := filepath.Join(dir, "wrong")
	if err := os.WriteFile(wrong, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		args  []string
		usage bool
		err   string
	}{
		"a wrong secret":     {args: []string{"-url", srv.URL, "-client-id", "test", "-client-secret-file", wrong}, err: "token: POST /admin/v1/token: 401"},
		"no secret":          {args: []string{"-url", srv.URL, "-client-id", "test"}, err: "give its file"},
		"no url":             {args: []string{"-client-id", "test"}, usage: true},
		"a secret argument":  {args: []string{"-url", srv.URL, "-client-id", "test", "-client-secret", "s3cret"}, usage: true},
		"an argument beside": {args: []string{"-url", srv.URL, "-client-id", "test", "extra"}, usage: true},
		// What the flag package quoted, a secret among it (revue R39).
		"a secret to a boolean": {args: []string{"-url", srv.URL, "-client-id", "test", "-client-secret-stdin=s3cret"}, usage: true},
		"a secret with a dash":  {args: []string{"-url", srv.URL, "-client-id", "test", "-s3cret"}, usage: true},
		"a secret beside":       {args: []string{"-url", srv.URL, "-client-id", "test", "s3cret"}, usage: true},
	} {
		var out, errOut bytes.Buffer
		err := run(context.Background(), append([]string{"export"}, tt.args...), &out, &errOut, strings.NewReader(""))
		switch {
		case tt.usage && !errors.Is(err, errUsage):
			t.Errorf("%s: %v, want a usage error", name, err)
		case !tt.usage && (err == nil || !strings.Contains(err.Error(), tt.err)):
			t.Errorf("%s: %v, want %q", name, err, tt.err)
		case out.Len() > 0:
			t.Errorf("%s: a seed written:\n%s", name, out.String())
		case strings.Contains(errOut.String(), "s3cret"):
			t.Errorf("%s: the secret printed:\n%s", name, errOut.String())
		}
	}
}
