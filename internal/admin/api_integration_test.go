//go:build integration

package admin

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The integration tests need a Postgres where they may create databases: the
// tag without DATABASE_URL fails rather than passing untested.
func TestMain(m *testing.M) {
	if os.Getenv("DATABASE_URL") == "" {
		fmt.Fprintln(os.Stderr, "the integration tag needs DATABASE_URL: a postgres:// URL of a Postgres 17 where the tests may create databases")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// newDatabase creates a database of its own for t, migrated, dropped at its
// end, and returns its URL.
func newDatabase(t *testing.T) string {
	t.Helper()
	base, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", base.String())
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "dispatcher_admin_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE " + name + " WITH (FORCE)")
		_ = admin.Close()
	})
	u := *base
	u.Path = "/" + name
	p, err := store.Open(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	if _, err := p.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return u.String()
}

// instance is a dispatcher on the database: its store, its snapshot refreshed
// at its writes and by LISTEN, and its admin API.
type instance struct {
	db      *store.Postgres
	live    *store.Live
	handler http.Handler
	mu      sync.Mutex
	wrote   []string
}

func newInstance(t *testing.T, dsn string, keys *Keys) *instance {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// What serve refuses of a snapshot: a webhook in http:// here.
	db.SetCheck(func(s *store.Snapshot) error {
		if strings.HasPrefix(s.Settings.LoginAcceptWebhookURL, "http://") {
			return errors.New("setting login_accept_webhook_url: is in http://, which needs tls.allow_http")
		}
		return nil
	})
	quiet := slog.New(slog.DiscardHandler)
	live, err := store.NewLive(ctx, db, quiet, quiet)
	if err != nil {
		t.Fatal(err)
	}
	db.OnCommit(func(ctx context.Context) { _ = live.Refresh(ctx) })
	var wg sync.WaitGroup
	wg.Go(func() { live.Run(ctx, time.Hour) })
	wg.Go(func() { db.Listen(ctx, live.Changed, quiet) })
	t.Cleanup(func() { cancel(); wg.Wait(); _ = db.Close() })
	i := &instance{db: db, live: live}
	api := mustNew(t, Options{
		Keys: keys, Config: live, Issuer: issuer, TokenTTL: 15 * time.Minute,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, RatePerMinute: 100000,
		Writer: db,
		Wrote: func(_ context.Context, client, resource, id, method string, fields []string) {
			i.mu.Lock()
			defer i.mu.Unlock()
			i.wrote = append(i.wrote, fmt.Sprintf("%s %s %s %s", client, method, resource, id))
		},
	})
	mux := http.NewServeMux()
	api.Register(mux)
	i.handler = httpx.Chain(mux, httpx.RealIP(nil))
	return i
}

func (i *instance) do(token, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "10.1.2.3:1"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.HasPrefix(body, "grant_type=") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	i.handler.ServeHTTP(w, req)
	return w
}

// within waits up to d for ok.
func within(d time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// The admin API on store.Postgres, two instances on one database: each write
// reads back at once on the instance that made it, and shows on the other in
// less than a second (Q99, Q101).
func TestAPIOnPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := newDatabase(t)
	keys := mustKeys(t, pkcs8(t, ecKey(t, elliptic.P256())), "")
	one, two := newInstance(t, dsn, keys), newInstance(t, dsn, keys)
	hash, err := domain.HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := one.db.CreateAPIClient(ctx, "test", store.APIClient{ID: "all", SecretHash: hash, Scopes: Scopes}); err != nil {
		t.Fatal(err)
	}
	if !within(time.Second, func() bool { _, ok := two.live.Snapshot().APIClient("all"); return ok }) {
		t.Fatal("the client is not on the second instance")
	}
	w := two.do("", http.MethodPost, "/admin/v1/token", "grant_type=client_credentials&client_id=all&client_secret=s3cret")
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	token := decodeInto[map[string]any](t, w)["access_token"].(string)

	expect := func(name string, w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("%s: %d, want %d: %s", name, w.Code, status, w.Body)
		}
	}
	expect("POST app", one.do(token, http.MethodPost, "/admin/v1/apps", appBody), http.StatusCreated)
	expect("GET app on its instance", one.do(token, http.MethodGet, "/admin/v1/apps/sql", ""), http.StatusOK)
	if !within(time.Second, func() bool { return two.do(token, http.MethodGet, "/admin/v1/apps/sql", "").Code == http.StatusOK }) {
		t.Error("the app is not on the second instance within a second")
	}
	expect("POST app twice", two.do(token, http.MethodPost, "/admin/v1/apps", appBody), http.StatusConflict)
	expect("POST flow", one.do(token, http.MethodPost, "/admin/v1/flows",
		`{"id": "f", "title": {"fr": "F"}, "description": {"fr": "D"}, "steps": [{"appId": "sql", "stepOrder": 0, "subjectCheck": "equal"}]}`), http.StatusCreated)
	expect("step to an unknown app", one.do(token, http.MethodPatch, "/admin/v1/flows/f", `{"steps": [{"appId": "nope", "stepOrder": 0}]}`), http.StatusUnprocessableEntity)
	w = one.do(token, http.MethodDelete, "/admin/v1/apps/sql", "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "flows f") {
		t.Errorf("DELETE referenced: %d %s", w.Code, w.Body)
	}
	// PUT of a tool written for Symfony: the step keeps its check (Q107).
	w = one.do(token, http.MethodPut, "/admin/v1/flows/f", `{"id": "f", "title": {"fr": "F2"}, "description": {"fr": "D"}, "enabled": true, "steps": [{"appId": "sql", "stepOrder": 0}]}`)
	if f := decodeInto[flowJSON](t, w); w.Code != http.StatusOK || f.Steps[0].SubjectCheck != "equal" {
		t.Errorf("PUT flow: %d %s", w.Code, w.Body)
	}
	if !within(time.Second, func() bool {
		f := two.live.Snapshot().Flows
		return len(f) == 1 && f[0].Title["fr"] == "F2"
	}) {
		t.Error("the flow replaced is not on the second instance")
	}

	// Settings: the rules of the registry, a configuration serve would refuse,
	// and the document read back.
	w = one.do(token, http.MethodPatch, "/admin/v1/settings", `{"supportedLocales": ["en"]}`)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"propertyPath":"defaultLocale"`) {
		t.Errorf("locales: %d %s", w.Code, w.Body)
	}
	w = one.do(token, http.MethodPatch, "/admin/v1/settings", `{"loginAcceptWebhookUrl": "http://hooks/login"}`)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"propertyPath":"loginAcceptWebhookUrl"`) {
		t.Errorf("webhook refused: %d %s", w.Code, w.Body)
	}
	w = one.do(token, http.MethodPatch, "/admin/v1/settings", `{"appAutoSelect": true, "sessionTtl": 1800, "loginAcceptWebhookUrl": "https://hooks/login"}`)
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, `"appAutoSelect":true`) || !strings.Contains(body, `"loginRememberFor":1800`) ||
		!strings.Contains(body, `"loginAcceptWebhookUrl":"https://hooks/login"`) {
		t.Errorf("settings: %d %s", w.Code, body)
	}
	w = one.do(token, http.MethodPatch, "/admin/v1/settings", `{"loginAcceptWebhookUrl": null, "loginRememberFor": null}`)
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, `"loginAcceptWebhookUrl":null`) || !strings.Contains(body, `"loginRememberFor":86400`) {
		t.Errorf("settings reset: %d %s", w.Code, body)
	}

	// A client created on one instance obtains a token on the other; deleted,
	// its token is refused there within a second.
	expect("POST client", one.do(token, http.MethodPost, "/admin/v1/oauth2-clients", `{"id": "ci", "secret": "ci-secret", "scopes": ["admin:read"]}`), http.StatusCreated)
	var ciToken string
	if !within(time.Second, func() bool {
		w := two.do("", http.MethodPost, "/admin/v1/token", "grant_type=client_credentials&client_id=ci&client_secret=ci-secret")
		if w.Code == http.StatusOK {
			ciToken = decodeInto[map[string]any](t, w)["access_token"].(string)
		}
		return w.Code == http.StatusOK
	}) {
		t.Fatal("the client created gets no token on the second instance")
	}
	expect("ci reads", two.do(ciToken, http.MethodGet, "/admin/v1/apps", ""), http.StatusOK)
	expect("ci writes", two.do(ciToken, http.MethodPost, "/admin/v1/apps", appBody), http.StatusForbidden)
	expect("DELETE client", one.do(token, http.MethodDelete, "/admin/v1/oauth2-clients/ci", ""), http.StatusNoContent)
	if !within(time.Second, func() bool {
		return two.do(ciToken, http.MethodGet, "/admin/v1/apps", "").Code == http.StatusUnauthorized
	}) {
		t.Error("the token of the client deleted is still taken by the second instance")
	}

	// The author of each row: the client of the API.
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for _, q := range []string{`SELECT updated_by FROM app WHERE id = 'sql'`, `SELECT updated_by FROM flow WHERE id = 'f'`, `SELECT updated_by FROM setting WHERE key = 'app_auto_select'`} {
		var by string
		if err := conn.QueryRow(q).Scan(&by); err != nil || by != "api_client:all" {
			t.Errorf("%s: %q, %v", q, by, err)
		}
	}
	one.mu.Lock()
	wrote := strings.Join(one.wrote, "\n")
	one.mu.Unlock()
	for _, want := range []string{"all POST apps sql", "all PUT flows f", "all PATCH settings ", "all DELETE oauth2-clients ci"} {
		if !strings.Contains(wrote, want) {
			t.Errorf("no %q in the audit:\n%s", want, wrote)
		}
	}
}
