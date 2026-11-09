//go:build integration

package store

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// TestDoctrineURL opens the database by the DATABASE_URL of the Symfony dispatcher,
// Doctrine's parameters included, as config.Load reads it (P12a): Postgres refuses
// those parameters, which pgx sends it as runtime parameters, and accepts what is
// left of them.
func TestDoctrineURL(t *testing.T) {
	ctx := context.Background()
	u, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "postgresql" // Doctrine's, as in hydra-dev
	q := u.Query()
	q.Set("serverVersion", "17")
	q.Set("charset", "utf8")
	u.RawQuery = q.Encode()
	doctrine := u.String()

	if p, err := Open(ctx, doctrine); err == nil {
		_ = p.Close()
		t.Fatal("Postgres accepts Doctrine's parameters: nothing needs dropping them")
	}

	cfg, warnings, err := config.Load("", []string{
		"DATABASE_URL=" + doctrine,
		"DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test",
		"DISPATCHER_SERVER_TRUSTED_PROXIES=",
		"DISPATCHER_HYDRA_ADMIN_URL=https://hydra:4445",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=10.0.1.0/24",
		"DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32),
		"DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "store.dsn: charset, serverVersion dropped") {
		t.Errorf("warnings: %q", warnings)
	}
	p, err := Open(ctx, cfg.Store.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	if err := p.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}
