package admin

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Q96: a read takes the scope of its resource or admin:read; a write, the
// scope of its resource only; admin:clients alone writes the clients.
func TestAllowed(t *testing.T) {
	resources := []Resource{Apps, Flows, Clients, Settings}
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, r := range resources {
		for _, m := range methods {
			read := m == http.MethodGet || m == http.MethodHead
			for _, granted := range [][]string{nil, {string(r)}, {ScopeRead}, Scopes, {"admin:config"}} {
				want := slices.Contains(granted, string(r)) || read && slices.Contains(granted, ScopeRead)
				if got := Allowed(granted, r, m); got != want {
					t.Errorf("%s %s with %q: %v, want %v", m, r, granted, got, want)
				}
			}
			// The scope of another resource never allows.
			for _, other := range resources {
				if other != r && Allowed([]string{string(other)}, r, m) {
					t.Errorf("%s %s allowed by %s", m, r, other)
				}
			}
		}
	}
	if got := Required(Clients, http.MethodPost); !slices.Equal(got, []string{ScopeClients}) {
		t.Errorf("Required = %q", got)
	}
}

func TestWarnings(t *testing.T) {
	got := Warnings([]store.APIClient{
		{ID: "ok", Scopes: []string{ScopeFlows, ScopeRead}},
		{ID: "symfony", Scopes: []string{"admin:config", ScopeApps, "admin:users"}},
		{ID: "none", Scopes: []string{}},
	})
	if len(got) != 1 || !strings.HasPrefix(got[0], "API client symfony: scopes admin:config, admin:users grant nothing") {
		t.Errorf("warnings = %q", got)
	}
}
