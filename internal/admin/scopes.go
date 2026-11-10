package admin

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The scopes of the admin API (Q96): one per resource, for its reads and its
// writes, and admin:read for every read.
const (
	ScopeApps     = "admin:apps"
	ScopeFlows    = "admin:flows"
	ScopeClients  = "admin:clients"
	ScopeSettings = "admin:settings"
	ScopeRead     = "admin:read"
)

// Scopes are those the API knows, in the order of the doc.
var Scopes = []string{ScopeApps, ScopeFlows, ScopeClients, ScopeSettings, ScopeRead}

// Resource is a resource of the admin API, by the scope of its writes.
type Resource string

const (
	Apps     Resource = ScopeApps
	Flows    Resource = ScopeFlows
	Clients  Resource = ScopeClients
	Settings Resource = ScopeSettings
)

// Required are the scopes that allow method on r, any one of them: the
// scope of the resource, and admin:read for a read.
func Required(r Resource, method string) []string {
	if method == http.MethodGet || method == http.MethodHead {
		return []string{string(r), ScopeRead}
	}
	return []string{string(r)}
}

// Allowed tells whether granted holds one of the scopes method on r requires.
func Allowed(granted []string, r Resource, method string) bool {
	return slices.ContainsFunc(Required(r, method), func(s string) bool { return slices.Contains(granted, s) })
}

// Warnings names the scopes of the API clients the API does not know, which
// grant nothing: admin:config and admin:users of Symfony, kept by a seed,
// translated only by the import of its database (Q96).
func Warnings(clients []store.APIClient) []string {
	var warnings []string
	for _, c := range clients {
		var unknown []string
		for _, s := range c.Scopes {
			if !slices.Contains(Scopes, s) {
				unknown = append(unknown, s)
			}
		}
		if len(unknown) > 0 {
			warnings = append(warnings, fmt.Sprintf("API client %s: scopes %s grant nothing: the admin API knows %s",
				c.ID, strings.Join(unknown, ", "), strings.Join(Scopes, ", ")))
		}
	}
	return warnings
}
