package adminui

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cfg "forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The tests of the revue R45.

// B1: no answer of Hydra in the log, whatever screen calls it: the screen of
// the scopes, which reads every client, as those of the clients (R43).
func TestHydraFailureLoggedEverywhere(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"FROM-HYDRA client_secret=XYZ"}`))
		}))
		c, err := hydra.New(cfg.Hydra{AdminURL: srv.URL, Timeout: cfg.Duration(time.Second), MaxInFlight: 4}, cfg.TLS{MinVersion: "1.2"})
		if err != nil {
			t.Fatal(err)
		}
		r := newRig(t, "http://dispatcher.test")
		withHydra(r) // its routes, then the Hydra that fails
		var log bytes.Buffer
		r.ui.o.HydraClients, r.ui.o.Logger = c, slog.New(slog.NewTextHandler(&log, nil))
		b := r.browser()
		b.login("victor", password, "")
		for _, path := range []string{"/admin/scopes", "/admin/hydra-clients", "/admin/hydra-clients/web"} {
			log.Reset()
			b.do(http.MethodGet, path, nil)
			if got := log.String(); !strings.Contains(got, "admin.hydra_failed") || !strings.Contains(got, "status=") ||
				strings.Contains(got, "FROM-HYDRA") || strings.Contains(got, "XYZ") || strings.Contains(got, "server_error") {
				t.Errorf("%d %s, log: %s", status, path, got)
			}
		}
		srv.Close()
	}
}

// B2: a save that changes nothing writes nothing, on every screen, a value
// stored with spaces at its ends or line ends of LF included, as the page
// shows it and the browser sends it back (a <textarea> in CRLF); a change
// beside them keeps them as stored.
func TestUntouchedKeptEverywhere(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	r.config.flows[0].Description["en"] = "line1\nline2"
	r.config.flows[0].Steps[0].SubjectCheck = "claim: mail "
	r.config.apps[0].LoginURL = "https://pwd.test/login "
	r.config.apps[0].ReceiveClaims = []string{" a b "}
	r.config.scopes = []store.Scope{{Name: "biz", Label: map[string]string{"fr": " Biz "}, Claims: []store.ScopeClaim{{Claim: " x ", Label: map[string]string{"fr": " X "}}}}}
	r.config.clients = []store.APIClient{{ID: "ci", Scopes: []string{"admin:read", "admin:apps"}}}
	h.putJSON(conforming("spaced", `{}`))
	h.clients["spaced"]["client_name"], h.clients["spaced"]["scope"] = rawOf(" Spaced "), rawOf(" openid  offline ")
	withIdP(r)
	r.config.oidc.ClientID = " dispatcher-admin "
	b := r.browser()
	b.login("alice", password, "")

	flow := func(title string) url.Values {
		return url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/flows/simple")}, "enabled": {"1"}, "acr": {""},
			"locale": {"fr", "en"}, "title": {"", title}, "description": {"", "line1\r\nline2"}, "icon_url": {"", ""},
			"step_app": {"pwd"}, "step_position": {"1"}, "step_check": {"claim"}, "step_claim": {" mail "}}
	}
	app := func(method string) url.Values {
		return url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/apps/pwd")}, "method": {method}, "login_url": {"https://pwd.test/login "},
			"consent_url": {"https://pwd.test/consent"}, "logout_url": {""}, "auth_mode": {"network"}, "allowed_sources": {"10.0.6.21/32"},
			"receive_claims": {" a b "}}
	}
	scope := func(en string) url.Values {
		return scopeValues(b, b.version("/admin/scopes/biz"), map[string]string{"label.fr": " Biz ", "label.en": en, "claim_label.0.fr": " X "}, " x ")
	}
	client := url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/clients/ci")}, "scope": {"admin:apps", "admin:read"}}
	for _, c := range []struct {
		path string
		form url.Values
	}{
		{"/admin/flows/simple", flow("Simple")},
		{"/admin/apps/pwd", app("pwd")},
		{"/admin/scopes/biz", scope("")},
		{"/admin/hydra-clients/spaced", hydraValues(b, "spaced")},
		{"/admin/sso", ssoValues(b)},
		{"/admin/clients/ci", client},
	} {
		if w := b.do(http.MethodPost, c.path, c.form); w.Code != http.StatusSeeOther {
			t.Errorf("%s unchanged: %d\n%s", c.path, w.Code, w.Body)
		}
	}
	if len(r.config.by) != 0 || len(r.wrote()) != 0 || len(h.patches) != 0 {
		t.Fatalf("unchanged saves wrote: by %q, audit %q, patches %v", r.config.by, r.wrote(), h.patches)
	}

	// A change beside them: the untouched values stay as stored.
	for _, c := range []struct {
		path string
		form url.Values
	}{
		{"/admin/flows/simple", flow("Plain")},
		{"/admin/apps/pwd", app("otp")},
		{"/admin/scopes/biz", scope("Business")},
	} {
		if w := b.do(http.MethodPost, c.path, c.form); w.Code != http.StatusSeeOther {
			t.Errorf("%s changed: %d\n%s", c.path, w.Code, w.Body)
		}
	}
	hv := hydraValues(b, "spaced")
	hv.Set("logo_uri", "https://n.test/logo.png")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/spaced", hv); w.Code != http.StatusSeeOther {
		t.Errorf("hydra changed: %d\n%s", w.Code, w.Body)
	}
	if f, _ := r.config.flow("simple"); f.Description["en"] != "line1\nline2" || f.Steps[0].SubjectCheck != "claim: mail " || f.Title["en"] != "Plain" {
		t.Errorf("flow %+v", f)
	}
	if a, _ := r.config.Snapshot().App("pwd"); a.LoginURL != "https://pwd.test/login " || len(a.ReceiveClaims) != 1 || a.ReceiveClaims[0] != " a b " || a.Method != "otp" {
		t.Errorf("app %+v", a)
	}
	if sc, _ := r.config.Snapshot().Scope("biz"); sc.Label["fr"] != " Biz " || sc.Label["en"] != "Business" || sc.Claims[0].Claim != " x " || sc.Claims[0].Label["fr"] != " X " {
		t.Errorf("scope %+v", sc)
	}
	if got := h.member("spaced", "client_name") + h.member("spaced", "scope"); got != `" Spaced "" openid  offline "` {
		t.Errorf("hydra client: %s, patches %v", got, h.patches)
	}
	// A text typed anew in a <textarea>: its line ends as LF.
	changed := flow("Plain")
	changed["description"] = []string{"", "new1\r\nnew2"}
	b.do(http.MethodPost, "/admin/flows/simple", changed)
	if f, _ := r.config.flow("simple"); f.Description["en"] != "new1\nnew2" {
		t.Errorf("a description typed: %q", f.Description["en"])
	}
}
