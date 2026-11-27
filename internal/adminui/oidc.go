package adminui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The login to the admin by the identity provider of the block admin_oidc
// (P22): the code flow with PKCE S256, a state and a nonce of 128 bits; the ID
// token checked (issuer, audience, expiry, signature by an asymmetric
// algorithm, nonce), its sub required, its acr among admin_oidc.required_acr
// when there are some. An account is found by its sub alone, never by its
// name; one no account has is refused, or created in the role viewer with
// admin_oidc.auto_create (Q126). A session opened so re-authenticates at the
// provider, which must authenticate anew (prompt=login, max_age=0, auth_time
// within the window).

const (
	oidcCookie = "dispatcher_admin_oidc"
	// oidcTTL bounds the time at the provider, from the login page to the
	// callback.
	oidcTTL = 10 * time.Minute
	// oidcWait bounds a call to the provider: the discovery, the exchange
	// of the code, the keys.
	oidcWait = 10 * time.Second
	// providerRetry is how long a provider that could not be discovered is
	// not tried again.
	providerRetry = time.Minute
	// MaxProviderAnswer bounds an answer of the provider, its discovery,
	// its keys, its tokens: one of hundreds of MB, hostile or intercepted,
	// would hold the memory of the dispatcher (revue R42).
	MaxProviderAnswer = 1 << 20
)

// algorithms are those an ID token may be signed by: asymmetric, never none
// nor a key shared with the client.
var algorithms = []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA}

// oidcRequest is what the callback checks, sealed in a cookie between the
// login page and the callback.
type oidcRequest struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	// Reauth names the account a re-authentication confirms; "" for a login.
	Reauth  string `json:"r,omitempty"`
	Expires int64  `json:"e"`
}

// provider is the identity provider of the block it was built from.
type provider struct {
	block    store.AdminOIDC
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	err      error
	failed   time.Time
}

// providers keeps the provider of the block of the moment: discovered once
// per block, not at each login; tried again a minute after a failure.
type providers struct {
	mu   sync.Mutex
	last *provider
}

// provider gives the provider of block: its endpoints declared, or
// discovered at its issuer, which must name itself so.
func (ui *UI) provider(ctx context.Context, block store.AdminOIDC) (*provider, error) {
	ui.idp.mu.Lock()
	defer ui.idp.mu.Unlock()
	if p := ui.idp.last; p != nil && reflect.DeepEqual(p.block, block) {
		if p.err == nil {
			return p, nil
		}
		if ui.o.Now().Sub(p.failed) < providerRetry {
			return nil, p.err
		}
	}
	// The discovery is the provider's, not the request's: a browser that
	// leaves does not make it a failure kept a minute (revue R42).
	ctx, cancel := context.WithTimeout(oidc.ClientContext(context.WithoutCancel(ctx), ui.o.HTTPClient), oidcWait)
	defer cancel()
	var op *oidc.Provider
	var err error
	if block.AuthorizationEndpoint != "" {
		op = (&oidc.ProviderConfig{IssuerURL: block.Issuer, AuthURL: block.AuthorizationEndpoint, TokenURL: block.TokenEndpoint,
			JWKSURL: block.JWKSURI, Algorithms: algorithms}).NewProvider(ctx)
	} else {
		op, err = oidc.NewProvider(ctx, block.Issuer)
	}
	p := &provider{block: block}
	if err != nil {
		p.err, p.failed = err, ui.o.Now()
		ui.idp.last = p
		return nil, err
	}
	p.oauth = oauth2.Config{ClientID: block.ClientID, ClientSecret: block.ClientSecret, Endpoint: op.Endpoint(),
		RedirectURL: ui.origin + ui.base + "/oidc/callback", Scopes: block.Scopes}
	p.verifier = op.VerifierContext(oidc.ClientContext(context.Background(), ui.o.HTTPClient),
		&oidc.Config{ClientID: block.ClientID, SupportedSigningAlgs: algorithms, Now: ui.o.Now})
	ui.idp.last = p
	return p, nil
}

// block is the block admin_oidc of the moment; disabled without a
// configuration.
func (ui *UI) block() store.AdminOIDC {
	if ui.o.Config == nil {
		return store.AdminOIDC{}
	}
	return ui.o.Config.Snapshot().Settings.AdminOIDC
}

func (ui *UI) registerOIDC() {
	ui.mux.HandleFunc("GET /admin/oidc/login", ui.oidcLogin)
	ui.mux.HandleFunc("GET /admin/oidc/callback", ui.oidcCallback)
}

// oidcLogin sends the browser to the provider: for a login, or with
// ?reauth=1 for the re-authentication of the session's account.
func (ui *UI) oidcLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	block := ui.block()
	if !block.Enabled {
		ui.status(w, r, http.StatusNotFound, "Not found", "The login by the identity provider is off.", nil)
		return
	}
	req := oidcRequest{Next: ui.next(r.URL.Query().Get("next")), Expires: ui.o.Now().Add(oidcTTL).Unix()}
	reauth := r.URL.Query().Get("reauth") != ""
	if reauth {
		s, err := ui.current(r)
		switch {
		case err != nil && err != errNoSession:
			ui.unreadable(w, r, nil, err)
			return
		case err != nil:
			http.Redirect(w, r, ui.base+"/login?next="+url.QueryEscape(ui.root()+r.URL.RequestURI()), http.StatusSeeOther)
			return
		case s.account.OIDCSub == "":
			ui.status(w, r, http.StatusForbidden, "Confirm it is you", "Your account has no identity at the provider: confirm it by your password.", s)
			return
		}
		req.Reauth = s.account.Username
	}
	p, err := ui.provider(ctx, block)
	if err != nil {
		ui.unavailable(w, r, err)
		return
	}
	req.State, req.Nonce, req.Verifier = randomToken(), randomToken(), oauth2.GenerateVerifier()
	data, _ := json.Marshal(req) // strings and a number
	ui.setCookie(w, oidcCookie, ui.o.Keys.Seal(oidcCookie, sealVersion, data), oidcTTL)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(req.Verifier), oidc.Nonce(req.Nonce)}
	if len(block.RequiredACR) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", strings.Join(block.RequiredACR, " ")))
	}
	if reauth {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	http.Redirect(w, r, p.oauth.AuthCodeURL(req.State, opts...), http.StatusSeeOther)
}

// unavailable answers a provider that cannot be reached: its cause in the
// log, never on the page.
func (ui *UI) unavailable(w http.ResponseWriter, r *http.Request, err error) {
	if ui.o.Logger != nil {
		ui.o.Logger.ErrorContext(r.Context(), "admin.oidc_unavailable", "cause", httpx.BoundedCause(err.Error()))
	}
	ui.status(w, r, http.StatusServiceUnavailable, "Unavailable", "The identity provider cannot be reached now: try again in a moment.", nil)
}

// oidcRequestOf opens the request the cookie seals, still valid.
func (ui *UI) oidcRequestOf(r *http.Request) (oidcRequest, bool) {
	var req oidcRequest
	c, err := r.Cookie(ui.prefix + oidcCookie)
	if err != nil {
		return req, false
	}
	plain, ok := ui.o.Keys.Open(oidcCookie, sealVersion, c.Value)
	if !ok || json.Unmarshal(plain, &req) != nil || req.State == "" || ui.o.Now().Unix() > req.Expires {
		return req, false
	}
	return req, true
}

// idClaims are the claims of an ID token the dispatcher reads.
type idClaims struct {
	ACR      string `json:"acr"`
	AuthTime int64  `json:"auth_time"`
}

// oidcCallback takes the browser back from the provider: the state first,
// then the limit of the address, the code exchanged, the ID token checked;
// the account of its sub logged in, or confirmed.
func (ui *UI) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	req, ok := ui.oidcRequestOf(r)
	ui.setCookie(w, oidcCookie, "", 0) // once
	method := "oidc"
	if !ok || !sameToken(q.Get("state"), req.State) {
		ui.audit(ctx, unknown, method, "refused", "state")
		ui.status(w, r, http.StatusBadRequest, "Log in again", "The login came back from the identity provider unexpected, or too late: start it again.", nil)
		return
	}
	if !ui.allowed(w, r) {
		return
	}
	refuse := func(user, reason, message string, cause error) {
		if cause != nil && ui.o.Logger != nil {
			ui.o.Logger.WarnContext(ctx, "admin.oidc_refused", "reason", reason, "cause", httpx.BoundedCause(cause.Error()))
		}
		ui.audit(ctx, user, method, "refused", reason)
		ui.status(w, r, http.StatusForbidden, "Not logged in", message, nil)
	}
	if q.Get("error") != "" {
		refuse(unknown, "provider_error", "The identity provider did not log you in.", nil)
		return
	}
	block := ui.block()
	if !block.Enabled {
		ui.status(w, r, http.StatusNotFound, "Not found", "The login by the identity provider is off.", nil)
		return
	}
	p, err := ui.provider(ctx, block)
	if err != nil {
		ui.unavailable(w, r, err)
		return
	}
	call, cancel := context.WithTimeout(context.WithValue(ctx, oauth2.HTTPClient, ui.o.HTTPClient), oidcWait)
	defer cancel()
	tok, err := p.oauth.Exchange(call, q.Get("code"), oauth2.VerifierOption(req.Verifier))
	if err != nil {
		refuse(unknown, "token", "The identity provider did not confirm the login: start it again.", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		refuse(unknown, "token", "The identity provider gave no ID token.", nil)
		return
	}
	idt, err := p.verifier.Verify(call, raw)
	if err != nil {
		refuse(unknown, "id_token", "The identity provider gave an ID token that does not check.", err)
		return
	}
	var claims idClaims
	if err := idt.Claims(&claims); err != nil || !sameToken(idt.Nonce, req.Nonce) || idt.Subject == "" {
		refuse(unknown, "id_token", "The identity provider gave an ID token that does not check.", err)
		return
	}
	a, found, err := ui.accountOfSubject(ctx, idt.Subject)
	if err != nil {
		ui.unreadable(w, r, nil, err)
		return
	}
	user := unknown
	if found {
		user = a.Username
	}
	if len(block.RequiredACR) > 0 && !slices.Contains(block.RequiredACR, claims.ACR) {
		refuse(user, "acr", "The identity provider did not authenticate you as strongly as the admin asks.", nil)
		return
	}
	if req.Reauth != "" {
		ui.oidcReauth(w, r, req, a, found, claims, refuse)
		return
	}
	if !found {
		if !block.AutoCreate {
			refuse(unknown, "unknown_subject", "No account of the admin has this identity: an admin creates it, with the OIDC subject "+idt.Subject+".", nil)
			return
		}
		if a, err = ui.createFromProvider(ctx, idt, block.UsernameClaim); err != nil {
			refuse(unknown, "unknown_subject", "No account could be created for this identity: an admin creates it, with the OIDC subject "+idt.Subject+".", err)
			return
		}
	}
	sess := ui.sessionOf(ctx, a, method)
	if !ui.authenticatedAnew(claims.AuthTime) {
		// The provider may log in by a session of its own, without an
		// authentication of now: this session is not fresh, and its first
		// sensitive action asks the provider again (revue R42).
		sess.Auth = 0
	}
	ui.setSession(w, sess)
	ui.audit(ctx, a.Username, method, "granted", "")
	http.Redirect(w, r, req.Next, http.StatusSeeOther)
}

// oidcReauth confirms the session's account: the same account, the same
// sub, authenticated anew at the provider within the window.
func (ui *UI) oidcReauth(w http.ResponseWriter, r *http.Request, req oidcRequest, a store.AdminUser, found bool, claims idClaims, refuse func(user, reason, message string, cause error)) {
	s, err := ui.current(r)
	switch {
	case err != nil && err != errNoSession:
		ui.unreadable(w, r, nil, err)
		return
	case err != nil || !found || s.account.Username != req.Reauth || a.Username != req.Reauth:
		refuse(req.Reauth, "reauth_subject", "The identity provider confirmed another identity than your account's.", nil)
		return
	}
	if !ui.authenticatedAnew(claims.AuthTime) {
		refuse(a.Username, "auth_time", "The identity provider did not authenticate you anew: confirm it again.", nil)
		return
	}
	s.session.Auth = ui.o.Now().UnixMicro()
	ui.setSession(w, s.session)
	ui.audit(r.Context(), a.Username, "oidc", "granted", "reauth")
	http.Redirect(w, r, req.Next, http.StatusSeeOther)
}

// authSkew is how far ahead of the dispatcher's clock the provider's may be,
// for an auth_time.
const authSkew = time.Minute

// authenticatedAnew tells whether the provider authenticated the user within
// admin.session.reauth_window, by the auth_time of its ID token: absent, or
// ahead of the clocks' skew, it did not (revue R42).
func (ui *UI) authenticatedAnew(authTime int64) bool {
	if authTime <= 0 {
		return false
	}
	at, now := time.Unix(authTime, 0), ui.o.Now()
	return !at.After(now.Add(authSkew)) && now.Sub(at) <= ui.o.ReauthWindow
}

// accountOfSubject reads the account of sub, bounded as a read of the
// accounts.
func (ui *UI) accountOfSubject(ctx context.Context, sub string) (store.AdminUser, bool, error) {
	ctx, cancel := ui.bounded(ctx)
	defer cancel()
	return ui.o.Accounts.AdminBySubject(ctx, sub)
}

// createFromProvider creates the account of a subject no account has, in the
// role viewer, never admin (Q126): named by the claim usernameClaim, then
// email, then sub, the first a name may be; a name taken gets the suffix _
// and the first 8 characters of sub, as Symfony did.
func (ui *UI) createFromProvider(ctx context.Context, idt *oidc.IDToken, usernameClaim string) (store.AdminUser, error) {
	var all map[string]any
	if err := idt.Claims(&all); err != nil {
		return store.AdminUser{}, err
	}
	name := ""
	for _, c := range []any{all[usernameClaim], all["email"], idt.Subject} {
		if s, ok := c.(string); ok && domain.Collect(func(fail domain.Fail) { domain.CheckUsername(fail, s) }) == nil {
			name = s
			break
		}
	}
	if name == "" {
		return store.AdminUser{}, fmt.Errorf("no claim gives a name an account may have")
	}
	suffix := idt.Subject
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	ctx, cancel := ui.bounded(ctx)
	defer cancel()
	var err error
	for _, n := range []string{name, name + "_" + suffix} {
		u := store.AdminUser{Username: n, OIDCSub: idt.Subject, Role: domain.RoleViewer}
		if err = ui.o.Accounts.CreateAdmin(ctx, u); err == nil {
			if ui.o.Wrote != nil {
				ui.o.Wrote(ctx, n, "admin-users", n, "create", []string{"role", "oidc_sub"})
			}
			created, _, err := ui.o.Accounts.Admin(ctx, n)
			if err != nil {
				return store.AdminUser{}, err
			}
			return created, nil
		}
	}
	return store.AdminUser{}, err
}

// sessionOf opens a session of the account a, after the end of its sessions
// whatever the clocks: an account just created, or whose sessions just
// ended, has its date of now.
func (ui *UI) sessionOf(_ context.Context, a store.AdminUser, method string) session {
	s := ui.newSession(a.Username, method)
	if issued := time.UnixMicro(s.Issued); !issued.After(a.SessionsValidAfter) {
		at := a.SessionsValidAfter.Add(time.Microsecond).UnixMicro()
		s.Issued, s.Seen, s.Auth = at, at, at
	}
	return s
}
