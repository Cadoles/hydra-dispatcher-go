package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// client is the OAuth2 client of the authorizations: hydra-dev's OIDC test
// client, whose credentials the e2e borrows to redeem the codes itself.
type client struct {
	public, admin *url.URL
	id, secret    string
	redirect      string
	http          *http.Client
	state, nonce  string // of the last authorization request
	// idToken is the one redeemed last, what a client gives back as
	// id_token_hint; postLogout the client's post_logout_redirect_uri.
	idToken    string
	postLogout string
	// accessToken is the one redeemed last, which accessClaims introspects.
	accessToken string
	// scope is that of the next authorization requests, "openid profile
	// email" when empty.
	scope string
}

// findClient returns the id of the one client named name. hydra-dev imports
// it at each start of Hydra, deleting the former first: several of that name
// are copies left by an import whose delete missed (a JSON without
// client_id), which the e2e does not choose between.
func findClient(ctx context.Context, c *http.Client, admin *url.URL, name string) (string, error) {
	var clients []struct {
		ID   string `json:"client_id"`
		Name string `json:"client_name"`
	}
	if err := getJSON(ctx, c, admin.JoinPath("/admin/clients").String(), &clients); err != nil {
		return "", fmt.Errorf("clients of Hydra: %w", err)
	}
	var ids []string
	for _, cl := range clients {
		if cl.Name == name {
			ids = append(ids, cl.ID)
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no client named %q in Hydra: give its id by -client", name)
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("%d clients named %q in Hydra (%s): give the id by -client, or make down in hydra-dev", len(ids), name, strings.Join(ids, ", "))
}

// authURL starts an authorization: openid profile email, as hydra-dev's test
// client asks, and prompt when not empty.
func (c *client) authURL(prompt string) string {
	c.state, c.nonce = random(), random()
	q := url.Values{
		"client_id":     {c.id},
		"response_type": {"code"},
		"scope":         {cmp.Or(c.scope, "openid profile email")},
		"redirect_uri":  {c.redirect},
		"state":         {c.state},
		"nonce":         {c.nonce},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	u := c.public.JoinPath("/oauth2/auth")
	u.RawQuery = q.Encode()
	return u.String()
}

// callbackError returns the error the authorization came back with, empty
// when it came back with a code.
func (c *client) callbackError(cb *url.URL) (string, error) {
	q := cb.Query()
	if q.Get("state") != c.state {
		return "", fmt.Errorf("callback state %q, want %q", q.Get("state"), c.state)
	}
	if e := q.Get("error"); e != "" {
		return e, nil
	}
	if q.Get("code") == "" {
		return "", fmt.Errorf("callback without code nor error: %s", cb.Redacted())
	}
	return "", nil
}

// redeem exchanges the code of the callback and returns the claims of the
// id_token, after checking its issuer, audience and nonce. The signature is
// Hydra's business, not the dispatcher's: it is not checked.
func (c *client) redeem(ctx context.Context, cb *url.URL) (map[string]any, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {cb.Query().Get("code")},
		"redirect_uri": {c.redirect},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.public.JoinPath("/oauth2/token").String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.id), url.QueryEscape(c.secret))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint: %d %s", resp.StatusCode, data)
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &tokens); err != nil || tokens.IDToken == "" {
		return nil, fmt.Errorf("token endpoint: no id_token in %s", data)
	}
	c.idToken, c.accessToken = tokens.IDToken, tokens.AccessToken
	parts := strings.Split(tokens.IDToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token is not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("id_token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("id_token payload: %w", err)
	}
	switch aud, _ := claims["aud"].([]any); {
	case strings.TrimSuffix(fmt.Sprint(claims["iss"]), "/") != strings.TrimSuffix(c.public.String(), "/"):
		return nil, fmt.Errorf("id_token iss %v, want %s", claims["iss"], c.public)
	case !slices.Contains(aud, any(c.id)):
		return nil, fmt.Errorf("id_token aud %v, without %s", claims["aud"], c.id)
	case claims["nonce"] != c.nonce:
		return nil, fmt.Errorf("id_token nonce %v, want %s", claims["nonce"], c.nonce)
	}
	return claims, nil
}

// loginSkip reads, on Hydra's admin API, whether Hydra asked the dispatcher
// to skip the login of challenge: the oracle of the second login.
func (c *client) loginSkip(ctx context.Context, challenge string) (bool, error) {
	u := c.admin.JoinPath("/admin/oauth2/auth/requests/login")
	u.RawQuery = url.Values{"login_challenge": {challenge}}.Encode()
	var lr struct {
		Skip bool `json:"skip"`
	}
	if err := getJSON(ctx, c.http, u.String(), &lr); err != nil {
		return false, fmt.Errorf("login request on Hydra: %w", err)
	}
	return lr.Skip, nil
}

// logoutURL is Hydra's logout, as a client asks for it with hint: back to the
// client with state (HLO-7); without hint, as a user does.
func (c *client) logoutURL(hint, state string) string {
	u := c.public.JoinPath("/oauth2/sessions/logout")
	if hint != "" {
		u.RawQuery = url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {c.postLogout}, "state": {state}}.Encode()
	}
	return u.String()
}

// hydraVersion reads the release Hydra reports: some ends differ (HLO-15).
func (c *client) hydraVersion(ctx context.Context) (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	if err := getJSON(ctx, c.http, c.admin.JoinPath("/version").String(), &v); err != nil {
		return "", fmt.Errorf("version of Hydra: %w", err)
	}
	return v.Version, nil
}

// sessionAlive tells whether a logout request comes for hint from a browser
// without a cookie: without one, the session is gone from Hydra's base (HLO-13).
func (c *client) sessionAlive(ctx context.Context, hint string) (bool, error) {
	u := c.public.JoinPath("/oauth2/sessions/logout")
	u.RawQuery = url.Values{"id_token_hint": {hint}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	noFollow := &http.Client{Timeout: c.http.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	loc, err := resp.Location()
	if err != nil {
		return false, fmt.Errorf("logout of a session: %d, no redirect", resp.StatusCode)
	}
	return loc.Query().Has("logout_challenge"), nil
}

// backChannelClient registers a copy of the client that hears of a logout at
// listener, and returns its id: hydra-dev's has no back-channel. Removed at the
// end of the run, as a client of a scenario.
func (c *client) backChannelClient(ctx context.Context, listener string) (string, func(), error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                "e2e back-channel",
		"client_secret":              c.secret,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      "openid email profile offline_access",
		"redirect_uris":              []string{c.redirect},
		"post_logout_redirect_uris":  []string{c.postLogout},
		"token_endpoint_auth_method": "client_secret_basic",
		"backchannel_logout_uri":     listener,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.admin.JoinPath("/admin/clients").String(), strings.NewReader(string(body)))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var created struct {
		ID string `json:"client_id"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(data, &created) != nil || created.ID == "" {
		return "", nil, fmt.Errorf("client with a back-channel: %d %s", resp.StatusCode, data)
	}
	remove := func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.admin.JoinPath("/admin/clients", created.ID).String(), nil)
		if err == nil {
			if resp, err := c.http.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
	return created.ID, remove, nil
}

// identity is what the final id_token must say.
type identity struct {
	Sub, Email string
	// ACR is the flow's: without one in the seed, min(2, steps) (FIN-1).
	ACR string
	AMR []string
}

func (want identity) check(claims map[string]any) error {
	var problems []string
	if claims["sub"] != want.Sub {
		problems = append(problems, fmt.Sprintf("sub %v, want %s", claims["sub"], want.Sub))
	}
	if want.Email != "" && claims["email"] != want.Email {
		problems = append(problems, fmt.Sprintf("email %v, want %s", claims["email"], want.Email))
	}
	if want.ACR != "" && claims["acr"] != want.ACR {
		problems = append(problems, fmt.Sprintf("acr %v, want %s", claims["acr"], want.ACR))
	}
	if want.AMR != nil {
		var amr []string
		raw, _ := claims["amr"].([]any)
		for _, m := range raw {
			amr = append(amr, fmt.Sprint(m))
		}
		if !slices.Equal(amr, want.AMR) {
			problems = append(problems, fmt.Sprintf("amr %v, want %v", claims["amr"], want.AMR))
		}
	}
	if problems != nil {
		return fmt.Errorf("id_token: %s", strings.Join(problems, "; "))
	}
	return nil
}

// mailbox reads fake-smtp, where hydra-passwordless sends its codes.
type mailbox struct {
	base *url.URL
	http *http.Client
}

type email struct {
	ID   int       `json:"ID"`
	To   []address `json:"To"`
	Text string    `json:"Text"`
}

type address struct {
	Address string `json:"Address"`
}

func (m mailbox) emails(ctx context.Context) ([]email, error) {
	var page struct {
		Data struct {
			Emails []email `json:"Emails"`
		} `json:"Data"`
	}
	if err := getJSON(ctx, m.http, m.base.JoinPath("/api/v1/emails").String(), &page); err != nil {
		return nil, fmt.Errorf("fake-smtp: %w", err)
	}
	return page.Data.Emails, nil
}

// last returns the id of the newest email, 0 without one.
func (m mailbox) last(ctx context.Context) (int, error) {
	emails, err := m.emails(ctx)
	if err != nil {
		return 0, err
	}
	last := 0
	for _, e := range emails {
		last = max(last, e.ID)
	}
	return last, nil
}

// otp is the code of hydra-passwordless's email: "Code de vérification :
// WX5SVQ" in French.
var otp = regexp.MustCompile(`(?i)code[^:\n]*:\s*([A-Z0-9]{4,})`)

// code waits for an email to to, newer than after, and returns its code:
// hydra-passwordless sends it from a queue.
func (m mailbox) code(ctx context.Context, to string, after int) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		emails, err := m.emails(ctx)
		if err != nil {
			return "", err
		}
		newest := email{}
		for _, e := range emails {
			if e.ID > after && e.ID > newest.ID && slices.ContainsFunc(e.To, func(a address) bool {
				return strings.EqualFold(a.Address, to)
			}) {
				newest = e
			}
		}
		if newest.ID != 0 {
			if m := otp.FindStringSubmatch(newest.Text); m != nil {
				return m[1], nil
			}
			return "", fmt.Errorf("no code in email %d to %s", newest.ID, to)
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no email to %s in fake-smtp after 15 s", to)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func getJSON(ctx context.Context, c *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %d %s", u, resp.StatusCode, data)
	}
	return json.Unmarshal(data, v)
}

func random() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// idTokenClaims reads the claims of an id_token, its signature not checked: the client
// got it from the token endpoint.
func idTokenClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("an id_token of %d parts", len(parts))
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(data, &claims)
}

// accessClaims are the claims of the access token redeemed last, as Hydra's
// admin introspects it: its ext, what the consent's session gave it.
func (c *client) accessClaims(ctx context.Context) (map[string]any, error) {
	if c.accessToken == "" {
		return nil, errors.New("no access token redeemed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.admin.JoinPath("/admin/oauth2/introspect").String(),
		strings.NewReader(url.Values{"token": {c.accessToken}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		Active bool           `json:"active"`
		Ext    map[string]any `json:"ext"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r) != nil || !r.Active {
		return nil, fmt.Errorf("introspection of the access token: %d, active %v", resp.StatusCode, r.Active)
	}
	if r.Ext == nil {
		r.Ext = map[string]any{}
	}
	return r.Ext, nil
}
