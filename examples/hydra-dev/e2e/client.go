package main

import (
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
}

// findClient returns the id Hydra gave the client named name: hydra-dev
// imports it at each start of Hydra, under a new id.
func findClient(ctx context.Context, c *http.Client, admin *url.URL, name string) (string, error) {
	var clients []struct {
		ID   string `json:"client_id"`
		Name string `json:"client_name"`
	}
	if err := getJSON(ctx, c, admin.JoinPath("/admin/clients").String(), &clients); err != nil {
		return "", fmt.Errorf("clients of Hydra: %w", err)
	}
	for _, cl := range clients {
		if cl.Name == name {
			return cl.ID, nil
		}
	}
	return "", fmt.Errorf("no client named %q in Hydra: give its id by -client", name)
}

// authURL starts an authorization: openid profile email, as hydra-dev's test
// client asks, and prompt when not empty.
func (c *client) authURL(prompt string) string {
	c.state, c.nonce = random(), random()
	q := url.Values{
		"client_id":     {c.id},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
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
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(data, &tokens); err != nil || tokens.IDToken == "" {
		return nil, fmt.Errorf("token endpoint: no id_token in %s", data)
	}
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

// identity is what the final id_token must say.
type identity struct {
	Sub, Email string
	AMR        []string
}

func (want identity) check(claims map[string]any) error {
	var problems []string
	if claims["sub"] != want.Sub {
		problems = append(problems, fmt.Sprintf("sub %v, want %s", claims["sub"], want.Sub))
	}
	if want.Email != "" && claims["email"] != want.Email {
		problems = append(problems, fmt.Sprintf("email %v, want %s", claims["email"], want.Email))
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
