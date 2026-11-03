// Command scenarios plays protocol scenarios against the dispatcher of
// hydra-dev, for the recorder of make capture to record. It is the browser,
// through Hydra and the dispatcher's pages, and the login apps, calling the
// emulated API directly: a scenario can then stop where a real app would not
// let it, on a reject, a second accept or an unknown challenge.
//
// After each scenario, the exchanges the recorder wrote to -capture move to
// -into/<NN>-<scenario>, NN counting from -first. With no scenario named, all
// of them run, in order. Start from a new stack (make down): Hydra remembers
// the consent back-after-the-end gives, and a second run would skip it in
// accept-twice, back-after-final-accept and back-after-the-end.
//
//	go run ./tools/scenarios -client <client_id> -first 16 \
//	  -capture testdata/capture -into testdata/protocol/symfony-hydra-2.1
//
// The client id is the one Hydra gave the OIDC test client:
//
//	docker exec hydra-dev-hydra-1 hydra list clients --endpoint http://127.0.0.1:4445 --format json
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/tools/capture"
)

// Positions of the flows on the choice page, sorted by id.
const (
	flowSQL    = "1"
	flowSQL2FA = "2"
)

// Bodies the login apps of hydra-dev send: recorded from hydra-sql-go and
// hydra-passwordless in testdata/protocol/symfony-hydra-2.1/14-sql-2fa-consent-skipped,
// or built as hydra-sql-go builds its deny button's. tfaConsentAccept waits
// for sql-2fa completed through the consent screen (the README's "Not
// captured yet").
const (
	sqlLoginAccept   = `{"amr":["pwd"],"context":{"email":"test2@test.com","firstname":"Isabelle","lastname":"Durand"},"remember":true,"subject":"test2@test.com"}`
	sqlConsentAccept = `{"grant_scope":["openid","profile","email"],"remember":true,"session":{"id_token":{"email":"test2@test.com","firstname":"Isabelle","lastname":"Durand"}}}`
	tfaLoginAccept   = `{"subject":"test2@test.com","remember":false,"remember_for":2592000,"acr":"","context":{"email":"test2@test.com"}}`
	tfaConsentAccept = `{"grant_scope":["email","openid","profile","email"],"grant_access_token_audience":[],"remember":false,"remember_for":0,"session":{"access_token":null,"id_token":{"email":null,"email_verified":true}}}`
	consentDenied    = `{"error":"access_denied","error_description":"The user denied the request"}`
	loginDenied      = `{"error":"access_denied","error_description":"The resource owner denied the request"}`
)

var (
	loginToken   = regexp.MustCompile(`name="login\[_token\]"[^>]*value="([^"]*)"`)
	consentToken = regexp.MustCompile(`name="form\[_token\]"[^>]*value="([^"]*)"`)
)

type driver struct {
	public, dispatcher *url.URL
	client, redirect   string
	// prefix of the emulated API: "" for the v1 paths of Symfony, "/admin".
	prefix  string
	browser *http.Client
	app     *http.Client
	// lastLogin is Hydra's login challenge of the current flow, read from
	// Hydra's redirect to the dispatcher: the apps only see step challenges.
	lastLogin string
}

// stop is where a walk through the dispatcher and Hydra ends: a page, or a
// redirect to a login app or to the client.
type stop struct {
	url    *url.URL
	status int
	body   []byte
}

func (s stop) param(name string) (string, error) {
	if v := s.url.Query().Get(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("stopped at %s (status %d), without %s", s.url.Redacted(), s.status, name)
}

var scenarios = []struct {
	name string
	run  func(*driver) error
}{
	{"consent-reject-first-step", (*driver).consentRejectFirstStep},
	{"consent-reject-second-step", (*driver).consentRejectSecondStep},
	{"login-reject-first-step", (*driver).loginRejectFirstStep},
	{"login-reject-second-step", (*driver).loginRejectSecondStep},
	{"accept-twice", (*driver).acceptTwice},
	{"unknown-step-challenge", (*driver).unknownStepChallenge},
	{"malformed-challenge", (*driver).malformedChallenge},
	{"csrf-mismatch", (*driver).csrfMismatch},
	{"back-after-final-accept", (*driver).backAfterFinalAccept},
	{"back-after-the-end", (*driver).backAfterTheEnd},
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	public := flag.String("public", "http://public.hydra.test", "Hydra public URL")
	dispatcher := flag.String("dispatcher", "http://dispatcher.hydra.test", "dispatcher URL, as Hydra and the apps see it")
	client := flag.String("client", "", "OAuth2 client id registered in Hydra")
	redirect := flag.String("redirect", "http://oidc.client.test/auth/callback", "redirect_uri registered for the client")
	prefix := flag.String("prefix", "", `path prefix of the emulated API: "" (Symfony) or "/admin"`)
	captureDir := flag.String("capture", "testdata/capture", "directory the recorder writes to")
	into := flag.String("into", "", "directory receiving one <NN>-<scenario> directory per scenario")
	first := flag.Int("first", 1, "number of the first scenario directory")
	flag.Parse()
	if *client == "" || *into == "" {
		flag.Usage()
		return errors.New("-client and -into are required")
	}

	d := &driver{client: *client, redirect: *redirect, prefix: *prefix}
	var err error
	if d.public, err = url.Parse(*public); err != nil {
		return err
	}
	if d.dispatcher, err = url.Parse(*dispatcher); err != nil {
		return err
	}
	d.app = &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	inbox := capture.Inbox(*captureDir)

	names := flag.Args()
	type planned struct {
		name string
		run  func(*driver) error
		dir  string
	}
	var plan []planned
	for _, s := range scenarios {
		if len(names) > 0 && !slices.Contains(names, s.name) {
			continue
		}
		dir := filepath.Join(*into, fmt.Sprintf("%02d-%s", *first+len(plan), s.name))
		if err := capture.EnsureEmpty(dir); err != nil {
			return err
		}
		plan = append(plan, planned{s.name, s.run, dir})
	}
	for _, s := range plan {
		before, err := inbox.Listing()
		if err != nil {
			return err
		}
		jar, _ := cookiejar.New(nil)
		// A new browser for each scenario: no Hydra session, no login skip.
		// Hydra remembers a consent by subject, whatever the browser.
		d.browser = &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: noRedirect}
		slog.Info("scenario", "name", s.name)
		if err := s.run(d); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		moved, err := inbox.Collect(before, s.dir)
		if err != nil {
			return err
		}
		slog.Info("captured", "dir", s.dir, "exchanges", moved)
	}
	return nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Scenarios.

func (d *driver) consentRejectFirstStep() error {
	at, err := d.startFlow(flowSQL)
	if err != nil {
		return err
	}
	if at, err = d.appLogin(at, "accept", sqlLoginAccept); err != nil {
		return err
	}
	_, err = d.appConsent(at, "reject", consentDenied)
	return err
}

func (d *driver) consentRejectSecondStep() error {
	at, err := d.startFlow(flowSQL2FA)
	if err != nil {
		return err
	}
	if at, err = d.appLogin(at, "accept", sqlLoginAccept); err != nil {
		return err
	}
	if at, err = d.appConsent(at, "accept", sqlConsentAccept); err != nil {
		return err
	}
	if at, err = d.appLogin(at, "accept", tfaLoginAccept); err != nil {
		return err
	}
	_, err = d.appConsent(at, "reject", consentDenied)
	return err
}

func (d *driver) loginRejectFirstStep() error {
	at, err := d.startFlow(flowSQL)
	if err != nil {
		return err
	}
	_, err = d.appLogin(at, "reject", loginDenied)
	return err
}

func (d *driver) loginRejectSecondStep() error {
	at, err := d.startFlow(flowSQL2FA)
	if err != nil {
		return err
	}
	if at, err = d.appLogin(at, "accept", sqlLoginAccept); err != nil {
		return err
	}
	if at, err = d.appConsent(at, "accept", sqlConsentAccept); err != nil {
		return err
	}
	_, err = d.appLogin(at, "reject", loginDenied)
	return err
}

// acceptTwice sends each accept of a step twice, then stops at the
// dispatcher's consent: a double submission, as a reloaded page sends it.
func (d *driver) acceptTwice() error {
	at, err := d.startFlow(flowSQL)
	if err != nil {
		return err
	}
	login, err := at.param("login_challenge")
	if err != nil {
		return err
	}
	if _, _, err := d.appCall(http.MethodGet, "login", "", login, ""); err != nil {
		return err
	}
	to, err := d.appRedirect("login", "accept", login, sqlLoginAccept)
	if err != nil {
		return err
	}
	if _, _, err := d.appCall(http.MethodPut, "login", "accept", login, sqlLoginAccept); err != nil {
		return err
	}
	if at, err = d.walk(to); err != nil {
		return err
	}
	consent, err := at.param("consent_challenge")
	if err != nil {
		return err
	}
	if _, _, err := d.appCall(http.MethodGet, "consent", "", consent, ""); err != nil {
		return err
	}
	if to, err = d.appRedirect("consent", "accept", consent, sqlConsentAccept); err != nil {
		return err
	}
	if _, _, err := d.appCall(http.MethodPut, "consent", "accept", consent, sqlConsentAccept); err != nil {
		return err
	}
	_, err = d.walk(to)
	return err
}

// unknownStepChallenge calls the emulated API with a well formed challenge
// that no flow issued.
func (d *driver) unknownStepChallenge() error {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	unknown := hex.EncodeToString(b)
	for _, c := range []struct{ method, kind, action, body string }{
		{http.MethodGet, "login", "", ""},
		{http.MethodPut, "login", "accept", sqlLoginAccept},
		{http.MethodGet, "consent", "", ""},
		{http.MethodPut, "consent", "accept", sqlConsentAccept},
	} {
		if _, _, err := d.appCall(c.method, c.kind, c.action, unknown, c.body); err != nil {
			return err
		}
	}
	return nil
}

// malformedChallenge sends a challenge of the wrong form to the emulated API
// and to the pages.
func (d *driver) malformedChallenge() error {
	const malformed = "not-a-challenge"
	if _, _, err := d.appCall(http.MethodGet, "login", "", malformed, ""); err != nil {
		return err
	}
	for _, page := range []string{"/", "/oauth2/auth", "/consent"} {
		param := "login_challenge"
		if page == "/consent" {
			param = "consent_challenge"
		}
		u := d.dispatcher.JoinPath(page)
		u.RawQuery = url.Values{param: {malformed}}.Encode()
		if _, err := d.get(u.String()); err != nil {
			return err
		}
	}
	return nil
}

// csrfMismatch posts the choice with a flow CSRF cookie that is not the one
// the page set.
func (d *driver) csrfMismatch() error {
	page, err := d.startPage()
	if err != nil {
		return err
	}
	d.browser.Jar.SetCookies(d.dispatcher, []*http.Cookie{{Name: "dispatcher_flow_csrf", Value: strings.Repeat("0", 64), Path: "/"}})
	_, err = d.choose(page, flowSQL)
	return err
}

// backAfterFinalAccept goes back to the dispatcher once it has accepted the
// login on Hydra, before the consent.
func (d *driver) backAfterFinalAccept() error {
	at, err := d.startFlow(flowSQL)
	if err != nil {
		return err
	}
	login := d.lastLogin
	if at, err = d.appLogin(at, "accept", sqlLoginAccept); err != nil {
		return err
	}
	if _, err = d.appConsent(at, "accept", sqlConsentAccept); err != nil {
		return err
	}
	return d.revisit(login, "")
}

// backAfterTheEnd completes a flow, the dispatcher's consent screen accepted
// if Hydra shows it, then goes back to the dispatcher's pages.
func (d *driver) backAfterTheEnd() error {
	at, err := d.startFlow(flowSQL)
	if err != nil {
		return err
	}
	login := d.lastLogin
	if at, err = d.appLogin(at, "accept", sqlLoginAccept); err != nil {
		return err
	}
	if at, err = d.appConsent(at, "accept", sqlConsentAccept); err != nil {
		return err
	}
	consent := at.url.Query().Get("consent_challenge")
	if at.status == http.StatusOK && consent != "" {
		if _, err = d.consentScreen(at, "accept"); err != nil {
			return err
		}
	}
	return d.revisit(login, consent)
}

// Browser.

// authURL is the client's authorization request.
func (d *driver) authURL() string {
	u := d.public.JoinPath("/oauth2/auth")
	u.RawQuery = url.Values{
		"client_id":     {d.client},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"redirect_uri":  {d.redirect},
		"state":         {"capture-scenario-state-0001"},
		"nonce":         {"capture-scenario-nonce-0001"},
	}.Encode()
	return u.String()
}

// startPage starts an authorization request and stops at the choice page.
func (d *driver) startPage() (stop, error) {
	at, err := d.walk(d.authURL())
	if err != nil {
		return stop{}, err
	}
	if at.status != http.StatusOK || at.url.Host != d.dispatcher.Host {
		return stop{}, fmt.Errorf("no choice page: stopped at %s (status %d)", at.url.Redacted(), at.status)
	}
	return at, nil
}

// startFlow starts an authorization request and chooses flow on the choice
// page: it stops at the first app's login.
func (d *driver) startFlow(flow string) (stop, error) {
	page, err := d.startPage()
	if err != nil {
		return stop{}, err
	}
	return d.choose(page, flow)
}

func (d *driver) choose(page stop, flow string) (stop, error) {
	l, err := page.param("login_challenge")
	if err != nil {
		return stop{}, err
	}
	token := "csrf-token"
	if m := loginToken.FindSubmatch(page.body); m != nil {
		token = string(m[1])
	}
	return d.post(page.url, url.Values{
		"login[flow]":           {flow},
		"login[submit]":         {""},
		"login[loginChallenge]": {l},
		"login[_token]":         {token},
	})
}

// consentScreen presses button ("accept" or "reject") on the dispatcher's
// consent screen.
func (d *driver) consentScreen(page stop, button string) (stop, error) {
	m := consentToken.FindSubmatch(page.body)
	if m == nil {
		return stop{}, fmt.Errorf("no consent form at %s", page.url.Redacted())
	}
	return d.post(page.url, url.Values{"form[" + button + "]": {""}, "form[_token]": {string(m[1])}})
}

// revisit goes back to the dispatcher's pages with Hydra's challenges, as
// the browser's back button does.
func (d *driver) revisit(login, consent string) error {
	pages := []struct{ path, param, value string }{
		{"/oauth2/auth", "login_challenge", login},
		{"/", "login_challenge", login},
	}
	if consent != "" {
		pages = append(pages, struct{ path, param, value string }{"/consent", "consent_challenge", consent})
	}
	for _, p := range pages {
		u := d.dispatcher.JoinPath(p.path)
		u.RawQuery = url.Values{p.param: {p.value}}.Encode()
		if _, err := d.get(u.String()); err != nil {
			return err
		}
	}
	return nil
}

func (d *driver) post(u *url.URL, form url.Values) (stop, error) {
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return stop{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", d.dispatcher.Scheme+"://"+d.dispatcher.Host)
	return d.follow(req)
}

func (d *driver) get(u string) (stop, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return stop{}, err
	}
	resp, err := d.do(req)
	if err != nil {
		return stop{}, err
	}
	return stop{url: req.URL, status: resp.status, body: resp.body}, nil
}

// walk requests u and follows the redirects through the dispatcher and
// Hydra, as the browser does, up to a page or a redirect elsewhere.
func (d *driver) walk(u string) (stop, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return stop{}, err
	}
	return d.follow(req)
}

func (d *driver) follow(req *http.Request) (stop, error) {
	for range 20 {
		resp, err := d.do(req)
		if err != nil {
			return stop{}, err
		}
		if resp.location == nil {
			return stop{url: req.URL, status: resp.status, body: resp.body}, nil
		}
		loc := resp.location
		if loc.Host != d.dispatcher.Host && loc.Host != d.public.Host {
			return stop{url: loc, status: resp.status}, nil
		}
		// Hydra's login URL is the dispatcher's root, with or without "/".
		if req.URL.Host == d.public.Host && loc.Host == d.dispatcher.Host && (loc.Path == "" || loc.Path == "/") {
			d.lastLogin = loc.Query().Get("login_challenge")
		}
		if req, err = http.NewRequest(http.MethodGet, loc.String(), nil); err != nil {
			return stop{}, err
		}
	}
	return stop{}, errors.New("more than 20 redirects")
}

type answer struct {
	status   int
	location *url.URL
	body     []byte
}

func (d *driver) do(req *http.Request) (answer, error) {
	req.Header.Set("User-Agent", "hydra-dispatcher-go/tools/scenarios")
	req.Header.Set("Accept-Language", "fr")
	resp, err := d.browser.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return answer{}, err
	}
	a := answer{status: resp.StatusCode, body: body}
	if loc, err := resp.Location(); err == nil {
		a.location = loc
	}
	slog.Info("browser", "method", req.Method, "path", req.URL.Path, "status", resp.StatusCode)
	return a, nil
}

// Login apps.

// appLogin plays a login app on the login it is redirected to: it reads the
// login request, then accepts or rejects it with body, and the browser
// follows the redirect_to.
func (d *driver) appLogin(at stop, action, body string) (stop, error) {
	challenge, err := at.param("login_challenge")
	if err != nil {
		return stop{}, err
	}
	if _, _, err := d.appCall(http.MethodGet, "login", "", challenge, ""); err != nil {
		return stop{}, err
	}
	to, err := d.appRedirect("login", action, challenge, body)
	if err != nil {
		return stop{}, err
	}
	return d.walk(to)
}

// appConsent is appLogin for the consent.
func (d *driver) appConsent(at stop, action, body string) (stop, error) {
	challenge, err := at.param("consent_challenge")
	if err != nil {
		return stop{}, err
	}
	if _, _, err := d.appCall(http.MethodGet, "consent", "", challenge, ""); err != nil {
		return stop{}, err
	}
	to, err := d.appRedirect("consent", action, challenge, body)
	if err != nil {
		return stop{}, err
	}
	return d.walk(to)
}

// appRedirect accepts or rejects and returns the redirect_to of the answer.
func (d *driver) appRedirect(kind, action, challenge, body string) (string, error) {
	status, data, err := d.appCall(http.MethodPut, kind, action, challenge, body)
	if err != nil {
		return "", err
	}
	var r struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.RedirectTo == "" {
		return "", fmt.Errorf("%s %s: status %d, no redirect_to", kind, action, status)
	}
	return r.RedirectTo, nil
}

// appCall calls the emulated API as a login app does.
func (d *driver) appCall(method, kind, action, challenge, body string) (int, []byte, error) {
	u := *d.dispatcher
	u.Path = path.Join("/", d.prefix, "oauth2/auth/requests", kind, action)
	u.RawQuery = url.Values{kind + "_challenge": {challenge}}.Encode()
	var reqBody io.Reader
	if body != "" {
		reqBody = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.app.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	slog.Info("app", "method", method, "path", u.Path, "status", resp.StatusCode)
	return resp.StatusCode, data, err
}
