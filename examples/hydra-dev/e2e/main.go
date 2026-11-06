// Command e2e runs the three flows of hydra-dev end to end through the
// dispatcher. It is the browser, through Hydra, the dispatcher's pages and the
// real login apps: hydra-sql-go, hydra-oidc-go and its test IdP,
// hydra-passwordless, whose code it reads in fake-smtp. It is also the OAuth2
// client: it redeems the code and checks the claims of the id_token.
//
// Start hydra-dev with make up-go (Hydra 2.1), make up-go-hydra22 or make
// capture-go, then, from hydra-dispatcher-go (or make e2e in hydra-dev):
//
//	go run ./examples/hydra-dev/e2e [flags] [scenario...]
//
// The host resolves the *.hydra.test names to Caddy, as hydra-dev's README
// sets up. Hydra's skip is honoured from the dispatcher's remember cookie
// (P8): the second logins keep the browser, or drop that cookie. Without scenario names, the default ones run in order, each in a
// new browser; each prints PASS or FAIL, and the command exits 1 when one
// fails. Under make capture-go (or make capture, with -symfony), -into sorts
// the recorded exchanges per scenario, as tools/scenarios does.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/remember"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/tools/capture"
)

// Accounts of hydra-dev's seeds: hydra-sql's (files/postgres/init-db.d,
// password 123456 for all) and the test IdP's (files/apps/oidc/seed.yaml).
const (
	isabelle = "test2@test.com"
	henri    = "test3@test.com"
	alice    = "alice"
)

// identities are what the final id_token says after each flow, isabelle
// signing in to hydra-sql. hydra-oidc's claims come from the IdP, and reach
// its consent through the step's context (A2).
var identities = map[string]identity{
	"hydra-oidc":    {Sub: alice, Email: "alice@example.com", ACR: "1", AMR: []string{"oidc"}},
	"hydra-sql":     {Sub: isabelle, Email: isabelle, ACR: "1", AMR: []string{"pwd"}},
	"hydra-sql-2fa": {Sub: isabelle, Email: isabelle, ACR: "2", AMR: []string{"pwd", "otp"}},
}

type scenario struct {
	name string
	run  func(*driver) error
	// optIn scenarios run only when named.
	optIn bool
}

var scenarios = []scenario{
	{name: "first-login-hydra-oidc", run: firstLogin("hydra-oidc")},
	{name: "first-login-hydra-sql", run: firstLogin("hydra-sql")},
	{name: "first-login-hydra-sql-2fa", run: firstLogin("hydra-sql-2fa")},
	{name: "second-login", run: (*driver).secondLogin},
	{name: "second-login-without-memory", run: (*driver).secondLoginWithoutMemory},
	{name: "second-login-fewer-scopes", run: (*driver).secondLoginFewerScopes},
	{name: "second-login-other-subject", run: (*driver).secondLoginOtherSubject},
	{name: "second-login-prompt-consent-reject", run: (*driver).secondLoginPromptConsentReject},
	{name: "second-login-reload", run: (*driver).secondLoginReload},
	{name: "second-login-prompt-none", run: (*driver).secondLoginPromptNone},
	{name: "second-login-after-replay", run: (*driver).secondLoginAfterReplay},
	{name: "second-login-cookie-lost-at-consent", run: (*driver).secondLoginCookieLostAtConsent},
	{name: "second-login-consent-posted-again", run: (*driver).secondLoginConsentPostedAgain},
	{name: "second-login-concurrent", run: (*driver).secondLoginConcurrent},
	{name: "logout", run: (*driver).logout},
	{name: "logout-refused", run: (*driver).logoutRefused},
	{name: "logout-refused-during-a-chain", run: (*driver).logoutRefusedDuringChain},
	{name: "logout-refused-after-the-end", run: (*driver).logoutRefusedAfterEnd},
	{name: "logout-of-a-client", run: (*driver).logoutOfClient},
	{name: "logout-of-a-client-double-click", run: (*driver).logoutOfClientDoubleClick},
	{name: "logout-former-id-token", run: (*driver).logoutFormerIDToken},
	{name: "logout-from-another-site", run: (*driver).logoutFromAnotherSite},
	{name: "logout-without-memory", run: (*driver).logoutWithoutMemory},
	{name: "logout-consent-in-another-tab", run: (*driver).logoutConsentInAnotherTab},
	{name: "logout-chain-stopped-passed", run: (*driver).logoutChainStoppedPassed},
	{name: "logout-chain-stopped-other-subject", run: (*driver).logoutChainStoppedOtherSubject},
	{name: "logout-chain-stopped-former-login", run: (*driver).logoutChainStoppedFormerLogin},
	{name: "logout-chain-stopped-prompt-none", run: (*driver).logoutChainStoppedPromptNone},
	{name: "logout-chain-stopped-other-session", run: (*driver).logoutChainStoppedOtherSession},
	{name: "logout-apps-answers", run: (*driver).logoutAppsAnswers},
	{name: "logout-preload-head-locale", run: (*driver).logoutPreloadHeadLocale},
	{name: "prompt-consent-accept", run: promptConsent("accept")},
	{name: "prompt-consent-reject", run: promptConsent("reject")},
	{name: "back-to-choice", run: (*driver).backToChoice},
	{name: "back-to-sql-2fa", run: (*driver).backToSQL2FA},
	{name: "expired-on-consent", run: (*driver).expiredOnConsent, optIn: true},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
}

func run() error {
	public := flag.String("public", "http://public.hydra.test", "Hydra's public URL")
	admin := flag.String("admin", "http://admin.hydra.test", "Hydra's admin URL, to find the client and read the login requests")
	dispatcher := flag.String("dispatcher", "http://dispatcher.hydra.test", "the dispatcher's URL")
	smtp := flag.String("smtp", "http://smtp.hydra.test", "fake-smtp's URL, where hydra-passwordless sends its codes")
	clientID := flag.String("client", "", `OAuth2 client id; empty: the one Hydra gave "OIDC Test Client"`)
	secret := flag.String("secret", "oidc-test-123456", "the client's secret (files/hydra/clients.d)")
	redirect := flag.String("redirect", "http://oidc.client.test/auth/callback", "the client's redirect_uri")
	postLogout := flag.String("post-logout", "http://oidc.client.test/", "the client's post_logout_redirect_uri")
	backChannel := flag.String("back-channel", "", "where Hydra reaches this host, host:port, for a client with a back-channel, http://10.0.6.1:<port> on hydra-dev; empty leaves that check out")
	password := flag.String("password", "123456", "password of hydra-sql's accounts")
	cookieKey := flag.String("cookie-key", "504c39b17f9e971e485b0472d2585c012b181d917d96567d353d88662750bda0", "secrets.cookie_key of the dispatcher, in hexadecimal, to open the note of logout; hydra-dev's development key by default")
	symfony := flag.Bool("symfony", false, "drive the Symfony dispatcher's pages (make capture), checking the subject only")
	wait := flag.Duration("wait", 0, "expired-on-consent: time spent on the consent screen, beyond the flow's challenge_ttl")
	captureDir := flag.String("capture", "testdata/capture", "directory the recorder writes to")
	into := flag.String("into", "", "directory receiving one <NN>-<scenario> directory of captured exchanges per scenario")
	first := flag.Int("first", 1, "number of the first scenario directory")
	verbose := flag.Bool("v", false, "log each request of the browser")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: e2e [flags] [scenario...]\n\nscenarios:\n")
		for _, s := range scenarios {
			optIn := ""
			if s.optIn {
				optIn = " (only when named)"
			}
			fmt.Fprintf(flag.CommandLine.Output(), "  %s%s\n", s.name, optIn)
		}
		fmt.Fprintf(flag.CommandLine.Output(), "\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	urls := map[string]*url.URL{}
	for name, raw := range map[string]string{"public": *public, "admin": *admin, "dispatcher": *dispatcher, "smtp": *smtp} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("-%s: %q is not an absolute URL", name, raw)
		}
		urls[name] = u
	}

	ctx := context.Background()
	httpc := &http.Client{Timeout: 15 * time.Second}
	if *clientID == "" {
		id, err := findClient(ctx, httpc, urls["admin"], "OIDC Test Client")
		if err != nil {
			return err
		}
		*clientID = id
	}
	d := &driver{
		ctx:        ctx,
		log:        log,
		dispatcher: urls["dispatcher"],
		client:     &client{public: urls["public"], admin: urls["admin"], id: *clientID, secret: *secret, redirect: *redirect, postLogout: *postLogout, http: httpc},
		mail:       mailbox{base: urls["smtp"], http: httpc},
		pages:      goPages,
		password:   *password,
		wait:       *wait,
	}
	if *symfony {
		d.pages, d.symfony = symfonyPages, true
	}
	key, err := hex.DecodeString(*cookieKey)
	if err != nil {
		return fmt.Errorf("-cookie-key: %w", err)
	}
	if d.memories, err = remember.New(key); err != nil {
		return fmt.Errorf("-cookie-key: %w", err)
	}
	if d.version, err = d.client.hydraVersion(ctx); err != nil {
		return err
	}
	if *backChannel != "" {
		stop, err := d.listenBackChannel(*backChannel)
		if err != nil {
			return err
		}
		defer stop()
	}

	type planned struct {
		name string
		run  func(*driver) error
		dir  string
	}
	var plan []planned
	names := flag.Args()
	for _, n := range names {
		if !slices.ContainsFunc(scenarios, func(s scenario) bool { return s.name == n }) {
			flag.Usage()
			return fmt.Errorf("unknown scenario %q", n)
		}
	}
	for _, s := range scenarios {
		if len(names) > 0 && !slices.Contains(names, s.name) || len(names) == 0 && s.optIn {
			continue
		}
		var dir string
		if *into != "" {
			dir = filepath.Join(*into, fmt.Sprintf("%02d-%s", *first+len(plan), s.name))
			if err := capture.EnsureEmpty(dir); err != nil {
				return err
			}
		}
		plan = append(plan, planned{s.name, s.run, dir})
	}

	inbox := capture.Inbox(*captureDir)
	failed := 0
	for _, s := range plan {
		var before map[string]bool
		if s.dir != "" {
			var err error
			if before, err = inbox.Listing(); err != nil {
				return err
			}
		}
		// A new browser for each scenario: no Hydra session, no cookie of the
		// dispatcher or of the apps. Hydra remembers a consent by subject
		// and client, whatever the browser.
		d.b, d.notes = newBrowser(*redirect, log), nil
		d.b.stopAt = append(d.b.stopAt, *postLogout)
		start := time.Now()
		err := s.run(d)
		elapsed := time.Since(start).Round(100 * time.Millisecond)
		status, detail := "PASS", strings.Join(d.notes, "; ")
		if err != nil {
			failed++
			status, detail = "FAIL", err.Error()
		}
		if detail != "" {
			detail = ": " + detail
		}
		fmt.Printf("--- %s %s (%s)%s\n", status, s.name, elapsed, detail)
		if s.dir != "" {
			moved, err := inbox.Collect(before, s.dir)
			if err != nil {
				return err
			}
			log.Info("captured", "dir", s.dir, "exchanges", moved)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d scenarios failed", failed, len(plan))
	}
	return nil
}

// dispatcherPages names the fields of a dispatcher's forms.
type dispatcherPages struct {
	// flow is the radio of the choice page, flowValue its value for a flow
	// id, and choose the button that submits it, if it has a name.
	flow      string
	flowValue func(id string) string
	choose    *pressed
	// consent is a field only the consent screen's form has, accept and
	// reject its buttons.
	consent        string
	accept, reject pressed
}

var (
	goPages = dispatcherPages{
		flow:      "flow",
		flowValue: func(id string) string { return id },
		consent:   "consent_challenge",
		accept:    pressed{"action", "accept"},
		reject:    pressed{"action", "reject"},
	}
	// The Symfony choice form posts the flow's position among the flows
	// sorted by id (testdata/protocol/symfony-hydra-2.1/README.md).
	symfonyPages = dispatcherPages{
		flow: "login[flow]",
		flowValue: func(id string) string {
			return fmt.Sprint(slices.Index([]string{"hydra-oidc", "hydra-sql", "hydra-sql-2fa"}, id))
		},
		choose:  &pressed{Name: "login[submit]"},
		consent: "form[_token]",
		accept:  pressed{Name: "form[accept]"},
		reject:  pressed{Name: "form[reject]"},
	}
)

type driver struct {
	ctx        context.Context
	log        *slog.Logger
	b          *browser
	client     *client
	mail       mailbox
	dispatcher *url.URL
	pages      dispatcherPages
	// symfony checks the subject only: Symfony loses claims (the email of
	// hydra-sql-2fa).
	symfony  bool
	password string
	wait     time.Duration
	// memories opens the dispatcher_remember cookie.
	memories *remember.Codec
	// version is Hydra's; backChannelURL where a client hears of a logout, ""
	// leaving that check out, and backChannelHits the logout tokens it got.
	version         string
	backChannelURL  string
	backChannelHits atomic.Int32
	// mark is the newest email when the authorization started: the code of
	// hydra-passwordless comes after it.
	mark int
	// notes of the scenario, printed after PASS.
	notes []string
}

func (d *driver) note(format string, args ...any) {
	d.notes = append(d.notes, fmt.Sprintf(format, args...))
}

// login says what the browser does on the pages of an authorization.
type login struct {
	flow string // chosen on the choice page
	// user signs in to hydra-sql; hydra-passwordless sends its code to this
	// address.
	user string
	// consent is the button pressed on the dispatcher's consent screen,
	// accept or reject, after waitOnConsent.
	consent       string
	waitOnConsent time.Duration
	prompt        string // of the authorization request
}

// outcome is how an authorization went.
type outcome struct {
	// entry is the first page driven, the dispatcher's choice page.
	entry *url.URL
	// seen lists the pages met, in order: choice, consent, hydra-sql,
	// hydra-2fa, idp, then callback or error.
	seen []string
	end  page
	// code is the error code of the dispatcher's page the walk ended on.
	code string
}

func (o outcome) saw(kind string) bool { return slices.Contains(o.seen, kind) }

// start sends the authorization request and returns the first page.
func (d *driver) start(prompt string) (page, error) {
	mark, err := d.mail.last(d.ctx)
	if err != nil {
		return page{}, err
	}
	d.mark = mark
	return d.b.get(d.client.authURL(prompt))
}

// authorize runs an authorization through to its end.
func (d *driver) authorize(l login) (outcome, error) {
	p, err := d.start(l.prompt)
	if err != nil {
		return outcome{}, err
	}
	return d.drive(p, l)
}

// drive acts on each page as l says, up to the client's redirect_uri or an
// error page of the dispatcher.
func (d *driver) drive(p page, l login) (outcome, error) {
	o := outcome{entry: p.URL}
	for range 12 {
		kind := d.kind(p)
		// A page met twice in a row refused what was sent: hydra-sql's
		// login form shows the error again.
		if n := len(o.seen); n > 0 && o.seen[n-1] == kind {
			return o, fmt.Errorf("%s again after %v: %w", kind, o.seen, errUnexpected(p))
		}
		o.seen = append(o.seen, kind)
		var err error
		switch kind {
		case "callback":
			o.end = p
			return o, nil
		case "error":
			o.end, o.code = p, errorCode.FindString(p.Body)
			return o, nil
		case "choice":
			p, err = d.choose(p, l.flow)
		case "consent":
			p, err = d.consentScreen(p, l.consent, l.waitOnConsent)
		case "hydra-sql":
			p, err = d.sqlLogin(p, l.user)
		case "hydra-2fa":
			p, err = d.otp(p, l.user)
		case "idp":
			p, err = d.idp(p, alice)
		default:
			return o, fmt.Errorf("after %v: %w", o.seen[:len(o.seen)-1], errUnexpected(p))
		}
		if err != nil {
			return o, fmt.Errorf("%s: %w", kind, err)
		}
	}
	return o, fmt.Errorf("too many pages: %v", o.seen)
}

// errorCode is the code of a dispatcher's error page.
var errorCode = regexp.MustCompile(`\bE1\d{3}\b`)

// kind tells which page p is, by its forms rather than by its host: "" for
// a page the e2e does not know.
func (d *driver) kind(p page) string {
	if p.Body == "" && strings.HasPrefix(p.URL.String(), d.client.redirect) {
		return "callback"
	}
	if p.URL.Host == d.dispatcher.Host {
		if _, ok := p.find(d.pages.flow); ok {
			return "choice"
		}
		if _, ok := p.find(d.pages.consent); ok {
			return "consent"
		}
		if _, ok := p.find("logout_challenge"); ok {
			return "logout"
		}
		if errorCode.MatchString(p.Body) {
			return "error"
		}
		return ""
	}
	for _, k := range []struct{ field, kind string }{
		{"password", "hydra-sql"},
		{"otp", "hydra-2fa"},
		{"userID", "idp"},
	} {
		if _, ok := p.find(k.field); ok {
			return k.kind
		}
	}
	return ""
}

func (d *driver) choose(p page, flow string) (page, error) {
	f, ok := p.find(d.pages.flow)
	if !ok {
		return page{}, errUnexpected(p)
	}
	v, err := f.values(map[string]string{d.pages.flow: d.pages.flowValue(flow)}, d.pages.choose)
	if err != nil {
		return page{}, err
	}
	return d.b.submit(p, f, v)
}

func (d *driver) consentScreen(p page, button string, wait time.Duration) (page, error) {
	f, _ := p.find(d.pages.consent)
	press := d.pages.accept
	if button == "reject" {
		press = d.pages.reject
	}
	if wait > 0 {
		d.log.Info("waiting on the consent screen", "for", wait)
		time.Sleep(wait)
	}
	v, err := f.values(nil, &press)
	if err != nil {
		return page{}, err
	}
	return d.b.submit(p, f, v)
}

func (d *driver) sqlLogin(p page, user string) (page, error) {
	f, _ := p.find("password")
	v, err := f.values(map[string]string{"login": user, "password": d.password}, nil)
	if err != nil {
		return page{}, err
	}
	return d.b.submit(p, f, v)
}

func (d *driver) otp(p page, user string) (page, error) {
	code, err := d.mail.code(d.ctx, user, d.mark)
	if err != nil {
		return page{}, err
	}
	f, _ := p.find("otp")
	v, err := f.values(map[string]string{"otp": code}, nil)
	if err != nil {
		return page{}, err
	}
	return d.b.submit(p, f, v)
}

// idp signs in as subject on the test IdP's account list: one form per
// account, on the row that names the subject.
func (d *driver) idp(p page, subject string) (page, error) {
	row := regexp.MustCompile(`(?s)<td>` + regexp.QuoteMeta(subject) + `</td>.*?name="userID" value="([^"]+)"`).FindStringSubmatch(p.Body)
	if row == nil {
		return page{}, fmt.Errorf("no account %s: %w", subject, errUnexpected(p))
	}
	for _, f := range parseForms(p.URL, p.Body) {
		if slices.ContainsFunc(f.Fields, func(x field) bool { return x.Name == "userID" && x.Value == row[1] }) {
			v, err := f.values(nil, nil)
			if err != nil {
				return page{}, err
			}
			return d.b.submit(p, f, v)
		}
	}
	return page{}, fmt.Errorf("no form for account %s: %w", subject, errUnexpected(p))
}

// granted checks that the authorization came back to the client with a code
// whose id_token says want.
func (d *driver) granted(o outcome, want identity) error {
	if o.end.URL == nil || d.kind(o.end) != "callback" {
		return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
	}
	refused, err := d.client.callbackError(o.end.URL)
	if err != nil {
		return err
	}
	if refused != "" {
		return fmt.Errorf("authorization refused: %s (%s), pages %v", refused, o.end.URL.Query().Get("error_description"), o.seen)
	}
	claims, err := d.client.redeem(d.ctx, o.end.URL)
	if err != nil {
		return err
	}
	if d.symfony {
		want.Email, want.ACR, want.AMR = "", "", nil
	}
	return want.check(claims)
}

func endURL(o outcome) string {
	if o.end.URL == nil {
		return ""
	}
	return o.end.URL.Redacted()
}

// noteConsent says whether the dispatcher showed its consent screen: Hydra
// skips the consent it remembers for the subject and the client.
func (d *driver) noteConsent(o outcome) {
	if o.saw("consent") {
		d.note("consent screen accepted")
	} else {
		d.note("consent skipped by Hydra")
	}
}

// Scenarios.

// firstLogin signs in through flow in a new browser.
func firstLogin(flow string) func(*driver) error {
	return func(d *driver) error {
		o, err := d.authorize(login{flow: flow, user: isabelle, consent: "accept"})
		if err != nil {
			return err
		}
		if !o.saw("choice") {
			return fmt.Errorf("no choice page: %v", o.seen)
		}
		d.noteConsent(o)
		return d.granted(o, identities[flow])
	}
}

// rememberCookie is the dispatcher's memory of the skip (P8), in plain
// HTTP without the __Host- prefix.
const rememberCookie = "dispatcher_remember"

// remembered signs in with hydra-sql, then checks the dispatcher wrote its
// memory of the skip at the consent (WRT-1).
func (d *driver) remembered() error {
	if err := d.signIn(login{flow: "hydra-sql", user: isabelle, consent: "accept"}); err != nil {
		return fmt.Errorf("first login: %w", err)
	}
	if !d.b.has(d.dispatcher, rememberCookie) {
		return fmt.Errorf("first login: no %s cookie (WRT-1)", rememberCookie)
	}
	return nil
}

// skipped checks that a walk went through the dispatcher's skip (SKP-1):
// its answer to Hydra's login request is the login verifier, without a page
// of its own, then its /consent without a flow.
func (d *driver) skipped(p page) error {
	honoured, consent := false, false
	for i, u := range p.Trail {
		if u.Host != d.dispatcher.Host {
			continue
		}
		switch {
		case u.Path == "/" && u.Query().Has("login_challenge") && i+1 < len(p.Trail):
			honoured = p.Trail[i+1].Query().Has("login_verifier")
		case u.Path == "/consent":
			consent = true
		}
	}
	if !honoured || !consent {
		return fmt.Errorf("skip not honoured (SKP-1, SKC): skip %v, consent %v, trail %s", honoured, consent, trail(p))
	}
	return nil
}

func trail(p page) string {
	var paths []string
	for _, u := range p.Trail {
		paths = append(paths, u.Host+u.Path)
	}
	return strings.Join(paths, " > ")
}

// secondLogin signs in twice with hydra-sql in the same browser. Hydra asks
// the second time to skip the login, which the dispatcher honours from its
// cookie (SKP-1): no choice page nor app, the consent accepted from the
// cookie too (SKC-1).
func (d *driver) secondLogin() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.start("")
	if err != nil {
		return err
	}
	if err := d.skipped(p); err != nil {
		return err
	}
	o := outcome{entry: p.Trail[0], seen: []string{d.kind(p)}, end: p}
	if err := d.granted(o, identities["hydra-sql"]); err != nil {
		return err
	}
	d.note("skip honoured")
	return nil
}

// secondLoginWithoutMemory signs in twice with hydra-sql in the same
// browser, which keeps Hydra's session but loses the dispatcher's cookie:
// Hydra asks to skip the login, the dispatcher ignores it (ENT-9, SKP-2):
// the choice page and the app's form again, then the subject compared at the
// final accept (FIN-2).
func (d *driver) secondLoginWithoutMemory() error {
	l := login{flow: "hydra-sql", user: isabelle, consent: "accept"}
	if err := d.remembered(); err != nil {
		return err
	}
	d.b.forget(d.dispatcher, rememberCookie)
	o, err := d.skippedLogin(l)
	if err != nil {
		return err
	}
	if !o.saw("choice") || !o.saw("hydra-sql") {
		return fmt.Errorf("skip not ignored: pages %v", o.seen)
	}
	return d.granted(o, identities["hydra-sql"])
}

// secondLoginFewerScopes signs in with hydra-sql, then in the same browser,
// cookie kept, for fewer scopes, openid alone: the cookie's claims were
// filtered by hydra-sql for openid, profile and email, so the dispatcher
// ignores Hydra's skip (MEM-8, revue R20) and plays the flow again, whose
// id_token holds no email, as without the cookie.
func (d *driver) secondLoginFewerScopes() error {
	if err := d.remembered(); err != nil {
		return err
	}
	d.client.scope = "openid"
	defer func() { d.client.scope = "" }()
	o, err := d.skippedLogin(login{flow: "hydra-sql", user: isabelle, consent: "accept"})
	if err != nil {
		return fmt.Errorf("MEM-8, skip not ignored: %w", err)
	}
	if o.end.URL == nil || d.kind(o.end) != "callback" {
		return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
	}
	claims, err := d.client.redeem(d.ctx, o.end.URL)
	if err != nil {
		return err
	}
	if err := (identity{Sub: isabelle, ACR: "1", AMR: []string{"pwd"}}).check(claims); err != nil {
		return err
	}
	for _, c := range []string{"email", "firstname", "lastname"} {
		if _, ok := claims[c]; ok {
			return fmt.Errorf("claim %s for scope openid alone", c)
		}
	}
	return nil
}

// secondLoginOtherSubject signs in with hydra-sql, then in the same browser,
// without the dispatcher's cookie, as someone else: the dispatcher refuses
// at the final accept, page E1003, and finishes the flow, which a reload of
// the choice page shows: E1002 (FIN-3, ENT-7). With prompt=login, Hydra no
// longer says skip, and FIN-3 is out of reach. The reject itself is not read
// on Hydra's admin: 2.2 no longer tells a handled request from a pending
// one, and 2.1 answers 410 to a login request once its verifier is followed
// (login_used of internal/hydra/testdata/errors), which the dispatcher never
// does after E1003; no fixture reads a rejected one before. go 05:0103 shows
// the reject.
func (d *driver) secondLoginOtherSubject() error {
	if err := d.remembered(); err != nil {
		return err
	}
	d.b.forget(d.dispatcher, rememberCookie)
	o, err := d.skippedLogin(login{flow: "hydra-sql", user: henri, consent: "accept"})
	if err != nil {
		return err
	}
	if o.code != "E1003" {
		return fmt.Errorf("pages %v, ended on %q %s, want the page E1003", o.seen, o.code, endURL(o))
	}
	p, err := d.b.get(o.entry.String())
	if err != nil {
		return err
	}
	if code := errorCode.FindString(p.Body); d.kind(p) != "error" || code != "E1002" {
		return fmt.Errorf("choice page reloaded after E1003: %q, want the page E1002 of a finished flow: %w", code, errUnexpected(p))
	}
	return nil
}

// signIn runs l to a granted authorization.
func (d *driver) signIn(l login) error {
	o, err := d.authorize(l)
	if err != nil {
		return err
	}
	return d.granted(o, identities[l.flow])
}

// skippedLogin runs l after checking, on Hydra's admin, that Hydra asks the
// dispatcher to skip the login: the browser has its session.
func (d *driver) skippedLogin(l login) (outcome, error) {
	p, err := d.start(l.prompt)
	if err != nil {
		return outcome{}, err
	}
	challenge := p.URL.Query().Get("login_challenge")
	if d.kind(p) != "choice" || challenge == "" {
		return outcome{}, fmt.Errorf("second login: no choice page: %w", errUnexpected(p))
	}
	skip, err := d.client.loginSkip(d.ctx, challenge)
	if err != nil {
		return outcome{}, err
	}
	if !skip {
		return outcome{}, errors.New("second login: Hydra does not ask to skip, the first login was not remembered")
	}
	return d.drive(p, l)
}

// secondLoginPromptConsentReject is the path of Symfony's capture 15: a
// second login in skip, honoured (SKP-1), with prompt=consent: the consent
// screen without a flow, built from the cookie (SKC-2), refused (SKC-4): the
// client gets access_denied.
func (d *driver) secondLoginPromptConsentReject() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.start("consent")
	if err != nil {
		return err
	}
	if d.kind(p) != "consent" {
		return fmt.Errorf("no consent screen: %w", errUnexpected(p))
	}
	if f, _ := p.find(d.pages.consent); !f.has("claims_print") {
		return errors.New("a consent screen without the print of its claims (SKC-2, Q37)")
	}
	o, err := d.drive(p, login{consent: "reject"})
	if err != nil {
		return err
	}
	if err := d.skipped(p); err != nil {
		return err
	}
	if d.kind(o.end) != "callback" {
		return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
	}
	refused, err := d.client.callbackError(o.end.URL)
	if err != nil {
		return err
	}
	if refused != "access_denied" {
		return fmt.Errorf("callback error %q, want access_denied", refused)
	}
	return nil
}

// skipReplay is how long the dispatcher replays the redirect_to of a skip
// (Q35), plus a margin.
const skipReplay = 10*time.Second + 500*time.Millisecond

// secondLoginReload reloads the dispatcher's page during the redirection of
// a skip honoured: it gives the same login verifier again, without a second
// accept, and the authorization goes on to the client (ENT-21, Q35); 10 s
// later, the same page gives E1002 (ENT-7).
func (d *driver) secondLoginReload() error {
	if err := d.remembered(); err != nil {
		return err
	}
	entry, err := d.b.hop(d.client.authURL(""))
	if err != nil {
		return err
	}
	if entry.Host != d.dispatcher.Host || !entry.Query().Has("login_challenge") {
		return fmt.Errorf("the authorization went to %s, not to the dispatcher", entry.Redacted())
	}
	first, err := d.b.hop(entry.String())
	if err != nil {
		return fmt.Errorf("SKP-1: %w", err)
	}
	if !first.Query().Has("login_verifier") {
		return fmt.Errorf("SKP-1: redirected to %s, not to the login verifier", first.Redacted())
	}
	again, err := d.b.hop(entry.String())
	if err != nil {
		return fmt.Errorf("ENT-21, the reload: %w", err)
	}
	if again.String() != first.String() {
		return fmt.Errorf("ENT-21, the reload redirected to %s, not to the same verifier", again.Redacted())
	}
	p, err := d.b.get(again.String())
	if err != nil {
		return err
	}
	if err := d.granted(outcome{entry: entry, seen: []string{d.kind(p)}, end: p}, identities["hydra-sql"]); err != nil {
		return err
	}
	d.log.Info("waiting past the replay of the skip", "for", skipReplay)
	time.Sleep(skipReplay)
	p, err = d.b.get(entry.String())
	if err != nil {
		return err
	}
	if code := errorCode.FindString(p.Body); d.kind(p) != "error" || code != "E1002" {
		return fmt.Errorf("ENT-7, past 10 s: %q, want the page E1002: %w", code, errUnexpected(p))
	}
	return nil
}

// secondLoginPromptNone is prompt=none, which forbids any page (OIDC Core
// 3.1.2.1), Hydra having a session and leaving that to the dispatcher: with
// the cookie valid, the code (SKP-1, SKC-1); a skip ignored, for fewer scopes
// or without the cookie, gives login_required, never the choice page (SKP-11).
func (d *driver) secondLoginPromptNone() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.start("none")
	if err != nil {
		return err
	}
	if err := d.granted(outcome{entry: p.Trail[0], seen: []string{d.kind(p)}, end: p}, identities["hydra-sql"]); err != nil {
		return fmt.Errorf("SKP-1 with prompt=none: %w", err)
	}
	for _, tc := range []struct {
		name  string
		scope string
		lost  bool
	}{{"fewer scopes", "openid", false}, {"the cookie lost", "", true}} {
		if tc.lost {
			d.b.forget(d.dispatcher, rememberCookie)
		}
		d.client.scope = tc.scope
		p, err := d.start("none")
		d.client.scope = ""
		if err != nil {
			return err
		}
		if d.kind(p) != "callback" {
			return fmt.Errorf("SKP-11, %s: %w", tc.name, errUnexpected(p))
		}
		refused, err := d.client.callbackError(p.URL)
		if err != nil {
			return err
		}
		if refused != "login_required" {
			return fmt.Errorf("SKP-11, %s: callback error %q, want login_required", tc.name, refused)
		}
	}
	return nil
}

// secondLoginAfterReplay checks the cookie written by a flow played again
// serves the next skip: after a skip ignored, Hydra keeps its session, the
// same session_id (FIN-2, MEM-4); after prompt=login, Hydra makes a new one,
// which the cookie written then names.
func (d *driver) secondLoginAfterReplay() error {
	l := login{flow: "hydra-sql", user: isabelle, consent: "accept"}
	if err := d.remembered(); err != nil {
		return err
	}
	honoured := func(after string) error {
		p, err := d.start("")
		if err != nil {
			return err
		}
		if err := d.skipped(p); err != nil {
			return fmt.Errorf("after %s: %w", after, err)
		}
		return d.granted(outcome{entry: p.Trail[0], seen: []string{d.kind(p)}, end: p}, identities["hydra-sql"])
	}
	d.b.forget(d.dispatcher, rememberCookie)
	o, err := d.skippedLogin(l)
	if err != nil {
		return err
	}
	if !o.saw("hydra-sql") {
		return fmt.Errorf("skip not ignored: pages %v", o.seen)
	}
	if err := honoured("a skip ignored"); err != nil {
		return err
	}
	l.prompt = "login"
	if o, err = d.authorize(l); err != nil {
		return err
	}
	if !o.saw("hydra-sql") {
		return fmt.Errorf("prompt=login without a login: pages %v", o.seen)
	}
	return honoured("prompt=login")
}

// secondLoginCookieLostAtConsent loses the cookie between the accept of a
// skip and its consent: nothing can be played again, the client gets
// login_required (SKC-6).
func (d *driver) secondLoginCookieLostAtConsent() error {
	if err := d.remembered(); err != nil {
		return err
	}
	entry, err := d.b.hop(d.client.authURL(""))
	if err != nil {
		return err
	}
	verifier, err := d.b.hop(entry.String())
	if err != nil {
		return fmt.Errorf("SKP-1: %w", err)
	}
	d.b.forget(d.dispatcher, rememberCookie)
	p, err := d.b.get(verifier.String())
	if err != nil {
		return err
	}
	if d.kind(p) != "callback" {
		return fmt.Errorf("SKC-6: %w", errUnexpected(p))
	}
	refused, err := d.client.callbackError(p.URL)
	if err != nil {
		return err
	}
	if refused != "login_required" {
		return fmt.Errorf("SKC-6: callback error %q, want login_required", refused)
	}
	return nil
}

// secondLoginConsentPostedAgain posts the screen without a flow again once
// its verifier is followed: never a second authorization. Hydra 2.1 answers
// 410 to the read, page E1002; 2.2 and 2.3 accept again, and refuse the
// verifier: access_denied at the client (SKC-14).
func (d *driver) secondLoginConsentPostedAgain() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.start("consent")
	if err != nil {
		return err
	}
	if d.kind(p) != "consent" {
		return fmt.Errorf("no consent screen: %w", errUnexpected(p))
	}
	f, _ := p.find(d.pages.consent)
	v, err := f.values(nil, &d.pages.accept)
	if err != nil {
		return err
	}
	done, err := d.b.submit(p, f, v)
	if err != nil {
		return err
	}
	if err := d.granted(outcome{entry: p.Trail[0], seen: []string{"consent", d.kind(done)}, end: done}, identities["hydra-sql"]); err != nil {
		return err
	}
	again, err := d.b.submit(p, f, v)
	if err != nil {
		return err
	}
	switch d.kind(again) {
	case "error":
		if code := errorCode.FindString(again.Body); code != "E1002" {
			return fmt.Errorf("SKC-14: page %s, want E1002", code)
		}
	case "callback":
		refused, err := d.client.callbackError(again.URL)
		if err != nil {
			return err
		}
		if refused != "access_denied" {
			return fmt.Errorf("SKC-14: callback error %q, want access_denied", refused)
		}
	default:
		return fmt.Errorf("SKC-14: %w", errUnexpected(again))
	}
	return nil
}

// secondLoginConcurrent loads the same L four times at once, the cookie
// valid: Hydra accepts each, one writes the flow, each is redirected to a
// login verifier, and the authorization goes on from any (SKP-6, ECR-3).
func (d *driver) secondLoginConcurrent() error {
	if err := d.remembered(); err != nil {
		return err
	}
	entry, err := d.b.hop(d.client.authURL(""))
	if err != nil {
		return err
	}
	const loads = 4
	verifiers := make([]*url.URL, loads)
	errs := make([]error, loads)
	var wg sync.WaitGroup
	for i := range loads {
		wg.Go(func() { verifiers[i], errs[i] = d.b.hop(entry.String()) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("SKP-6: %w", err)
	}
	for _, u := range verifiers {
		if !u.Query().Has("login_verifier") {
			return fmt.Errorf("SKP-6: redirected to %s, not to a login verifier", u.Redacted())
		}
	}
	p, err := d.b.get(verifiers[0].String())
	if err != nil {
		return err
	}
	return d.granted(outcome{entry: entry, seen: []string{d.kind(p)}, end: p}, identities["hydra-sql"])
}

// The URLs of the apps' logout, as hydra-dev's seed names them.
const (
	sqlLogout  = "http://sql.hydra.test/logout"
	tfaLogout  = "http://2fa.hydra.test/logout"
	oidcLogout = "http://oidc.hydra.test/logout"
)

// through checks that a walk went through the logout_url of each app, in order,
// and returns what it left out.
func through(p page, urls ...string) error {
	i := 0
	for _, u := range p.Trail {
		if i < len(urls) && strings.HasPrefix(u.String(), urls[i]) {
			i++
		}
	}
	if i < len(urls) {
		return fmt.Errorf("the logout_url of %s not reached: %s", urls[i], trail(p))
	}
	return nil
}

// endsOnVerifier checks that a walk followed Hydra's verifier, the last step of a
// logout (HLO-2).
func endsOnVerifier(p page) error {
	if !slices.ContainsFunc(p.Trail, func(u *url.URL) bool { return u.Query().Has("logout_verifier") }) {
		return fmt.Errorf("the verifier not followed: %s", trail(p))
	}
	return nil
}

// noted checks that the cookie is a note of logout of the session of the last
// id_token, naming apps, without anything that could serve a skip (WRT-4).
func (d *driver) noted(apps ...string) (*flow.Remembered, error) {
	n := d.memories.Open(d.b.cookie(d.dispatcher, rememberCookie)).Content
	switch {
	case n == nil:
		return nil, errors.New("WRT-4: no cookie that opens")
	case !n.Lo:
		return nil, fmt.Errorf("WRT-4: not a note: %+v", n)
	case n.Flow != "" || n.FH != "" || n.ACR != "" || len(n.AMR) != 0 || len(n.Ctx) != 0 || len(n.Scp) != 0 || len(n.Aud) != 0 || len(n.IDT) != 0 || len(n.ACT) != 0:
		return nil, fmt.Errorf("WRT-4: the note holds claims: %+v", n)
	case n.Sub == "" || n.SID == "" || n.IAT == 0:
		return nil, fmt.Errorf("WRT-4: a note without its session: %+v", n)
	case !slices.Equal(n.AP, apps):
		return nil, fmt.Errorf("WRT-4: the note names %v, want %v", n.AP, apps)
	}
	claims, err := idTokenClaims(d.client.idToken)
	if err != nil {
		return nil, err
	}
	if n.SID != claims["sid"] {
		return nil, fmt.Errorf("WRT-4: the note of session %s, want %v", n.SID, claims["sid"])
	}
	return n, nil
}

// signedIn signs in through flow, and returns once the memory of the skip is
// written.
func (d *driver) signedIn(flow string) error {
	if err := d.signIn(login{flow: flow, user: isabelle, consent: "accept"}); err != nil {
		return fmt.Errorf("sign-in: %w", err)
	}
	if !d.b.has(d.dispatcher, rememberCookie) {
		return fmt.Errorf("sign-in: no %s cookie (WRT-1)", rememberCookie)
	}
	return nil
}

// askLogout asks for the logout as a user does, and returns the page of the
// confirmation (LGO-6).
func (d *driver) askLogout() (page, error) {
	p, err := d.b.get(d.client.logoutURL("", ""))
	if err != nil {
		return page{}, err
	}
	if d.kind(p) != "logout" {
		return page{}, fmt.Errorf("no confirmation: %w", errUnexpected(p))
	}
	return p, nil
}

// answerLogout presses a button of the confirmation p.
func (d *driver) answerLogout(p page, button string) (page, error) {
	f, ok := p.find("logout_challenge")
	if !ok {
		return page{}, errUnexpected(p)
	}
	v, err := f.values(nil, &pressed{"action", button})
	if err != nil {
		return page{}, err
	}
	return d.b.submit(p, f, v)
}

// honoured checks that the skip is still honoured in this browser (SKP-1).
func (d *driver) honoured(what string) error {
	p, err := d.start("")
	if err != nil {
		return err
	}
	if err := d.skipped(p); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return d.granted(outcome{entry: p.Trail[0], seen: []string{d.kind(p)}, end: p}, identities["hydra-sql"])
}

// loggedOut checks that the next authorization has no session at Hydra: the
// choice page and the app.
func (d *driver) loggedOut(flow string) error {
	o, err := d.authorize(login{flow: flow, user: isabelle, consent: "accept"})
	if err != nil {
		return err
	}
	if !o.saw("choice") || !o.saw("hydra-sql") {
		return fmt.Errorf("after the logout, pages %v: want the choice page and the app", o.seen)
	}
	return d.granted(o, identities[flow])
}

// logout signs in with two apps, then out: the question, then the logout_url of
// each app of the flow (LST-1), the verifier last. The cookie is now a note, and
// the next authorization, without a session at Hydra, shows the choice page.
func (d *driver) logout() error {
	if err := d.signedIn("hydra-sql-2fa"); err != nil {
		return err
	}
	memory := d.b.cookie(d.dispatcher, rememberCookie)
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	if d.b.cookie(d.dispatcher, rememberCookie) != memory {
		return errors.New("WRT-4: the cookie changed at the confirmation")
	}
	end, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	if err := through(end, sqlLogout, tfaLogout); err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	if _, err := d.noted("hydra-sql", "hydra-2fa"); err != nil {
		return err
	}
	return d.loggedOut("hydra-sql")
}

// logoutRefused refuses the confirmation: the skip stays honoured, the cookie
// kept (LGO-12).
func (d *driver) logoutRefused() error {
	if err := d.remembered(); err != nil {
		return err
	}
	memory := d.b.cookie(d.dispatcher, rememberCookie)
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	end, err := d.answerLogout(p, "reject")
	if err != nil {
		return err
	}
	if end.Status != http.StatusOK || !strings.Contains(end.Body, "restez connecté") || strings.Contains(end.Body, "<form") {
		return fmt.Errorf("LGO-12: %w", errUnexpected(end))
	}
	if d.b.cookie(d.dispatcher, rememberCookie) != memory {
		return errors.New("LGO-12: the cookie changed")
	}
	// LGO-15, the double click.
	again, err := d.answerLogout(p, "reject")
	if err != nil {
		return err
	}
	if !strings.Contains(again.Body, "restez connecté") {
		return fmt.Errorf("LGO-15: %w", errUnexpected(again))
	}
	return d.honoured("refused")
}

// logoutRefusedDuringChain refuses a second demand while a chain goes on: no
// reject of its verifier's demand, a page that says it, its link taking the chain
// up (LGO-14).
func (d *driver) logoutRefusedDuringChain() error {
	if err := d.signedIn("hydra-sql-2fa"); err != nil {
		return err
	}
	d.b.stopAt = append(d.b.stopAt, sqlLogout)
	first, err := d.askLogout()
	if err != nil {
		return err
	}
	stopped, err := d.answerLogout(first, "accept")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(stopped.URL.String(), sqlLogout) {
		return fmt.Errorf("the chain did not stop at hydra-sql: %s", trail(stopped))
	}
	second, err := d.askLogout()
	if err != nil {
		return err
	}
	if d.kind(second) != "logout" {
		return fmt.Errorf("the second demand: %w", errUnexpected(second))
	}
	refused, err := d.answerLogout(second, "reject")
	if err != nil {
		return err
	}
	if !strings.Contains(refused.Body, "déjà commencée") {
		return fmt.Errorf("LGO-14: %w", errUnexpected(refused))
	}
	links := regexp.MustCompile(`href="([^"]*/logout/next\?ref=[^"]*)"`).FindStringSubmatch(refused.Body)
	if links == nil {
		return fmt.Errorf("LGO-14, no link: %w", errUnexpected(refused))
	}
	d.b.stopAt = d.b.stopAt[:len(d.b.stopAt)-1]
	end, err := d.b.get(links[1])
	if err != nil {
		return err
	}
	if err := through(end, sqlLogout, tfaLogout); err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	return d.loggedOut("hydra-sql")
}

// logoutRefusedAfterEnd refuses a page left open once the logout is over: the page
// says it, not "you stay connected" (LGO-16).
func (d *driver) logoutRefusedAfterEnd() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	end, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	late, err := d.answerLogout(p, "reject")
	if err != nil {
		return err
	}
	if !strings.Contains(late.Body, "déjà déconnecté") {
		return fmt.Errorf("LGO-16: %w", errUnexpected(late))
	}
	return d.loggedOut("hydra-sql")
}

// logoutOfClient is a logout asked by the client, id_token_hint and
// post_logout_redirect_uri: no page, the apps of the session, then back to the
// client with its state (LGO-8).
func (d *driver) logoutOfClient() error {
	if err := d.signedIn("hydra-sql-2fa"); err != nil {
		return err
	}
	const state = "e2e-logout-state"
	end, err := d.b.get(d.client.logoutURL(d.client.idToken, state))
	if err != nil {
		return err
	}
	if err := through(end, sqlLogout, tfaLogout); err != nil {
		return err
	}
	if !strings.HasPrefix(end.URL.String(), d.client.postLogout) || end.URL.Query().Get("state") != state {
		return fmt.Errorf("not back to the client with its state: %s", trail(end))
	}
	return d.loggedOut("hydra-sql")
}

// logoutOfClientDoubleClick follows that link twice before the browser leaves:
// Hydra makes two logout requests, the first's answer dropped. No app is passed:
// the browser was sent there under 15 s ago (DEP-4, Q46).
func (d *driver) logoutOfClientDoubleClick() error {
	if err := d.signedIn("hydra-sql-2fa"); err != nil {
		return err
	}
	link := d.client.logoutURL(d.client.idToken, "e2e-double-click")
	first, err := d.b.hop(link)
	if err != nil {
		return err
	}
	if _, err := d.b.hop(first.String()); err != nil {
		return fmt.Errorf("the first click: %w", err)
	}
	end, err := d.b.get(link)
	if err != nil {
		return err
	}
	if err := through(end, sqlLogout, tfaLogout); err != nil {
		return err
	}
	if end.URL.Query().Get("state") != "e2e-double-click" {
		return fmt.Errorf("not back to the client with its state: %s", trail(end))
	}
	return d.loggedOut("hydra-sql")
}

// logoutFormerIDToken logs in again with prompt=login, a new session, then asks
// for the logout with the id_token of the former: the cookie names another
// session, and the page asks (LGO-7, Q47). Refused, the current session lives.
func (d *driver) logoutFormerIDToken() error {
	if err := d.remembered(); err != nil {
		return err
	}
	former := d.client.idToken
	if err := d.signIn(login{flow: "hydra-sql", user: isabelle, consent: "accept", prompt: "login"}); err != nil {
		return fmt.Errorf("prompt=login: %w", err)
	}
	p, err := d.b.get(d.client.logoutURL(former, "e2e-former"))
	if err != nil {
		return err
	}
	if d.kind(p) != "logout" || !strings.Contains(p.Body, "autre session") {
		return fmt.Errorf("LGO-7: %w", errUnexpected(p))
	}
	refused, err := d.answerLogout(p, "reject")
	if err != nil {
		return err
	}
	if !strings.Contains(refused.Body, "restez connecté") {
		return fmt.Errorf("LGO-12: %w", errUnexpected(refused))
	}
	return d.honoured("refused")
}

// logoutFromAnotherSite posts the confirmation from another site, then without its
// token: E1008, and the session lives (LGO-9, LGO-10).
func (d *driver) logoutFromAnotherSite() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	f, _ := p.find("logout_challenge")
	v, err := f.values(nil, &pressed{"action", "accept"})
	if err != nil {
		return err
	}
	for _, tc := range []struct {
		name   string
		form   url.Values
		origin string
	}{
		{"another site", v, "http://evil.example"},
		{"no token", url.Values{"logout_challenge": v["logout_challenge"], "action": {"accept"}}, p.URL.Scheme + "://" + p.URL.Host},
	} {
		end, err := d.b.post(f.Action.String(), tc.form, tc.origin)
		if err != nil {
			return err
		}
		if code := errorCode.FindString(end.Body); code != "E1008" {
			return fmt.Errorf("%s: %q, want E1008: %w", tc.name, code, errUnexpected(end))
		}
	}
	return d.honoured("after a forged form")
}

// logoutWithoutMemory logs out of an hydra-oidc session in a browser that lost the
// cookie: the three apps of the configuration (LST-2), hydra-oidc through the
// end_session of its provider and back.
func (d *driver) logoutWithoutMemory() error {
	if err := d.signedIn("hydra-oidc"); err != nil {
		return err
	}
	d.b.forget(d.dispatcher, rememberCookie)
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	end, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	// The order of the snapshot, by id.
	if err := through(end, tfaLogout, oidcLogout, sqlLogout); err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	idp := slices.ContainsFunc(end.Trail, func(u *url.URL) bool {
		return u.Host != d.dispatcher.Host && u.Host != "oidc.hydra.test" && u.Host != "sql.hydra.test" && u.Host != "2fa.hydra.test" && u.Host != d.client.public.Host
	})
	callback := slices.ContainsFunc(end.Trail, func(u *url.URL) bool { return strings.HasPrefix(u.String(), oidcLogout+"/callback") })
	if !idp || !callback {
		return fmt.Errorf("hydra-oidc did not go through its provider's end_session: %s", trail(end))
	}
	return d.loggedOut("hydra-sql")
}

// logoutConsentInAnotherTab finishes a logout while a flow is at its consent in
// another tab, the session deleted under it: on 2.1, Hydra empties its
// login_session_id, and the dispatcher rejects it (CST-24); from 2.2 it cannot
// tell, and the client gets error=error at the verifier (HLO-15, Q55).
func (d *driver) logoutConsentInAnotherTab() error {
	if err := d.remembered(); err != nil {
		return err
	}
	d.b.forget(d.dispatcher, rememberCookie)
	p, err := d.start("consent")
	if err != nil {
		return err
	}
	// The skip ignored: the flow played again, to the screen, left there.
	for d.kind(p) != "consent" {
		switch d.kind(p) {
		case "choice":
			p, err = d.choose(p, "hydra-sql")
		case "hydra-sql":
			p, err = d.sqlLogin(p, isabelle)
		default:
			return fmt.Errorf("to the consent: %w", errUnexpected(p))
		}
		if err != nil {
			return err
		}
	}
	screen := p
	confirm, err := d.askLogout()
	if err != nil {
		return err
	}
	end, err := d.answerLogout(confirm, "accept")
	if err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	done, err := d.consentScreen(screen, "accept", 0)
	if err != nil {
		return err
	}
	if d.kind(done) != "callback" {
		return fmt.Errorf("the consent: %w", errUnexpected(done))
	}
	refused, err := d.client.callbackError(done.URL)
	if err != nil {
		return err
	}
	want := "error"
	if strings.HasPrefix(d.version, "v2.1") {
		want = "login_required"
	}
	if refused != want {
		return fmt.Errorf("callback error %q on %s, want %q", refused, d.version, want)
	}
	return nil
}

// stoppedChain signs in with two apps, and starts a logout the browser abandons at
// the logout_url of the first: an app that does not answer (browser.stopAt).
func (d *driver) stoppedChain() error {
	if err := d.signedIn("hydra-sql-2fa"); err != nil {
		return err
	}
	return d.stopChain()
}

func (d *driver) stopChain() error {
	d.b.stopAt = append(d.b.stopAt, sqlLogout)
	defer func() { d.b.stopAt = d.b.stopAt[:len(d.b.stopAt)-1] }()
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	stopped, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(stopped.URL.String(), sqlLogout) {
		return fmt.Errorf("the chain did not stop at hydra-sql: %s", trail(stopped))
	}
	_, err = d.noted("hydra-sql", "hydra-2fa")
	return err
}

// passDelay is how long after the browser was sent to an app a new demand passes
// it (Q46), plus a margin.
const passDelay = 15*time.Second + 500*time.Millisecond

// logoutChainStoppedPassed stops a chain at hydra-sql: a second demand under 15 s
// goes back there; past 15 s it passes it, and the logout ends (DEP-4, Q46).
func (d *driver) logoutChainStoppedPassed() error {
	if err := d.stoppedChain(); err != nil {
		return err
	}
	d.log.Info("waiting past the delay of a new demand", "for", passDelay)
	time.Sleep(passDelay)
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	end, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	if slices.ContainsFunc(end.Trail, func(u *url.URL) bool { return strings.HasPrefix(u.String(), sqlLogout) }) {
		return fmt.Errorf("hydra-sql not passed: %s", trail(end))
	}
	if err := through(end, tfaLogout); err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	return d.loggedOut("hydra-sql")
}

// listenBackChannel serves the logout tokens of a client with a back-channel.
func (d *driver) listenBackChannel(reach string) (func(), error) {
	u, err := url.Parse(reach)
	if err != nil || u.Port() == "" {
		return nil, fmt.Errorf("-back-channel: %q is not http://host:port", reach)
	}
	ln, err := net.Listen("tcp", ":"+u.Port())
	if err != nil {
		return nil, err
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { d.backChannelHits.Add(1) })}
	go func() { _ = srv.Serve(ln) }()
	d.backChannelURL = reach + "/logout"
	return func() { _ = srv.Close() }, nil
}

// logoutChainStoppedOtherSubject stops a chain, and the next authorization in this
// browser is someone else's: the session is deleted, which sends the back-channel,
// the authorization started again, the choice page, a code, without E1003 (SKP-12,
// HLO-18).
func (d *driver) logoutChainStoppedOtherSubject() error {
	if d.backChannelURL != "" {
		id, remove, err := d.client.backChannelClient(d.ctx, d.backChannelURL)
		if err != nil {
			return err
		}
		defer remove()
		former := d.client.id
		d.client.id = id
		defer func() { d.client.id = former }()
	}
	if err := d.stoppedChain(); err != nil {
		return err
	}
	session := d.client.idToken
	before := d.backChannelHits.Load()
	o, err := d.authorize(login{flow: "hydra-sql", user: henri, consent: "accept"})
	if err != nil {
		return err
	}
	if !o.saw("choice") || !o.saw("hydra-sql") {
		return fmt.Errorf("pages %v: want the choice page and the app", o.seen)
	}
	if d.kind(o.end) != "callback" {
		return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
	}
	claims, err := d.client.redeem(d.ctx, o.end.URL)
	if err != nil {
		return err
	}
	if err := (identity{Sub: henri}).check(claims); err != nil {
		return err
	}
	alive, err := d.client.sessionAlive(d.ctx, session)
	if err != nil {
		return err
	}
	if alive {
		return errors.New("SKP-12: the session is still in Hydra's base")
	}
	if d.backChannelURL == "" {
		d.note("back-channel not checked: no -back-channel")
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.backChannelHits.Load() == before && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if d.backChannelHits.Load() == before {
		return errors.New("SKP-12: no logout token on the back-channel")
	}
	return nil
}

// logoutChainStoppedFormerLogin stops a chain, and a login request read before the
// session was deleted comes back: it starts the authorization again, by SKP-12
// (2.2 and 2.3, which keep its session_id) or SKP-13 (2.1, which empties it).
func (d *driver) logoutChainStoppedFormerLogin() error {
	if err := d.stoppedChain(); err != nil {
		return err
	}
	// An L read in another tab, its load left unanswered, then this one.
	entry, err := d.b.hop(d.client.authURL(""))
	if err != nil {
		return err
	}
	state, nonce := d.client.state, d.client.nonce
	p, err := d.b.get(d.client.authURL(""))
	if err != nil {
		return err
	}
	if d.kind(p) != "choice" {
		return fmt.Errorf("SKP-12: %w", errUnexpected(p))
	}
	back, err := d.b.get(entry.String())
	if err != nil {
		return err
	}
	if d.kind(back) != "choice" || back.URL.Query().Get("login_challenge") == entry.Query().Get("login_challenge") {
		return fmt.Errorf("the former L: %w", errUnexpected(back))
	}
	// Started again from the request_url of the former L: its state and nonce.
	d.client.state, d.client.nonce = state, nonce
	o, err := d.drive(back, login{flow: "hydra-sql", user: isabelle, consent: "accept"})
	if err != nil {
		return err
	}
	return d.granted(o, identities["hydra-sql"])
}

// logoutChainStoppedPromptNone stops a chain, and an authorization that admits no
// page comes: the session deleted, Hydra answers login_required (SKP-12, HLO-18).
func (d *driver) logoutChainStoppedPromptNone() error {
	if err := d.stoppedChain(); err != nil {
		return err
	}
	p, err := d.start("none")
	if err != nil {
		return err
	}
	if d.kind(p) != "callback" {
		return fmt.Errorf("SKP-12 with prompt=none: %w", errUnexpected(p))
	}
	refused, err := d.client.callbackError(p.URL)
	if err != nil {
		return err
	}
	if refused != "login_required" {
		return fmt.Errorf("callback error %q, want login_required", refused)
	}
	return nil
}

// signOutLink is the way out of page E1003 (FIN-3, Q60).
var signOutLink = regexp.MustCompile(`href="([^"]*/oauth2/sessions/logout)"`)

// logoutChainStoppedOtherSession stops the chain of a former session, the question
// of LGO-7 answered yes: the note names that session, and Hydra's cookie another, so
// SKP-12 has nothing to delete. Someone else gets E1003, each time; its link goes
// through the question and the chain, then that person signs in (Q60).
func (d *driver) logoutChainStoppedOtherSession() error {
	if err := d.remembered(); err != nil {
		return err
	}
	former := d.client.idToken
	if err := d.signIn(login{flow: "hydra-sql", user: isabelle, consent: "accept", prompt: "login"}); err != nil {
		return fmt.Errorf("prompt=login: %w", err)
	}
	d.b.stopAt = append(d.b.stopAt, sqlLogout)
	p, err := d.b.get(d.client.logoutURL(former, "e2e-other-session"))
	if err != nil {
		return err
	}
	if d.kind(p) != "logout" || !strings.Contains(p.Body, "autre session") {
		return fmt.Errorf("LGO-7: %w", errUnexpected(p))
	}
	stopped, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	d.b.stopAt = d.b.stopAt[:len(d.b.stopAt)-1]
	if !strings.HasPrefix(stopped.URL.String(), sqlLogout) {
		return fmt.Errorf("the chain did not stop at hydra-sql: %s", trail(stopped))
	}
	o, err := d.authorize(login{flow: "hydra-sql", user: henri, consent: "accept"})
	if err != nil {
		return err
	}
	if o.code != "E1003" {
		return fmt.Errorf("FIN-3: pages %v, code %q: want E1003", o.seen, o.code)
	}
	link := signOutLink.FindStringSubmatch(o.end.Body)
	if link == nil {
		return fmt.Errorf("Q60, no way out: %w", errUnexpected(o.end))
	}
	confirm, err := d.b.get(html.UnescapeString(link[1]))
	if err != nil {
		return err
	}
	if d.kind(confirm) != "logout" {
		return fmt.Errorf("Q60, the link asks first: %w", errUnexpected(confirm))
	}
	end, err := d.answerLogout(confirm, "accept")
	if err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	o, err = d.authorize(login{flow: "hydra-sql", user: henri, consent: "accept"})
	if err != nil {
		return err
	}
	if d.kind(o.end) != "callback" {
		return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
	}
	claims, err := d.client.redeem(d.ctx, o.end.URL)
	if err != nil {
		return err
	}
	return (identity{Sub: henri}).check(claims)
}

// logoutAppsAnswers plays what the real apps do of the emulated API's answers: the
// logout_url of a step past, reloaded, sends on (LEM-6, hydra-sql); a challenge
// unknown or another app's never sends the browser to the chain, and the chain goes on
// from where it was (LEM-2, LEM-3, LEM-4).
func (d *driver) logoutAppsAnswers() error {
	if err := d.signedIn("hydra-sql-2fa"); err != nil {
		return err
	}
	d.b.stopAt = append(d.b.stopAt, tfaLogout)
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	stopped, err := d.answerLogout(p, "accept")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(stopped.URL.String(), tfaLogout) {
		return fmt.Errorf("the chain did not stop at hydra-2fa: %s", trail(stopped))
	}
	var past string
	for _, u := range stopped.Trail {
		if strings.HasPrefix(u.String(), sqlLogout) {
			past = u.Query().Get("logout_challenge")
		}
	}
	again, err := d.b.get(sqlLogout + "?logout_challenge=" + past)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(again.URL.String(), tfaLogout) {
		return fmt.Errorf("LEM-6, hydra-sql reloaded: %s", trail(again))
	}
	current := stopped.URL.Query().Get("logout_challenge")
	unknown := "00000000-0000-0000-0000-000000000000"
	noFollow := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, tc := range []struct{ name, url string }{
		{"LEM-2 at hydra-sql", sqlLogout + "?logout_challenge=" + unknown},
		{"LEM-2 at hydra-oidc", oidcLogout + "?logout_challenge=" + unknown},
		{"LEM-2 at hydra-2fa", tfaLogout + "?logout_challenge=" + unknown},
		{"LEM-3 a signature forged, at hydra-sql", sqlLogout + "?logout_challenge=" + current[:24] + "000000000000"},
		{"LEM-4 hydra-2fa's at hydra-sql", sqlLogout + "?logout_challenge=" + current},
		{"LEM-4 hydra-sql's at hydra-oidc", oidcLogout + "?logout_challenge=" + past},
		{"LEM-4 hydra-sql's at hydra-2fa", tfaLogout + "?logout_challenge=" + past},
	} {
		resp, err := noFollow.Get(tc.url)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if loc := resp.Header.Get("Location"); resp.StatusCode < 300 || strings.Contains(loc, "/logout/next") {
			return fmt.Errorf("%s: %d to %q: the chain answered", tc.name, resp.StatusCode, loc)
		}
	}
	d.b.stopAt = d.b.stopAt[:len(d.b.stopAt)-1]
	end, err := d.b.get(stopped.URL.String())
	if err != nil {
		return err
	}
	if err := endsOnVerifier(end); err != nil {
		return err
	}
	return d.loggedOut("hydra-sql")
}

// logoutPreloadHeadLocale goes around the logout without leaving it: a HEAD (LGO-17),
// a browser's preload of a client's link (LGO-18, Q59), a change of language on the
// question: nothing ends, nothing is written, and the skip stays. The link then
// followed does end the session.
func (d *driver) logoutPreloadHeadLocale() error {
	if err := d.signedIn("hydra-sql"); err != nil {
		return err
	}
	memory := d.b.cookie(d.dispatcher, rememberCookie)
	p, err := d.askLogout()
	if err != nil {
		return err
	}
	status, err := d.b.preload(http.MethodHead, p.URL.String(), "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("LGO-17: %d", status)
	}
	back, err := d.b.post(d.dispatcher.String()+"/locale/en", url.Values{"return": {p.URL.RequestURI()}}, d.dispatcher.Scheme+"://"+d.dispatcher.Host)
	if err != nil {
		return err
	}
	if d.kind(back) != "logout" || !strings.Contains(back.Body, "Do you want to sign out") {
		return fmt.Errorf("the change of language: %w", errUnexpected(back))
	}
	link := d.client.logoutURL(d.client.idToken, "e2e-preload")
	first, err := d.b.hop(link)
	if err != nil {
		return err
	}
	for _, purpose := range []string{"prefetch", "prefetch;prerender"} {
		status, err := d.b.preload(http.MethodGet, first.String(), purpose)
		if err != nil {
			return err
		}
		if status != http.StatusServiceUnavailable {
			return fmt.Errorf("LGO-18, %s: %d, want 503", purpose, status)
		}
	}
	if d.b.cookie(d.dispatcher, rememberCookie) != memory {
		return errors.New("LGO-17, LGO-18: the cookie changed")
	}
	if err := d.honoured("after a preload"); err != nil {
		return err
	}
	end, err := d.b.get(link)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(end.URL.String(), d.client.postLogout) || end.URL.Query().Get("state") != "e2e-preload" {
		return fmt.Errorf("the link followed: %s", trail(end))
	}
	return d.loggedOut("hydra-sql")
}

// promptConsent signs in with hydra-sql and prompt=consent: the dispatcher's
// consent screen, whatever Hydra remembers, then button pressed.
func promptConsent(button string) func(*driver) error {
	return func(d *driver) error {
		o, err := d.authorize(login{flow: "hydra-sql", user: isabelle, consent: button, prompt: "consent"})
		if err != nil {
			return err
		}
		if !o.saw("consent") {
			return fmt.Errorf("no consent screen with prompt=consent: %v", o.seen)
		}
		if button == "accept" {
			return d.granted(o, identities["hydra-sql"])
		}
		if d.kind(o.end) != "callback" {
			return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
		}
		refused, err := d.client.callbackError(o.end.URL)
		if err != nil {
			return err
		}
		if refused != "access_denied" {
			return fmt.Errorf("callback error %q, want access_denied", refused)
		}
		return nil
	}
}

// backToChoice goes back to the choice page twice before signing in: from
// the browser's history, posting the choice form again (POS-4), then by
// reloading the choice page (ENT-3). Both flows start with hydra-sql: the
// step challenge, new in the generation POS-4 starts, tells them apart.
func (d *driver) backToChoice() error {
	choice, err := d.start("")
	if err != nil {
		return err
	}
	if d.kind(choice) != "choice" {
		return fmt.Errorf("no choice page: %w", errUnexpected(choice))
	}
	var challenges []string
	for _, flow := range []string{"hydra-sql", "hydra-sql-2fa"} {
		p, err := d.choose(choice, flow)
		if err != nil {
			return err
		}
		if d.kind(p) != "hydra-sql" {
			return fmt.Errorf("%s chosen: %w", flow, errUnexpected(p))
		}
		challenges = append(challenges, p.URL.Query().Get("login_challenge"))
	}
	// Symfony's step challenges are its own business (-symfony checks the
	// subject only).
	if !d.symfony && (challenges[0] == "" || challenges[1] == challenges[0]) {
		return fmt.Errorf("the choice form posted again from the history: step challenge %q, then %q; want a new one (POS-4)", challenges[0], challenges[1])
	}
	p, err := d.b.get(choice.URL.String())
	if err != nil {
		return err
	}
	if d.kind(p) != "choice" {
		return fmt.Errorf("choice page reloaded: %w", errUnexpected(p))
	}
	o, err := d.drive(p, login{flow: "hydra-oidc", consent: "accept"})
	if err != nil {
		return err
	}
	return d.granted(o, identities["hydra-oidc"])
}

// backToSQL2FA chooses hydra-sql, goes back to the choice page in the
// browser's history and chooses hydra-sql-2fa from it, then accepts the
// consent screen, which prompt=consent shows whatever Hydra remembers: two
// steps and the screen, the path of Symfony's capture 05.
func (d *driver) backToSQL2FA() error {
	choice, err := d.start("consent")
	if err != nil {
		return err
	}
	if d.kind(choice) != "choice" {
		return fmt.Errorf("no choice page: %w", errUnexpected(choice))
	}
	p, err := d.choose(choice, "hydra-sql")
	if err != nil {
		return err
	}
	if d.kind(p) != "hydra-sql" {
		return fmt.Errorf("hydra-sql chosen: %w", errUnexpected(p))
	}
	l := login{flow: "hydra-sql-2fa", user: isabelle, consent: "accept"}
	o, err := d.drive(choice, l)
	if err != nil {
		return err
	}
	if !o.saw("consent") || !o.saw("hydra-2fa") {
		return fmt.Errorf("pages %v, want both steps and the consent screen", o.seen)
	}
	return d.granted(o, identities[l.flow])
}

// expiredOnConsent stays on the consent screen past the flow's lifetime
// (challenge_ttl, lowered in the seed beforehand), then accepts. The flow is
// accepted on Hydra already: the dispatcher rejects the consent, and the
// client gets login_required, on Hydra 2.1 as on 2.2 (CST-22, Q31).
func (d *driver) expiredOnConsent() error {
	if d.wait <= 0 {
		return errors.New("needs -wait, longer than the challenge_ttl of the seed")
	}
	o, err := d.authorize(login{flow: "hydra-sql", user: isabelle, consent: "accept", waitOnConsent: d.wait, prompt: "consent"})
	if err != nil {
		return err
	}
	if !o.saw("consent") {
		return fmt.Errorf("no consent screen with prompt=consent: %v", o.seen)
	}
	if d.kind(o.end) != "callback" {
		return fmt.Errorf("%w: pages %v, ended on %s %s", errNoCallback, o.seen, o.code, endURL(o))
	}
	refused, err := d.client.callbackError(o.end.URL)
	if err != nil {
		return err
	}
	if refused != "login_required" {
		return fmt.Errorf("callback error %q, want login_required", refused)
	}
	return nil
}
