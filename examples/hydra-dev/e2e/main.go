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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

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
	{name: "second-login-other-subject", run: (*driver).secondLoginOtherSubject},
	{name: "second-login-prompt-consent-reject", run: (*driver).secondLoginPromptConsentReject},
	{name: "second-login-reload", run: (*driver).secondLoginReload},
	{name: "logout", run: (*driver).logout},
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
	password := flag.String("password", "123456", "password of hydra-sql's accounts")
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
		client:     &client{public: urls["public"], admin: urls["admin"], id: *clientID, secret: *secret, redirect: *redirect, http: httpc},
		mail:       mailbox{base: urls["smtp"], http: httpc},
		pages:      goPages,
		password:   *password,
		wait:       *wait,
	}
	if *symfony {
		d.pages, d.symfony = symfonyPages, true
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
	d.b.forget(d.dispatcher, rememberCookie, rememberCookie+"_2")
	o, err := d.skippedLogin(l)
	if err != nil {
		return err
	}
	if !o.saw("choice") || !o.saw("hydra-sql") {
		return fmt.Errorf("skip not ignored: pages %v", o.seen)
	}
	return d.granted(o, identities["hydra-sql"])
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
	d.b.forget(d.dispatcher, rememberCookie, rememberCookie+"_2")
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

// logout signs in, then out on Hydra, which goes through the dispatcher's
// logout: the memory of the skip is cleared (WRT-4, Q41), and the next
// authorization, without a session at Hydra, shows the choice page.
func (d *driver) logout() error {
	if err := d.remembered(); err != nil {
		return err
	}
	p, err := d.b.get(d.client.public.JoinPath("/oauth2/sessions/logout").String())
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(p.Trail, func(u *url.URL) bool { return u.Host == d.dispatcher.Host && u.Path == "/logout" }) {
		return fmt.Errorf("the logout went without the dispatcher: %s", trail(p))
	}
	if d.b.has(d.dispatcher, rememberCookie) {
		return fmt.Errorf("WRT-4: %s kept after the logout", rememberCookie)
	}
	o, err := d.authorize(login{flow: "hydra-sql", user: isabelle, consent: "accept"})
	if err != nil {
		return err
	}
	if !o.saw("choice") || !o.saw("hydra-sql") {
		return fmt.Errorf("after the logout, pages %v: want the choice page and the app", o.seen)
	}
	return d.granted(o, identities["hydra-sql"])
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
