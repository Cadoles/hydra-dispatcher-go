// Command flowfixtures records golden fixtures from a running Hydra, each set
// in a hydra-<version> directory named after the version Hydra reports:
//
//   - with -out, for internal/hydra/flowcodec (Hydra 2.2 or later): a login
//     challenge and a consent challenge, each with the admin API response
//     Hydra serves for it. It starts an authorization request, accepts the
//     login through the admin API with a known subject and context, and stops
//     at the consent challenge.
//   - with -errors, for internal/hydra (any Hydra 2.x): Hydra's answers to
//     unknown, tampered, handled, refused and expired login, consent and
//     logout requests, one JSON file per exchange, whatever the status.
//
// Hydra's secrets.system must be the tests' devSecret and the client must
// accept -redirect. Against hydra-dev (make up-hydra22):
//
//	go run ./tools/flowfixtures -client <client_id> -out internal/hydra/flowcodec/testdata
//
// Against a throwaway Hydra of another version, here with a request lifetime
// short enough for -ttl to record the expired cases:
//
//	docker run --rm -d --name hydra -p 4444:4444 -p 4445:4445 -e DSN=memory \
//	  -e SECRETS_SYSTEM=youReallyNeedToChangeThis -e URLS_SELF_ISSUER=http://127.0.0.1:4444 \
//	  -e URLS_LOGIN=http://login.test/login -e URLS_CONSENT=http://login.test/consent \
//	  -e URLS_LOGOUT=http://login.test/logout -e TTL_LOGIN_CONSENT_REQUEST=5s \
//	  oryd/hydra:v2.3.0 serve all --dev
//	docker exec hydra hydra create client --endpoint http://127.0.0.1:4445 --name "OIDC Test Client" \
//	  --redirect-uri http://oidc.client.test/auth/callback --scope openid,profile,email
//	go run ./tools/flowfixtures -public http://127.0.0.1:4444 -admin http://127.0.0.1:4445 \
//	  -client <client_id> -out internal/hydra/flowcodec/testdata \
//	  -errors internal/hydra/testdata/errors -ttl 5s
package main

import (
	"bytes"
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
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Values the flowcodec tests expect to find back in the decrypted flows.
const (
	subject = "alice"
	state   = "flowfixtures-state-0123456789"
	nonce   = "flowfixtures-nonce-0123456789"
)

var loginContext = map[string]any{"fixture": "flowfixtures", "step": 1}

// release is a Hydra release version, safe as a directory name.
var release = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// Admin API paths of the login, consent and logout requests.
const (
	loginPath   = "/admin/oauth2/auth/requests/login"
	consentPath = "/admin/oauth2/auth/requests/consent"
	logoutPath  = "/admin/oauth2/auth/requests/logout"
)

type fixtures struct {
	public, admin *url.URL
	http          *http.Client
	out, errors   string
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	public := flag.String("public", "http://public.hydra.test", "Hydra public URL")
	admin := flag.String("admin", "http://admin.hydra.test", "Hydra admin URL")
	client := flag.String("client", "", "OAuth2 client id registered in Hydra")
	redirect := flag.String("redirect", "http://oidc.client.test/auth/callback", "redirect_uri registered for the client")
	out := flag.String("out", "", "flowcodec testdata directory, which receives hydra-<version> (Hydra 2.2 or later)")
	errDir := flag.String("errors", "", "error fixtures directory, which receives hydra-<version>")
	ttl := flag.Duration("ttl", 0, "Hydra's ttl.login_consent_request, when short enough to wait out: records the expired cases (0 skips them)")
	flag.Parse()
	if *client == "" || (*out == "" && *errDir == "") {
		flag.Usage()
		return errors.New("-client, and -out or -errors, are required")
	}

	f := &fixtures{}
	var err error
	if f.public, err = url.Parse(*public); err != nil {
		return err
	}
	if f.admin, err = url.Parse(*admin); err != nil {
		return err
	}
	jar, _ := cookiejar.New(nil)
	f.http = &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		// Each redirect is a step to inspect, not to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	version, err := f.hydraVersion()
	if err != nil {
		return err
	}
	if *out != "" {
		if strings.HasPrefix(version, "v2.1.") {
			return fmt.Errorf("-out needs Hydra 2.2 or later: %s does not encrypt its challenges", version)
		}
		f.out = filepath.Join(*out, "hydra-"+version)
		if err := os.MkdirAll(f.out, 0o755); err != nil {
			return err
		}
	}
	if *errDir != "" {
		f.errors = filepath.Join(*errDir, "hydra-"+version)
		if err := os.MkdirAll(f.errors, 0o755); err != nil {
			return err
		}
	}

	auth := f.public.JoinPath("/oauth2/auth")
	auth.RawQuery = url.Values{
		"client_id":     {*client},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"redirect_uri":  {*redirect},
		"state":         {state},
		"nonce":         {nonce},
		"ui_locales":    {"fr en"},
	}.Encode()
	if f.out != "" {
		if err := f.recordChallenges(auth.String()); err != nil {
			return err
		}
		slog.Info("fixtures written", "dir", f.out)
	}
	if f.errors != "" {
		if err := f.recordErrors(auth.String(), *ttl); err != nil {
			return err
		}
		slog.Info("error fixtures written", "dir", f.errors)
	}
	return nil
}

// recordChallenges saves a login challenge and a consent challenge for
// flowcodec, each with the request the admin API serves for it.
func (f *fixtures) recordChallenges(auth string) error {
	loginChallenge, err := f.challengeFrom(auth, "login_challenge")
	if err != nil {
		return err
	}
	if err := f.save("login_challenge.txt", []byte(loginChallenge)); err != nil {
		return err
	}
	if _, err := f.adminCall(http.MethodGet, loginPath, "login_challenge", loginChallenge, nil, "login_request.json"); err != nil {
		return err
	}

	consentChallenge, err := f.acceptLogin(loginChallenge,
		jsonBody(map[string]any{"subject": subject, "remember": false, "acr": "fixture-acr", "amr": []string{"pwd"}, "context": loginContext}))
	if err != nil {
		return err
	}
	if err := f.save("consent_challenge.txt", []byte(consentChallenge)); err != nil {
		return err
	}
	_, err = f.adminCall(http.MethodGet, consentPath, "consent_challenge", consentChallenge, nil, "consent_request.json")
	return err
}

// recordErrors provokes Hydra's answers to unknown, tampered, handled, refused
// and expired requests, and saves each exchange.
func (f *fixtures) recordErrors(auth string, ttl time.Duration) error {
	const unknown = "00000000000000000000000000000000"
	loginAccept := jsonBody(map[string]any{"subject": subject, "remember": true, "amr": []string{"pwd"}})
	consentAccept := jsonBody(map[string]any{
		"grant_scope": []string{"openid", "profile", "email"},
		"remember":    true,
		"session":     map[string]any{"id_token": map[string]any{"email": "alice@example.com"}},
	})
	reject := jsonBody(map[string]any{"error": "access_denied"})
	get, put := http.MethodGet, http.MethodPut

	if err := f.recordAll(
		call{"login_unknown", get, loginPath, "login_challenge", unknown, nil},
		call{"consent_unknown", get, consentPath, "consent_challenge", unknown, nil},
		call{"logout_unknown", get, logoutPath, "logout_challenge", unknown, nil},
	); err != nil {
		return err
	}

	// A login and its consent, both remembered: the session cookie in the
	// jar makes the next login a skip. The login verifier is used at once
	// (acceptLogin follows it); the consent is first recorded accepted, its
	// verifier unused, then used.
	login, err := f.challengeFrom(auth, "login_challenge")
	if err != nil {
		return err
	}
	consent, err := f.acceptLogin(login, loginAccept)
	if err != nil {
		return err
	}
	if err := f.recordAll(
		call{"login_tampered", get, loginPath, "login_challenge", tamper(login), nil},
		call{"login_used", get, loginPath, "login_challenge", login, nil},
	); err != nil {
		return err
	}
	loginAgain, err := f.record(call{"login_accept_used", put, loginPath + "/accept", "login_challenge", login, loginAccept})
	if err != nil {
		return err
	}
	if err := f.recordAll(
		call{"login_reject_used", put, loginPath + "/reject", "login_challenge", login, reject},
		call{"consent_tampered", get, consentPath, "consent_challenge", tamper(consent), nil},
	); err != nil {
		return err
	}
	done, err := f.acceptConsent(consent, consentAccept)
	if err != nil {
		return err
	}
	if err := f.recordAll(call{"consent_accepted", get, consentPath, "consent_challenge", consent, nil}); err != nil {
		return err
	}
	consentAgain, err := f.record(call{"consent_accept_accepted", put, consentPath + "/accept", "consent_challenge", consent, consentAccept})
	if err != nil {
		return err
	}
	if _, err := f.visit(done); err != nil {
		return err
	}
	if err := f.recordAll(
		call{"consent_used", get, consentPath, "consent_challenge", consent, nil},
		call{"consent_accept_used", put, consentPath + "/accept", "consent_challenge", consent, consentAccept},
		call{"consent_reject_used", put, consentPath + "/reject", "consent_challenge", consent, reject},
	); err != nil {
		return err
	}
	// The verifiers of the second accepts, once the first ones are used:
	// what stops a double submission when the admin API accepts it again.
	if err := f.recordReplay("login_verifier_replayed", loginAgain); err != nil {
		return err
	}
	if err := f.recordReplay("consent_verifier_replayed", consentAgain); err != nil {
		return err
	}

	skip, err := f.challengeFrom(auth, "login_challenge")
	if err != nil {
		return err
	}
	if err := f.recordAll(
		call{"login_skip", get, loginPath, "login_challenge", skip, nil},
		call{"login_bad_body", put, loginPath + "/accept", "login_challenge", skip, []byte(`{"subject":1}`)},
	); err != nil {
		return err
	}
	otherSubject, err := f.record(call{"login_other_subject", put, loginPath + "/accept", "login_challenge", skip, jsonBody(map[string]any{"subject": "bob"})})
	if err != nil {
		return err
	}
	// Where Hydra stops a skip accepted with another subject, when the
	// admin API takes it.
	if err := f.recordReplay("login_other_subject_verifier", otherSubject); err != nil {
		return err
	}

	logout, err := f.challengeFrom(f.public.JoinPath("/oauth2/sessions/logout").String(), "logout_challenge")
	if err != nil {
		return err
	}
	if _, err := f.adminCall(put, logoutPath+"/accept", "logout_challenge", logout, nil, ""); err != nil {
		return err
	}
	if err := f.recordAll(
		call{"logout_handled", get, logoutPath, "logout_challenge", logout, nil},
		call{"logout_accept_again", put, logoutPath + "/accept", "logout_challenge", logout, nil},
	); err != nil {
		return err
	}

	if ttl <= 0 {
		slog.Info("expired cases skipped: no -ttl")
		return nil
	}
	pendingLogin, err := f.challengeFrom(auth, "login_challenge")
	if err != nil {
		return err
	}
	second, err := f.challengeFrom(auth, "login_challenge")
	if err != nil {
		return err
	}
	pendingConsent, err := f.acceptLogin(second, loginAccept)
	if err != nil {
		return err
	}
	slog.Info("waiting for the requests to expire", "ttl", ttl)
	time.Sleep(ttl + 2*time.Second)
	return f.recordAll(
		call{"login_expired", get, loginPath, "login_challenge", pendingLogin, nil},
		call{"login_expired_accept", put, loginPath + "/accept", "login_challenge", pendingLogin, loginAccept},
		call{"consent_expired", get, consentPath, "consent_challenge", pendingConsent, nil},
		call{"consent_expired_accept", put, consentPath + "/accept", "consent_challenge", pendingConsent, consentAccept},
	)
}

// call is one admin API exchange to record under name.
type call struct {
	name, method, path, param, challenge string
	body                                 []byte
}

func (f *fixtures) recordAll(calls ...call) error {
	for _, c := range calls {
		if _, err := f.record(c); err != nil {
			return err
		}
	}
	return nil
}

// exchange is the file an error fixture holds.
type exchange struct {
	Request struct {
		Method string `json:"method"`
		// URI is the path and the challenge parameter, without the
		// challenge: a value of the run, kilobytes long from Hydra 2.2.
		URI  string          `json:"uri"`
		Body json.RawMessage `json:"body,omitempty"`
	} `json:"request"`
	Response struct {
		Status      int    `json:"status"`
		ContentType string `json:"content_type"`
		// Location is where a redirect sends the browser: path and the
		// error parameters only, the others' values elided.
		Location string `json:"location,omitempty"`
		// Body is Hydra's JSON as served, re-indented, or a JSON string for
		// anything else.
		Body json.RawMessage `json:"body"`
	} `json:"response"`
}

// record makes one admin API call, saves the exchange as <name>.json,
// whatever Hydra answered, and returns the response body.
func (f *fixtures) record(c call) ([]byte, error) {
	status, contentType, data, err := f.adminRaw(c.method, c.path, c.param, c.challenge, c.body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.name, err)
	}
	var ex exchange
	ex.Request.Method = c.method
	ex.Request.URI = c.path + "?" + c.param + "=<challenge>"
	if c.body != nil {
		ex.Request.Body = asJSON(c.body)
	}
	ex.Response.Status = status
	ex.Response.ContentType = contentType
	ex.Response.Body = asJSON(data)
	return data, f.saveExchange(c.name, ex)
}

// recordReplay follows the redirect_to of an accept that should have been
// refused, as the browser would, and saves where Hydra sends it. An accept
// that was refused leaves nothing to follow.
func (f *fixtures) recordReplay(name string, accepted []byte) error {
	to, err := redirectTo(accepted, name)
	if err != nil {
		slog.Info("nothing to replay", "case", name)
		return nil
	}
	u, err := url.Parse(to)
	if err != nil {
		return err
	}
	resp, err := f.http.Get(to)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	var ex exchange
	ex.Request.Method = http.MethodGet
	ex.Request.URI = u.Path + "?" + elide(u.Query())
	ex.Response.Status = resp.StatusCode
	ex.Response.ContentType = resp.Header.Get("Content-Type")
	if loc, err := resp.Location(); err == nil {
		ex.Response.Location = loc.Path + "?" + elide(loc.Query())
		data = nil // the redirect's HTML repeats the location, values included
	}
	ex.Response.Body = asJSON(data)
	return f.saveExchange(name, ex)
}

// elide keeps Hydra's error parameters and replaces the other values, which
// hold verifiers, codes and state.
func elide(q url.Values) string {
	for k := range q {
		switch k {
		case "error", "error_description", "error_hint":
		default:
			q[k] = []string{"<" + k + ">"}
		}
	}
	return strings.NewReplacer("%3C", "<", "%3E", ">").Replace(q.Encode())
}

func (f *fixtures) saveExchange(name string, ex exchange) error {
	b, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	slog.Info("recorded", "case", name, "status", ex.Response.Status)
	return os.WriteFile(filepath.Join(f.errors, name+".json"), append(b, '\n'), 0o644)
}

// asJSON keeps a JSON body as it is and quotes anything else.
func asJSON(b []byte) json.RawMessage {
	if json.Valid(b) {
		return b
	}
	quoted, _ := json.Marshal(string(b))
	return quoted
}

// jsonBody encodes a request body built from maps and slices, which cannot fail.
func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// tamper changes one character in the middle of a challenge: still well
// formed, hexadecimal or base64, but no longer Hydra's.
func tamper(challenge string) string {
	b := []byte(challenge)
	i := len(b) / 2
	if b[i] == '0' {
		b[i] = '1'
	} else {
		b[i] = '0'
	}
	return string(b)
}

// hydraVersion reads the release Hydra reports, which names the fixtures.
func (f *fixtures) hydraVersion() (string, error) {
	resp, err := f.http.Get(f.admin.JoinPath("/version").String())
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var v struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil || !release.MatchString(v.Version) {
		return "", fmt.Errorf("GET /version: status %d, no release version (%q)", resp.StatusCode, v.Version)
	}
	return v.Version, nil
}

// acceptLogin accepts a login with body and returns the consent challenge
// Hydra redirects to.
func (f *fixtures) acceptLogin(challenge string, body []byte) (string, error) {
	accepted, err := f.adminCall(http.MethodPut, loginPath+"/accept", "login_challenge", challenge, body, "")
	if err != nil {
		return "", err
	}
	to, err := redirectTo(accepted, "login accept")
	if err != nil {
		return "", err
	}
	return f.challengeFrom(to, "consent_challenge")
}

// acceptConsent accepts a consent with body and returns where Hydra sends the
// browser next.
func (f *fixtures) acceptConsent(challenge string, body []byte) (string, error) {
	accepted, err := f.adminCall(http.MethodPut, consentPath+"/accept", "consent_challenge", challenge, body, "")
	if err != nil {
		return "", err
	}
	return redirectTo(accepted, "consent accept")
}

func redirectTo(accepted []byte, what string) (string, error) {
	var r struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(accepted, &r); err != nil || r.RedirectTo == "" {
		return "", fmt.Errorf("%s: no redirect_to in %s", what, accepted)
	}
	return r.RedirectTo, nil
}

// visit requests u as a browser following a redirect, and returns where
// Hydra sends it next.
func (f *fixtures) visit(u string) (*url.URL, error) {
	resp, err := f.http.Get(u)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("GET %s: status %d, no redirect", u, resp.StatusCode)
	}
	return loc, nil
}

// challengeFrom requests u and reads the named challenge from the redirect.
func (f *fixtures) challengeFrom(u, param string) (string, error) {
	loc, err := f.visit(u)
	if err != nil {
		return "", err
	}
	ch := loc.Query().Get(param)
	if ch == "" {
		return "", fmt.Errorf("GET %s: redirect %s has no %s", u, loc, param)
	}
	return ch, nil
}

// adminRaw calls the admin API and returns Hydra's answer, whatever its status.
func (f *fixtures) adminRaw(method, path, param, challenge string, body []byte) (int, string, []byte, error) {
	u := f.admin.JoinPath(path)
	u.RawQuery = url.Values{param: {challenge}}.Encode()
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), data, err
}

// adminCall calls the admin API, fails on anything but 200 and, when file is
// set, saves the indented response.
func (f *fixtures) adminCall(method, path, param, challenge string, body []byte, file string) ([]byte, error) {
	status, _, data, err := f.adminRaw(method, path, param, challenge, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s %s: status %d: %s", method, path, status, strings.TrimSpace(string(data)))
	}
	if file != "" {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			return nil, err
		}
		if err := f.save(file, pretty.Bytes()); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (f *fixtures) save(name string, data []byte) error {
	return os.WriteFile(filepath.Join(f.out, name), append(data, '\n'), 0o644)
}
