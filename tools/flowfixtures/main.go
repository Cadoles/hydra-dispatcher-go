// Command flowfixtures records golden fixtures for internal/hydra/flowcodec
// from a running Hydra 2.2: a login challenge and a consent challenge, each
// with the admin API response Hydra serves for it. It starts an authorization
// request, accepts the login through the admin API with a known subject and
// context, and stops at the consent challenge.
//
//	go run ./tools/flowfixtures -client <client_id> -out internal/hydra/flowcodec/testdata/hydra-v2.2.0
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

type fixtures struct {
	public, admin *url.URL
	http          *http.Client
	out           string
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
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *client == "" || *out == "" {
		flag.Usage()
		return errors.New("-client and -out are required")
	}

	f := &fixtures{out: *out}
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
	if err := os.MkdirAll(f.out, 0o755); err != nil {
		return err
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
	loginChallenge, err := f.challengeFrom(auth.String(), "login_challenge")
	if err != nil {
		return err
	}
	if err := f.save("login_challenge.txt", []byte(loginChallenge)); err != nil {
		return err
	}
	if _, err := f.adminCall(http.MethodGet, "/admin/oauth2/auth/requests/login", "login_challenge", loginChallenge, nil, "login_request.json"); err != nil {
		return err
	}

	accepted, err := f.adminCall(http.MethodPut, "/admin/oauth2/auth/requests/login/accept", "login_challenge", loginChallenge,
		map[string]any{"subject": subject, "remember": false, "acr": "fixture-acr", "amr": []string{"pwd"}, "context": loginContext}, "")
	if err != nil {
		return err
	}
	var redirectTo struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(accepted, &redirectTo); err != nil || redirectTo.RedirectTo == "" {
		return fmt.Errorf("login accept: no redirect_to in %s", accepted)
	}

	consentChallenge, err := f.challengeFrom(redirectTo.RedirectTo, "consent_challenge")
	if err != nil {
		return err
	}
	if err := f.save("consent_challenge.txt", []byte(consentChallenge)); err != nil {
		return err
	}
	if _, err := f.adminCall(http.MethodGet, "/admin/oauth2/auth/requests/consent", "consent_challenge", consentChallenge, nil, "consent_request.json"); err != nil {
		return err
	}
	slog.Info("fixtures written", "dir", f.out)
	return nil
}

// challengeFrom requests u and reads the named challenge from the redirect.
func (f *fixtures) challengeFrom(u, param string) (string, error) {
	resp, err := f.http.Get(u)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("GET %s: status %d, no redirect", u, resp.StatusCode)
	}
	ch := loc.Query().Get(param)
	if ch == "" {
		return "", fmt.Errorf("GET %s: redirect %s has no %s", u, loc, param)
	}
	return ch, nil
}

// adminCall calls the admin API and, when file is set, saves the indented response.
func (f *fixtures) adminCall(method, path, param, challenge string, body any, file string) ([]byte, error) {
	u := f.admin.JoinPath(path)
	u.RawQuery = url.Values{param: {challenge}}.Encode()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
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
