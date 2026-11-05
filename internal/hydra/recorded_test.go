package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
)

// recordedExchange is an error fixture of tools/flowfixtures: one call and
// Hydra's answer.
type recordedExchange struct {
	Request struct {
		Method string `json:"method"`
		URI    string `json:"uri"`
	} `json:"request"`
	Response struct {
		Status      int             `json:"status"`
		ContentType string          `json:"content_type"`
		Body        json.RawMessage `json:"body"`
	} `json:"response"`
}

// served is the body as Hydra sent it: its JSON as recorded, anything else
// recorded as a JSON string.
func (e recordedExchange) served() []byte {
	var s string
	if err := json.Unmarshal(e.Response.Body, &s); err == nil {
		return []byte(s)
	}
	return e.Response.Body
}

// Hydra's own answers to unknown, tampered, handled, refused and expired
// requests, recorded against Hydra 2.1, 2.2 and 2.3: a 4xx is a RequestError
// carrying Hydra's body as sent, a 410 its redirect_to, and a 2xx a success,
// never an unavailability.
func TestRecordedHydraAnswers(t *testing.T) {
	const challenge = "SENTINEL-CHALLENGE"
	files, err := filepath.Glob("testdata/errors/hydra-*/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no recorded answers (%v): run tools/flowfixtures -errors", err)
	}
	statuses := map[int]bool{}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var ex recordedExchange
		if err := json.Unmarshal(b, &ex); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		path, _, _ := strings.Cut(ex.Request.URI, "?")
		if !strings.HasPrefix(path, "/admin/") {
			continue // a browser on Hydra's public port
		}
		status := ex.Response.Status
		statuses[status] = true
		t.Run(filepath.Base(filepath.Dir(file))+"/"+strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			body := ex.served()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", ex.Response.ContentType)
				w.WriteHeader(status)
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			op, err := callAs(t, newTestClient(t, srv.URL, 1, time.Second), ex.Request.Method, path, challenge)

			switch {
			case status < 300:
				if err != nil {
					t.Fatalf("%s answered %d: err = %v", op, status, err)
				}
				return
			case err == nil:
				t.Fatalf("%s answered %d: no error", op, status)
			case strings.Contains(err.Error(), challenge):
				t.Errorf("the challenge is in the error: %v", err)
			}
			var reqErr *RequestError
			if !errors.As(err, &reqErr) || errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want a RequestError: the answer is Hydra's own", err)
			}
			if reqErr.Op != op || reqErr.Status != status || !bytes.Equal(reqErr.Body, body) {
				t.Errorf("RequestError{%s, %d, %s}, want %s, %d and Hydra's body", reqErr.Op, reqErr.Status, reqErr.Body, op, status)
			}
			var doc struct {
				RedirectTo string `json:"redirect_to"`
			}
			_ = json.Unmarshal(body, &doc)
			if status == http.StatusGone && (doc.RedirectTo == "" || reqErr.RedirectTo() != doc.RedirectTo) {
				t.Errorf("RedirectTo() = %q, want Hydra's %q", reqErr.RedirectTo(), doc.RedirectTo)
			}
		})
	}
	// The statuses the dispatcher tells apart: a fixture set that lost one
	// would let its classification drift unseen.
	for _, s := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusGone} {
		if !statuses[s] {
			t.Errorf("no recorded answer of status %d", s)
		}
	}
}

// callAs makes the client call that sends method and path, and returns the
// name of its operation.
func callAs(t *testing.T, c *Client, method, path, challenge string) (string, error) {
	t.Helper()
	ctx := context.Background()
	var err error
	switch op := method + " " + path; op {
	case "GET /admin/oauth2/auth/requests/login":
		_, err = c.LoginRequest(ctx, challenge)
		return "get_login_request", err
	case "PUT /admin/oauth2/auth/requests/login/accept":
		_, err = c.AcceptLogin(ctx, challenge, ory.AcceptOAuth2LoginRequest{Subject: "alice"})
		return "accept_login", err
	case "PUT /admin/oauth2/auth/requests/login/reject":
		_, err = c.RejectLogin(ctx, challenge, ory.RejectOAuth2Request{})
		return "reject_login", err
	case "GET /admin/oauth2/auth/requests/consent":
		_, err = c.ConsentRequest(ctx, challenge)
		return "get_consent_request", err
	case "PUT /admin/oauth2/auth/requests/consent/accept":
		_, err = c.AcceptConsent(ctx, challenge, ory.AcceptOAuth2ConsentRequest{})
		return "accept_consent", err
	case "PUT /admin/oauth2/auth/requests/consent/reject":
		_, err = c.RejectConsent(ctx, challenge, ory.RejectOAuth2Request{})
		return "reject_consent", err
	case "GET /admin/oauth2/auth/requests/logout":
		_, err = c.LogoutRequest(ctx, challenge)
		return "get_logout_request", err
	case "PUT /admin/oauth2/auth/requests/logout/accept":
		_, err = c.AcceptLogout(ctx, challenge)
		return "accept_logout", err
	case "PUT /admin/oauth2/auth/requests/logout/reject":
		return "reject_logout", c.RejectLogout(ctx, challenge)
	default:
		t.Fatalf("no client call sends %s", op)
		return "", nil
	}
}

// recorded reads the exchange name of a Hydra version, as the client serves it.
func recorded(t *testing.T, version, name string) (*Client, recordedExchange) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata/errors", "hydra-"+version, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var ex recordedExchange
	if err := json.Unmarshal(b, &ex); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ex.Response.ContentType)
		w.WriteHeader(ex.Response.Status)
		_, _ = w.Write(ex.served())
	}))
	t.Cleanup(srv.Close)
	return newTestClient(t, srv.URL, 1, time.Second), ex
}

// What HLO-7 and HLO-10 say of a logout request, read back through the client,
// on each version: rp_initiated false without a hint, its client null; true with
// one, the client whole, without its secret, the whole query in request_url, which
// a POST leaves out; requested_at and expires_at from 2.3 alone.
func TestRecordedLogoutRequests(t *testing.T) {
	const path = "/oauth2/sessions/logout"
	ctx := context.Background()
	for _, version := range []string{"v2.1.2", "v2.2.0", "v2.3.0"} {
		t.Run(version, func(t *testing.T) {
			c, _ := recorded(t, version, "logout_request")
			plain, err := c.LogoutRequest(ctx, "U")
			if err != nil {
				t.Fatal(err)
			}
			if plain.GetRpInitiated() || plain.Client != nil || plain.GetRequestUrl() != path || plain.GetSubject() != "alice" || plain.GetSid() == "" {
				t.Errorf("without a hint: %+v", plain)
			}
			if lives := plain.ExpiresAt != nil && plain.RequestedAt != nil; lives != (version == "v2.3.0") {
				t.Errorf("requested_at %v, expires_at %v", plain.RequestedAt, plain.ExpiresAt)
			}

			c, _ = recorded(t, version, "logout_request_hint")
			hint, err := c.LogoutRequest(ctx, "U")
			if err != nil {
				t.Fatal(err)
			}
			if !hint.GetRpInitiated() || hint.Client == nil || hint.Client.GetClientId() == "" {
				t.Fatalf("with a hint: %+v", hint)
			}
			if hint.Client.GetClientSecret() != "" {
				t.Error("the client's secret is served")
			}
			for _, member := range []string{"jwks", "metadata"} {
				if !strings.Contains(string(jsonOf(t, hint.Client)), `"`+member+`"`) {
					t.Errorf("the client lacks its %s", member)
				}
			}
			u := hint.GetRequestUrl()
			if !strings.HasPrefix(u, path+"?") || !strings.Contains(u, "id_token_hint=") || !strings.Contains(u, "state=flowfixtures-logout-state") {
				t.Errorf("request_url %q, want its whole query", u)
			}

			c, _ = recorded(t, version, "logout_request_posted")
			posted, err := c.LogoutRequest(ctx, "U")
			if err != nil {
				t.Fatal(err)
			}
			if !posted.GetRpInitiated() || posted.GetRequestUrl() != path {
				t.Errorf("posted: rp_initiated %v, request_url %q", posted.GetRpInitiated(), posted.GetRequestUrl())
			}
		})
	}
}

// What the logout's answers say past the verifier and past a reject (HLO-3 to
// HLO-5, HLO-10), which the classes of LGO-2, LGO-3, LGO-13, LGO-15 and LGO-16
// read: 410 with a relative redirect_to once it is followed, 404 once rejected,
// a reject in 204 whatever came first, an accept in 200 even past it all.
func TestRecordedLogoutAnswers(t *testing.T) {
	ctx := context.Background()
	for _, version := range []string{"v2.1.2", "v2.2.0", "v2.3.0"} {
		t.Run(version, func(t *testing.T) {
			for _, name := range []string{"logout_after_verifier", "logout_expired_used"} {
				c, _ := recorded(t, version, name)
				_, err := c.LogoutRequest(ctx, "U")
				var re *RequestError
				if !errors.As(err, &re) || re.Status != http.StatusGone || !strings.HasPrefix(re.RedirectTo(), "/oauth2/sessions/logout") {
					t.Errorf("%s: %v, want 410 and a relative redirect_to", name, err)
				}
			}
			for _, name := range []string{"logout_rejected", "logout_after_reject"} {
				c, _ := recorded(t, version, name)
				_, err := c.LogoutRequest(ctx, "U")
				var re *RequestError
				if !errors.As(err, &re) || re.Status != http.StatusNotFound {
					t.Errorf("%s: %v, want 404", name, err)
				}
			}
			for _, name := range []string{"logout_reject", "logout_reject_again", "logout_reject_accepted", "logout_reject_after_verifier"} {
				c, _ := recorded(t, version, name)
				if err := c.RejectLogout(ctx, "U"); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
			for _, name := range []string{"logout_accept_rejected", "logout_accept_after_verifier", "logout_accept_after_reject", "logout_expired_accept"} {
				c, _ := recorded(t, version, name)
				to, err := c.AcceptLogout(ctx, "U")
				if err != nil || !strings.Contains(to, "logout_verifier=") {
					t.Errorf("%s: %q, %v", name, to, err)
				}
			}
			// HLO-10: past its lifetime, read and accepted all the same.
			c, _ := recorded(t, version, "logout_expired")
			if _, err := c.LogoutRequest(ctx, "U"); err != nil {
				t.Errorf("logout_expired: %v", err)
			}
		})
	}
}

// HLO-15, Q55: the consent request of a flow in progress as a logout ends: its
// login_session_id emptied in 2.1.2, by a foreign key, and kept from 2.2 (CST-24,
// SKC-15).
func TestRecordedConsentAfterLogout(t *testing.T) {
	for version, emptied := range map[string]bool{"v2.1.2": true, "v2.2.0": false, "v2.3.0": false} {
		t.Run(version, func(t *testing.T) {
			c, _ := recorded(t, version, "consent_after_logout")
			r, err := c.ConsentRequest(context.Background(), "C")
			if err != nil {
				t.Fatal(err)
			}
			if got := r.GetLoginSessionId() == ""; got != emptied {
				t.Errorf("login_session_id %q, emptied %v", r.GetLoginSessionId(), emptied)
			}
		})
	}
}

// Where the browser goes from the logout's verifiers, which the admin API does
// not show: HLO-2, HLO-5, HLO-6, HLO-10.
func TestRecordedLogoutVerifiers(t *testing.T) {
	type dest struct {
		status   int
		location string
		iframe   bool
	}
	const notFound = "/oauth2/fallbacks/error?"
	cases := []struct {
		name string
		want map[string]dest
	}{
		{"logout_verifier", map[string]dest{"v2.1.2": {200, "", true}, "v2.2.0": {200, "", true}, "v2.3.0": {200, "", true}}},
		{"logout_accept_rejected_verifier", map[string]dest{"v2.1.2": {200, "", true}, "v2.2.0": {200, "", true}, "v2.3.0": {200, "", true}}},
		{"logout_reject_accepted_verifier", map[string]dest{"v2.1.2": {302, notFound, false}, "v2.2.0": {302, notFound, false}, "v2.3.0": {302, notFound, false}}},
		{"logout_verifier_replayed", map[string]dest{"v2.1.2": {302, notFound, false}, "v2.2.0": {302, "/default", false}, "v2.3.0": {302, "/default", false}}},
		{"logout_expired_verifier", map[string]dest{"v2.1.2": {200, "", true}, "v2.2.0": {200, "", true}, "v2.3.0": {302, notFound, false}}},
	}
	for _, c := range cases {
		for version, want := range c.want {
			t.Run(version+"/"+c.name, func(t *testing.T) {
				b, err := os.ReadFile(filepath.Join("testdata/errors", "hydra-"+version, c.name+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var ex struct {
					Response struct {
						Status   int    `json:"status"`
						Location string `json:"location"`
						Body     string `json:"body"`
					} `json:"response"`
				}
				if err := json.Unmarshal(b, &ex); err != nil {
					t.Fatal(err)
				}
				r := ex.Response
				if r.Status != want.status || !strings.HasPrefix(r.Location, want.location) || strings.Contains(r.Body, "<iframe") != want.iframe {
					t.Errorf("%d to %q, iframe %v: want %+v", r.Status, r.Location, strings.Contains(r.Body, "<iframe"), want)
				}
				if want.iframe && !strings.Contains(r.Body, "sid=<sid>") {
					t.Error("the session is not elided from the front-channel")
				}
			})
		}
	}
}

func jsonOf(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
