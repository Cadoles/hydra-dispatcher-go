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
	default:
		t.Fatalf("no client call sends %s", op)
		return "", nil
	}
}
