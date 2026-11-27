package emulated

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"

	"github.com/Cadoles/hydra-dispatcher-go/api"
	"github.com/Cadoles/hydra-dispatcher-go/internal/flow"
)

// openAPI is the validator of the document, made once.
var openAPI = sync.OnceValues(func() (validator.Validator, error) {
	doc, err := api.JSON()
	if err != nil {
		return nil, err
	}
	d, err := libopenapi.NewDocument(doc)
	if err != nil {
		return nil, err
	}
	v, errs := validator.NewValidator(d)
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return v, nil
})

// seen counts the answers checked against the document, by "METHOD path
// status".
type seen struct {
	mu sync.Mutex
	n  map[string]int
}

func (s *seen) add(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == nil {
		s.n = map[string]int{}
	}
	s.n[key]++
}

func (s *seen) counts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.n)
}

// documented serves h and checks each of its answers against the OpenAPI
// document: an app generated from the document reads what the dispatcher
// answers. The admin API's tests did, not those of the emulated API, and its
// 410 and the 200 of a logout reject were documented otherwise (revue R36).
func documented(t *testing.T, h http.Handler) (http.Handler, *seen) {
	t.Helper()
	v, err := openAPI()
	if err != nil {
		t.Fatal(err)
	}
	s := &seen{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		maps.Copy(w.Header(), rec.Header())
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())

		req := r.Clone(context.Background())
		req.Body = io.NopCloser(bytes.NewReader(body))
		resp := rec.Result()
		resp.Body = io.NopCloser(bytes.NewReader(rec.Body.Bytes()))
		if ok, errs := v.ValidateHttpResponse(req, resp); !ok {
			var reasons []string
			for _, e := range errs {
				reasons = append(reasons, e.Message+": "+e.Reason)
			}
			t.Errorf("%s %s answered %d, not as the document says: %s\n%s", r.Method, r.URL.Path, rec.Code, strings.Join(reasons, "; "), rec.Body.String())
		}
		s.add(fmt.Sprintf("%s %s %d", r.Method, r.URL.Path, rec.Code))
	}), s
}

// The answers the emulated API gives the apps, on both paths, are those of the
// document: the 410 of a read that sends the browser back to the flow, the
// 200 of a logout reject (Q49), the errors.
func TestOpenAPIEmulated(t *testing.T) {
	all := map[string]int{}
	for _, dir := range []string{"12-sql-consent-skipped", "14-sql-2fa-consent-skipped", "16-consent-reject-first-step", "17-consent-reject-second-step",
		"18-login-reject-first-step", "19-login-reject-second-step", "20-accept-twice"} {
		for _, prefix := range []string{"", "/admin"} {
			xs := readCapture(t, dir)
			p := newPlayer(t, xs, prefix)
			p.play(xs)
			// An app that reads again a request already handled: the
			// browser goes back to the flow, in 410 (Q25).
			p.call(http.MethodGet, "/oauth2/auth/requests/login", "login_challenge", p.current.login, nil)
			if p.current.consent != "" {
				p.call(http.MethodGet, "/oauth2/auth/requests/consent", "consent_challenge", p.current.consent, nil)
			}
			for k, n := range p.seen.counts() {
				all[k] += n
			}
		}
	}
	const sid = "e1ab6d8c-1c0b-4a39-a3c5-7c3bd1c1ab0f"
	for _, prefix := range []string{"", "/admin"} {
		for _, op := range []string{"", "/accept", "/reject"} {
			f := newLogoutFixture(t, &flow.LogoutRecord{V: flow.LogoutFormat, U: "hydra-u", RT: "http://hydra/verifier", Subject: "alice", SID: sid,
				URL: "/oauth2/sessions/logout", Apps: []string{"hydra-sql"}, SentAt: 1})
			method := http.MethodPut
			if op == "" {
				method = http.MethodGet
			}
			req, err := http.NewRequest(method, f.url+prefix+"/oauth2/auth/requests/logout"+op+"?logout_challenge="+f.keys.LogoutChallenge(f.ref, 0, "hydra-sql"), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			for k, n := range f.seen.counts() {
				all[k] += n
			}
		}
	}
	for _, want := range []string{
		"GET /oauth2/auth/requests/login 200", "GET /admin/oauth2/auth/requests/login 200",
		"GET /oauth2/auth/requests/login 410", "GET /admin/oauth2/auth/requests/login 410",
		"PUT /admin/oauth2/auth/requests/login/accept 200", "PUT /admin/oauth2/auth/requests/login/reject 200",
		"GET /admin/oauth2/auth/requests/consent 200", "PUT /admin/oauth2/auth/requests/consent/reject 200",
		"GET /oauth2/auth/requests/logout 200", "GET /admin/oauth2/auth/requests/logout 200",
		"PUT /oauth2/auth/requests/logout/reject 200", "PUT /admin/oauth2/auth/requests/logout/reject 200",
		"PUT /admin/oauth2/auth/requests/logout/accept 200",
	} {
		if all[want] == 0 {
			t.Errorf("never checked: %s; checked: %q", want, slices.Sorted(maps.Keys(all)))
		}
	}
}
