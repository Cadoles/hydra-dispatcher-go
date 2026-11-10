package admin

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/api"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/emulated"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
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

func mustOpenAPI(t *testing.T) validator.Validator {
	t.Helper()
	v, err := openAPI()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The document is OpenAPI 3.1, valid against its schema.
func TestOpenAPIDocument(t *testing.T) {
	ok, errs := mustOpenAPI(t).ValidateDocument()
	for _, e := range errs {
		t.Errorf("%s: %s", e.Message, e.Reason)
		for _, s := range e.SchemaValidationErrors {
			t.Errorf("  %s at %s (line %d)", s.Reason, s.FieldPath, s.Line)
		}
	}
	if !ok && len(errs) == 0 {
		t.Error("invalid, without a reason")
	}
	var doc map[string]any
	if data, err := api.JSON(); err != nil || json.Unmarshal(data, &doc) != nil || doc["openapi"] != "3.1.0" {
		t.Errorf("docs.json: %v", err)
	}
}

// Each route the admin API and the emulated API serve is in the document, and
// each operation of the document is served: the files of the page of the
// documentation apart.
func TestOpenAPIRoutes(t *testing.T) {
	data, err := api.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for path, ops := range doc.Paths {
		for method := range ops {
			if slices.Contains([]string{"get", "put", "post", "patch", "delete"}, method) {
				documented = append(documented, strings.ToUpper(method)+" "+path)
			}
		}
	}
	r := newResources(t)
	var served []string
	for _, route := range append(r.api.Routes(), emulated.Routes(true)...) {
		if !strings.HasPrefix(route, "GET "+Prefix+"/docs/") {
			served = append(served, route)
		}
	}
	slices.Sort(documented)
	slices.Sort(served)
	for _, route := range served {
		if !slices.Contains(documented, route) {
			t.Errorf("served, not in the document: %s", route)
		}
	}
	for _, route := range documented {
		if !slices.Contains(served, route) {
			t.Errorf("in the document, not served: %s", route)
		}
	}
	if len(served) < 40 {
		t.Errorf("%d routes served: %q", len(served), served)
	}
}

// Each route of a resource answers by the scopes its operation in the document
// requires, and no other: a route attached to another resource fails here
// (revue R35). Authorization comes before the body, so any body will do.
func TestRouteScopes(t *testing.T) {
	data, err := api.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	r := newResources(t)
	tokens := map[string]string{}
	for _, scope := range Scopes {
		tokens[scope] = r.tokenOf(t, "only-"+strings.ReplaceAll(scope, ":", "-"), scope)
	}
	checked := 0
	var open []string
	for path, ops := range doc.Paths {
		if !strings.HasPrefix(path, Prefix+"/") {
			continue
		}
		for method, raw := range ops {
			if !slices.Contains([]string{"get", "put", "post", "patch", "delete"}, method) {
				continue // the parameters of the path
			}
			var op struct {
				Security []map[string][]string `json:"security"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatal(err)
			}
			var allowed []string
			for _, req := range op.Security {
				allowed = append(allowed, req["bearer"]...)
			}
			if len(allowed) == 0 {
				open = append(open, strings.ToUpper(method)+" "+path)
				continue
			}
			concrete := strings.ReplaceAll(path, "{id}", "x")
			for _, scope := range Scopes {
				w := r.do(tokens[scope], strings.ToUpper(method), concrete, "application/json", `{}`)
				// A 403 for the scope, not for another reason.
				refused := w.Code == http.StatusForbidden && strings.Contains(w.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
				if refused == slices.Contains(allowed, scope) || w.Code == http.StatusForbidden && !refused {
					t.Errorf("%s %s with %s: %d %s, the document allows %q", strings.ToUpper(method), path, scope, w.Code, w.Header().Get("WWW-Authenticate"), allowed)
				}
			}
			checked++
		}
	}
	if checked != 21 {
		t.Errorf("%d operations checked, want 21", checked)
	}
	// Without a token, these alone: a route of a resource documented with
	// security: [] would escape the check above (revue R36).
	slices.Sort(open)
	if want := []string{"GET /admin/v1/docs", "GET /admin/v1/docs.json", "POST /admin/v1/token"}; !slices.Equal(open, want) {
		t.Errorf("operations without a token: %q, want %q", open, want)
	}
}

// exchange is a request of the tests and what to validate of it.
type exchange struct {
	token, method, path, contentType, body string
	// requestToo validates the request as well; off for the requests the
	// API must refuse.
	requestToo bool
}

// Each answer of the admin API, success or error, is what the document says;
// each valid request too.
func TestOpenAPIResponses(t *testing.T) {
	v := mustOpenAPI(t)
	r := newResources(t)
	r.withApps("a")
	ok := func(token, method, path, ct, body string) exchange {
		return exchange{token, method, path, ct, body, true}
	}
	bad := func(token, method, path, ct, body string) exchange {
		return exchange{token, method, path, ct, body, false}
	}
	merge := "application/merge-patch+json"
	for _, x := range []exchange{
		ok(r.all, "POST", "/admin/v1/apps", "", appBody),
		ok(r.all, "GET", "/admin/v1/apps", "", ""),
		ok(r.all, "GET", "/admin/v1/apps?page=2", "", ""),
		ok(r.reader, "GET", "/admin/v1/apps/sql", "", ""),
		ok(r.all, "PATCH", "/admin/v1/apps/sql", merge, `{"receiveClaims": ["email"], "allowedSources": ["10.0.0.1"]}`),
		ok(r.all, "PUT", "/admin/v1/apps/sql", "", appBody),
		ok(r.all, "POST", "/admin/v1/flows", "", `{"id": "f", "title": {"fr": "F"}, "description": {"fr": "D"}, "steps": [{"appId": "sql", "stepOrder": 0}]}`),
		ok(r.all, "GET", "/admin/v1/flows/f", "", ""),
		ok(r.all, "PATCH", "/admin/v1/flows/f", "application/json", `{"acr": "loa2", "iconUrl": {"fr": "http://i/f.svg"}}`),
		ok(r.all, "PUT", "/admin/v1/flows/f", "", `{"title": {"fr": "F"}, "description": {"fr": "D"}, "steps": [{"id": "a", "order": "1"}]}`),
		ok(r.all, "GET", "/admin/v1/flows", "", ""),
		ok(r.all, "POST", "/admin/v1/oauth2-clients", "", `{"id": "ci", "secret": "s3cret", "scopes": ["admin:read"]}`),
		ok(r.all, "GET", "/admin/v1/oauth2-clients", "", ""),
		ok(r.all, "PUT", "/admin/v1/oauth2-clients/ci", "", `{"scopes": ["admin:read", "admin:flows"]}`),
		ok(r.all, "GET", "/admin/v1/settings", "", ""),
		ok(r.all, "PATCH", "/admin/v1/settings", merge, `{"appAutoSelect": true, "sessionTtl": 1800}`),
		ok(r.all, "PUT", "/admin/v1/settings", "", `{"loginAcceptWebhookUrl": null}`),
		ok(r.all, "DELETE", "/admin/v1/flows/f", "", ""),
		ok(r.all, "DELETE", "/admin/v1/oauth2-clients/ci", "", ""),
		ok("", "GET", "/admin/v1/docs.json", "", ""),
		ok("", "GET", "/admin/v1/docs", "", ""),
		bad(r.all, "POST", "/admin/v1/apps", "", appBody),               // 409
		bad(r.all, "POST", "/admin/v1/apps", "", `{"id": "x", "y": 1}`), // 422
		bad(r.all, "POST", "/admin/v1/apps", "", `{"id": 1}`),           // 400
		bad(r.all, "POST", "/admin/v1/apps", "text/plain", appBody),     // 415
		bad(r.all, "GET", "/admin/v1/apps/nope", "", ""),                // 404
		bad(r.all, "GET", "/admin/v1/apps?page=0", "", ""),              // 400
		bad(r.reader, "POST", "/admin/v1/apps", "", appBody),            // 403
		bad("", "GET", "/admin/v1/apps", "", ""),                        // 401
		bad(r.all, "DELETE", "/admin/v1/apps/a", "", ""),                // 204
	} {
		w := r.do(x.token, x.method, x.path, x.contentType, x.body)
		req := httptest.NewRequest(x.method, x.path, strings.NewReader(x.body))
		if x.token != "" {
			req.Header.Set("Authorization", "Bearer "+x.token)
		}
		if x.body != "" {
			req.Header.Set("Content-Type", cmpOr(x.contentType, "application/json"))
		}
		resp := w.Result()
		resp.Body = io.NopCloser(bytes.NewReader(w.Body.Bytes()))
		var ok bool
		var errs []string
		if x.requestToo {
			valid, verrs := v.ValidateHttpRequestResponse(req, resp)
			ok = valid
			for _, e := range verrs {
				errs = append(errs, e.Message+": "+e.Reason)
			}
		} else {
			valid, verrs := v.ValidateHttpResponse(req, resp)
			ok = valid
			for _, e := range verrs {
				errs = append(errs, e.Message+": "+e.Reason)
			}
		}
		if !ok {
			t.Errorf("%s %s (%d): %s\n%s", x.method, x.path, w.Code, strings.Join(errs, "; "), truncate(w.Body.String(), 300))
		}
	}
}

// The validator refuses what the document does not say: the tests above can
// fail.
func TestOpenAPIRefuses(t *testing.T) {
	v := mustOpenAPI(t)
	for name, x := range map[string]struct {
		method, path, contentType, body string
		status                          int
	}{
		"an app without its fields": {"GET", "/admin/v1/apps/sql", "application/json; charset=utf-8", `{"id": "sql"}`, 200},
		"an id that is a number":    {"GET", "/admin/v1/apps/sql", "application/json; charset=utf-8", `{"id": 1, "loginUrl": "", "consentUrl": "", "logoutUrl": "", "method": "", "authMode": "network", "allowedSources": [], "clientCertFingerprint": null, "receiveClaims": null}`, 200},
		"a status not documented":   {"GET", "/admin/v1/apps/sql", "application/json", `{}`, 418},
		"a problem without status":  {"GET", "/admin/v1/apps/nope", "application/problem+json", `{"type": "/errors/404", "title": "x", "detail": "y"}`, 404},
	} {
		req := httptest.NewRequest(x.method, x.path, nil)
		req.Header.Set("Authorization", "Bearer x")
		resp := &http.Response{StatusCode: x.status, Header: http.Header{"Content-Type": {x.contentType}}, Body: io.NopCloser(strings.NewReader(x.body))}
		if ok, _ := v.ValidateHttpResponse(req, resp); ok {
			t.Errorf("%s: valid", name)
		}
	}
	req := httptest.NewRequest("POST", "/admin/v1/apps", strings.NewReader(`{"id": "x", "recieveClaims": []}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer x")
	if ok, _ := v.ValidateHttpRequest(req); ok {
		t.Error("a request with an unknown field: valid")
	}
}

// A write that fails for a cause of the dispatcher's own: a 500 the document
// says, which names the trace and not the cause (revue R36).
func TestOpenAPIServerError(t *testing.T) {
	v := mustOpenAPI(t)
	r := newResources(t)
	r.writer.fail = errors.New("dial tcp 10.0.0.5:5432: connection refused")
	w := r.do(r.all, http.MethodPost, "/admin/v1/apps", "", appBody)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/apps", strings.NewReader(appBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.all)
	resp := w.Result()
	resp.Body = io.NopCloser(bytes.NewReader(w.Body.Bytes()))
	if ok, errs := v.ValidateHttpResponse(req, resp); !ok || w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "10.0.0.5") {
		t.Errorf("%d %s: %v", w.Code, w.Body, errs)
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// wantDocsCSP is the CSP of the page, written out: compared with the
// constant itself, the test let any change of it pass (revue R36).
const wantDocsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// docsPaths are the page of the documentation and its files.
var docsPaths = []string{"/admin/v1/docs", "/admin/v1/docs.json", "/admin/v1/docs/scalar.js", "/admin/v1/docs/init.js"}

// The page of the documentation: its CSP, its files, served without a token.
func TestDocsPage(t *testing.T) {
	r := newResources(t)
	w := r.do("", http.MethodGet, "/admin/v1/docs", "", "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != wantDocsCSP || w.Header().Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(w.Body.String(), `<script src="docs/scalar.js">`) {
		t.Fatalf("page: %d %v", w.Code, w.Header())
	}
	for path, ct := range map[string]string{
		"/admin/v1/docs/scalar.js": "text/javascript; charset=utf-8",
		"/admin/v1/docs/init.js":   "text/javascript; charset=utf-8",
		"/admin/v1/docs.json":      "application/json",
	} {
		w := r.do("", http.MethodGet, path, "", "")
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != ct || w.Header().Get("ETag") == "" || w.Body.Len() == 0 {
			t.Errorf("%s: %d %v", path, w.Code, w.Header())
			continue
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.1.2.3:1"
		req.Header.Set("If-None-Match", w.Header().Get("ETag"))
		again := httptest.NewRecorder()
		r.handler.ServeHTTP(again, req)
		if again.Code != http.StatusNotModified {
			t.Errorf("%s again: %d", path, again.Code)
		}
	}
	// The allowlist and the rate limit hold for each of them: a limit of 2,
	// the third request of an address refused.
	keys := mustKeys(t, pkcs8(t, ecKey(t, elliptic.P256())), "")
	limited := mustNew(t, Options{Keys: keys, Config: &snapshots{}, Issuer: issuer, TokenTTL: time.Minute,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, RatePerMinute: 2})
	mux := http.NewServeMux()
	limited.Register(mux)
	h := httpx.Chain(mux, httpx.RealIP(nil))
	get := func(path, from string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = from + ":1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	for i, path := range docsPaths {
		if code := get(path, "203.0.113.7"); code != http.StatusForbidden {
			t.Errorf("%s outside the allowlist: %d", path, code)
		}
		from := fmt.Sprintf("10.9.0.%d", i+1)
		if codes := []int{get(path, from), get(path, from), get(path, from)}; codes[0] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
			t.Errorf("%s under a limit of 2: %v", path, codes)
		}
	}
}
