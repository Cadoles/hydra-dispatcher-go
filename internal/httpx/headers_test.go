package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	csp := CSP(map[string][]string{"font-src": {"https://fonts.gstatic.com"}})
	if want := "base-uri 'none'; connect-src 'self'; default-src 'none'; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; img-src 'self' data: https: http:; script-src 'self'; style-src 'self'"; csp != want {
		t.Errorf("CSP %q", csp)
	}
	if again := CSP(map[string][]string{"font-src": {"https://other"}}); again != "base-uri 'none'; connect-src 'self'; default-src 'none'; font-src 'self' https://other; frame-ancestors 'none'; img-src 'self' data: https: http:; script-src 'self'; style-src 'self'" {
		t.Errorf("the base policy changed by an earlier call: %q", again)
	}
	for _, tc := range []struct {
		https, subdomains bool
		hsts              string
	}{{false, false, ""}, {true, false, "max-age=31536000"}, {true, true, "max-age=31536000; includeSubDomains"}} {
		w := httptest.NewRecorder()
		SecurityHeaders(csp, tc.https, tc.subdomains)(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		h := w.Header()
		if h.Get("Content-Security-Policy") != csp || h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "strict-origin-when-cross-origin" || h.Get("Cross-Origin-Opener-Policy") != "" ||
			h.Get("Permissions-Policy") == "" || h.Get("Strict-Transport-Security") != tc.hsts {
			t.Errorf("https %v: %v", tc.https, h)
		}
	}
}
