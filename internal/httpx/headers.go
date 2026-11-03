package httpx

import (
	"maps"
	"net/http"
	"slices"
	"strings"
)

// baseCSP is the content security policy of every response: the pages load
// their own styles, scripts and fonts only, no inline script, and are never
// framed. Images may be external: the clients' logos and the flows' icons
// are URLs of their own. form-action is left out: a form posted to the
// dispatcher redirects to a login app or to Hydra, which form-action would
// block in some browsers.
var baseCSP = map[string][]string{
	"default-src":     {"'none'"},
	"script-src":      {"'self'"},
	"style-src":       {"'self'"},
	"img-src":         {"'self'", "data:", "https:", "http:"},
	"font-src":        {"'self'"},
	"connect-src":     {"'self'"},
	"base-uri":        {"'none'"},
	"frame-ancestors": {"'none'"},
}

// CSP returns the content security policy, ui.csp_extra appended to the
// sources of its directives (validated by internal/config).
func CSP(extra map[string][]string) string {
	directives := maps.Clone(baseCSP)
	for d, sources := range extra {
		directives[d] = append(slices.Clip(directives[d]), sources...)
	}
	parts := make([]string, 0, len(directives))
	for _, d := range slices.Sorted(maps.Keys(directives)) {
		parts = append(parts, d+" "+strings.Join(directives[d], " "))
	}
	return strings.Join(parts, "; ")
}

// SecurityHeaders sets the security headers of every response (Sécurité,
// durcissements 5 et 6): the content security policy, no framing, no MIME
// sniffing, the full referrer for the dispatcher's own pages only (their
// URLs carry Hydra's challenges, which no login app may see: I7; the change
// of language goes back by it), the permissions policy, and HSTS when the
// dispatcher is served in HTTPS.
//
// No Cross-Origin-Opener-Policy: the pages are a step of the sign-in a
// client may open in a popup, and same-origin there, as
// same-origin-allow-popups, puts the popup in another browsing context
// group, whose window.opener stays null back on the client's callback
// (checked in Chrome): the popup never hands the sign-in back.
func SecurityHeaders(csp string, https, hstsSubdomains bool) Middleware {
	hsts := "max-age=31536000"
	if hstsSubdomains {
		hsts += "; includeSubDomains"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
			if https {
				h.Set("Strict-Transport-Security", hsts)
			}
			next.ServeHTTP(w, r)
		})
	}
}
