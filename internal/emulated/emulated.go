// Package emulated serves the login apps Hydra's admin API for their step
// (lot P4): the six login and consent endpoints and the three of the logout (P9)
// on the v2 paths, and the v1 paths of the Symfony dispatcher as deprecated
// aliases, which hydra-passwordless still calls. Each call is an
// event of the flow engine, which decides; the handlers check where the call
// comes from, read it, and write the engine's answer.
package emulated

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Engine runs the transition of an event to its end: flow.Orchestrator.
type Engine interface {
	Handle(ctx context.Context, ev flow.Event) flow.Result
}

// Options configure the handlers.
type Options struct {
	Engine Engine
	// AuthorizedHosts is security.emulated_api_authorized_hosts: the
	// networks the login apps call from (B2).
	AuthorizedHosts []netip.Prefix
	// LegacyV1Paths is emulated_api.legacy_v1_paths.
	LegacyV1Paths bool
	// Logger gets the refusals of the allowlist and the first use of a v1
	// path by an address; LogIP is observability.log_ip, for those addresses.
	Logger *slog.Logger
	LogIP  string
	// Refused, nil for none, is told of a caller outside the allowlist.
	Refused func(context.Context)
	// LogSample thins the lines of those refusals, nil keeps them all. The failure
	// limiter has no part here: the challenge an app calls with, a browser gave it (Q80).
	LogSample *httpx.Sampler
}

// maxBody bounds the body of a call (Sécurité, report R5).
const maxBody = 1 << 20

// deprecation is the Deprecation header of the v1 paths (RFC 9745): the date
// the Go dispatcher deprecated them, 2026-11-02. Sunset waits for the date
// of the 1.0, which removes them.
const deprecation = "@1793577600"

// maxLegacyCallers bounds the addresses remembered for the warning of a
// first v1 call: past it, no address is warned of again.
const maxLegacyCallers = 4096

type endpoint struct {
	method, path, param string
	op                  flow.AppOp
}

// endpoints are the nine of Hydra's admin API a login app calls, by their v1
// path; the v2 one has the /admin prefix.
var endpoints = []endpoint{
	{http.MethodGet, "/oauth2/auth/requests/login", "login_challenge", flow.AppGetLogin},
	{http.MethodPut, "/oauth2/auth/requests/login/accept", "login_challenge", flow.AppAcceptLogin},
	{http.MethodPut, "/oauth2/auth/requests/login/reject", "login_challenge", flow.AppRejectLogin},
	{http.MethodGet, "/oauth2/auth/requests/consent", "consent_challenge", flow.AppGetConsent},
	{http.MethodPut, "/oauth2/auth/requests/consent/accept", "consent_challenge", flow.AppAcceptConsent},
	{http.MethodPut, "/oauth2/auth/requests/consent/reject", "consent_challenge", flow.AppRejectConsent},
	{http.MethodGet, "/oauth2/auth/requests/logout", "logout_challenge", flow.AppGetLogout},
	{http.MethodPut, "/oauth2/auth/requests/logout/accept", "logout_challenge", flow.AppAcceptLogout},
	{http.MethodPut, "/oauth2/auth/requests/logout/reject", "logout_challenge", flow.AppRejectLogout},
}

// prefix is the path of the nine endpoints, by their v1 path.
const prefix = "/oauth2/auth/requests/"

// Register adds the endpoints to mux, and under their prefix an answer to
// the other paths and methods, after the allowlist as well.
func Register(mux *http.ServeMux, o Options) {
	h := &handler{Options: o, legacyCallers: map[netip.Addr]bool{}}
	for _, e := range endpoints {
		mux.Handle(e.method+" /admin"+e.path, h.serve(e, false))
		if o.LegacyV1Paths {
			mux.Handle(e.method+" "+e.path, h.serve(e, true))
		}
	}
	mux.Handle("/admin"+prefix, h.other(false))
	if o.LegacyV1Paths {
		mux.Handle(prefix, h.other(true))
	}
}

type handler struct {
	Options
	mu            sync.Mutex
	legacyCallers map[netip.Addr]bool
}

func (h *handler) serve(e endpoint, legacy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := h.admit(w, r, e.path, legacy)
		if !ok {
			return
		}
		var body json.RawMessage
		if e.method == http.MethodPut {
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
			var tooLarge *http.MaxBytesError
			switch {
			case errors.As(err, &tooLarge):
				writeError(w, r, flow.AppError{Error: "invalid_request", Description: string(flow.E1001), StatusCode: http.StatusRequestEntityTooLarge})
				return
			case err != nil:
				// A body cut short, or past the server's ReadTimeout: an
				// invalid body (EMU-15), which an app that hung up does not
				// read. Without an answer, net/http would send 200.
				writeError(w, r, flow.AppError{Error: "invalid_request", Description: string(flow.E1001), StatusCode: http.StatusBadRequest})
				return
			}
			body = data
		}
		res := h.Engine.Handle(r.Context(), flow.AppCall{
			Op:        e.op,
			Challenge: r.URL.Query().Get(e.param),
			Caller:    identify(r, ip),
			Body:      body,
		})
		write(w, r, res.Response)
	})
}

// admit refuses a caller outside the allowlist, and gives the answers of a
// v1 path, an alias of path, their Deprecation and Link, the refusal's too;
// path is "" on another path. The first v1 call of an address the allowlist
// lets in is logged.
func (h *handler) admit(w http.ResponseWriter, r *http.Request, path string, legacy bool) (netip.Addr, bool) {
	ip := httpx.ClientIP(r.Context())
	alias := legacy && path != ""
	if alias {
		w.Header().Set("Deprecation", deprecation)
		w.Header().Set("Link", "</admin"+path+`>; rel="successor-version"`)
	}
	if !httpx.Within(h.AuthorizedHosts, ip) {
		if h.LogSample.AllowClient(r.Context(), "security.ip_rejected") {
			h.Logger.WarnContext(r.Context(), "security.ip_rejected", "surface", "emulated", "ip", httpx.FormatIP(ip, h.LogIP))
		}
		if h.Refused != nil {
			h.Refused(r.Context())
		}
		writeError(w, r, flow.AppError{Error: "request_forbidden", Description: "The request is not allowed.", StatusCode: http.StatusForbidden})
		return ip, false
	}
	if alias {
		h.warnLegacy(r, path, ip)
	}
	return ip, true
}

// other answers what is under the prefix but no endpoint, after the
// allowlist, so that a caller outside it learns nothing of the routes: 405
// with Allow to another method of an endpoint, 404 to another path, in the
// form of a malformed challenge (EMU-1).
func (h *handler) other(legacy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if !legacy {
			path = strings.TrimPrefix(path, "/admin")
		}
		var allow []string
		for _, e := range endpoints {
			if e.path == path {
				allow = append(allow, e.method)
			}
		}
		if len(allow) == 0 {
			path = ""
		}
		if _, ok := h.admit(w, r, path, legacy); !ok {
			return
		}
		status := http.StatusNotFound
		if len(allow) > 0 {
			if allow[0] == http.MethodGet {
				allow = append(allow, http.MethodHead)
			}
			w.Header().Set("Allow", strings.Join(allow, ", "))
			status = http.StatusMethodNotAllowed
		}
		writeError(w, r, flow.AppError{Error: "invalid_request", Description: "request_failed", StatusCode: status})
	})
}

// identify tells whether the caller is app (Sécurité, durcissement 1): by
// its certificate in mtls, by its address among its allowed_sources in
// network. An app without allowed_sources falls back on the allowlist, which
// the caller passed. The certificate is the one the dispatcher received: a
// proxy terminating TLS does not forward it yet.
func identify(r *http.Request, ip netip.Addr) func(app store.App) bool {
	return func(app store.App) bool {
		if app.AuthMode == "mtls" {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return false
			}
			sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
			return app.ClientCertFingerprint != "" && hex.EncodeToString(sum[:]) == app.ClientCertFingerprint
		}
		return len(app.AllowedSources) == 0 || httpx.Within(app.AllowedSources, ip)
	}
}

// Warnings are those of the apps' identification against hosts, the
// allowlist (Sécurité, durcissement 1), written as config.warning by each
// snapshot that changes them:
//   - an app in network mode without allowed_sources, which any address of
//     the allowlist passes for;
//   - a source the allowlist does not cover, from which the app is refused;
//   - sources two apps share, from which a host passes for either;
//   - an app in mtls, which the dispatcher, serving no TLS yet, never
//     identifies.
func Warnings(apps []store.App, hosts []netip.Prefix) []string {
	var out []string
	for i, a := range apps {
		if a.AuthMode == "mtls" {
			out = append(out, "app "+a.ID+" is in auth_mode mtls: the dispatcher serves no TLS yet, so the emulated API never identifies it and refuses its calls")
			continue
		}
		if len(a.AllowedSources) == 0 {
			out = append(out, "app "+a.ID+" has no allowed_sources: the emulated API accepts its steps from any address of security.emulated_api_authorized_hosts")
		}
		for _, s := range a.AllowedSources {
			if !config.Covers(hosts, s) {
				out = append(out, fmt.Sprintf("app %s: allowed source %s is not within security.emulated_api_authorized_hosts: the emulated API refuses its calls from outside it", a.ID, s))
			}
		}
		for _, b := range apps[i+1:] {
			if b.AuthMode == "mtls" {
				continue
			}
			if p, q, ok := overlap(a.AllowedSources, b.AllowedSources); ok {
				out = append(out, fmt.Sprintf("apps %s and %s share addresses (%s, %s): a host there is identified as either", a.ID, b.ID, p, q))
			}
		}
	}
	return out
}

// overlap returns the first prefixes of ps and qs that share an address.
func overlap(ps, qs []netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	for _, p := range ps {
		for _, q := range qs {
			if p.Overlaps(q) {
				return p, q, true
			}
		}
	}
	return netip.Prefix{}, netip.Prefix{}, false
}

// warnLegacy logs the first v1 call of an address, so that the apps still
// on the aliases show before 1.0 removes them.
func (h *handler) warnLegacy(r *http.Request, path string, ip netip.Addr) {
	h.mu.Lock()
	first := !h.legacyCallers[ip] && len(h.legacyCallers) < maxLegacyCallers
	if first {
		h.legacyCallers[ip] = true
	}
	h.mu.Unlock()
	if first {
		h.Logger.WarnContext(r.Context(), "emulated.legacy_path", "path", path, "ip", httpx.FormatIP(ip, h.LogIP))
	}
}

// errorBody is an error of the emulated API in Symfony's form (T5), with the
// trace id the support asks for. An unknown challenge has none, as Symfony
// answered it (capture 21).
type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	StatusCode  int    `json:"status_code"`
	TraceID     string `json:"trace_id,omitempty"`
}

func writeError(w http.ResponseWriter, r *http.Request, e flow.AppError) {
	b := errorBody{Error: e.Error, Description: e.Description, StatusCode: e.StatusCode}
	if e.Error != "missing_session_error" {
		b.TraceID = httpx.TraceID(r.Context())
	}
	writeJSON(w, e.StatusCode, b)
}

// write answers the engine's response: a login, consent or logout request, a
// redirect_to, or an error. Hydra saturated (max_in_flight) is a 503 with
// Retry-After; the engine answering a page is a bug, E1000.
func write(w http.ResponseWriter, r *http.Request, resp flow.Response) {
	if resp.Kind != flow.AppJSON {
		writeError(w, r, flow.AppError{Error: "server_error", Description: string(flow.E1000), StatusCode: http.StatusInternalServerError})
		return
	}
	e, isError := resp.Body.(flow.AppError)
	switch {
	case isError && resp.Overloaded:
		w.Header().Set("Retry-After", "1")
		e.StatusCode = http.StatusServiceUnavailable
		writeError(w, r, e)
	case isError:
		writeError(w, r, e)
	default:
		writeJSON(w, resp.Status, resp.Body)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		status, data = http.StatusInternalServerError, []byte(`{"error":"server_error","error_description":"E1000","status_code":500}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
