// Package emulated serves the login apps Hydra's admin API for their step
// (lot P4): the six login and consent endpoints on the v2 paths, and the v1
// paths of the Symfony dispatcher as deprecated aliases. Each call is an
// event of the flow engine, which decides; the handlers check where the call
// comes from, read it, and write the engine's answer.
package emulated

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"

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

// endpoints are the six of Hydra's admin API a login app calls, by their v1
// path; the v2 one has the /admin prefix.
var endpoints = []endpoint{
	{http.MethodGet, "/oauth2/auth/requests/login", "login_challenge", flow.AppGetLogin},
	{http.MethodPut, "/oauth2/auth/requests/login/accept", "login_challenge", flow.AppAcceptLogin},
	{http.MethodPut, "/oauth2/auth/requests/login/reject", "login_challenge", flow.AppRejectLogin},
	{http.MethodGet, "/oauth2/auth/requests/consent", "consent_challenge", flow.AppGetConsent},
	{http.MethodPut, "/oauth2/auth/requests/consent/accept", "consent_challenge", flow.AppAcceptConsent},
	{http.MethodPut, "/oauth2/auth/requests/consent/reject", "consent_challenge", flow.AppRejectConsent},
}

// Register adds the endpoints to mux.
func Register(mux *http.ServeMux, o Options) {
	h := &handler{Options: o, legacyCallers: map[netip.Addr]bool{}}
	for _, e := range endpoints {
		mux.Handle(e.method+" /admin"+e.path, h.serve(e, false))
		if o.LegacyV1Paths {
			mux.Handle(e.method+" "+e.path, h.serve(e, true))
		}
	}
}

type handler struct {
	Options
	mu            sync.Mutex
	legacyCallers map[netip.Addr]bool
}

func (h *handler) serve(e endpoint, legacy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r.Context())
		if !httpx.Within(h.AuthorizedHosts, ip) {
			h.Logger.WarnContext(r.Context(), "security.ip_rejected", "surface", "emulated", "ip", httpx.FormatIP(ip, h.LogIP))
			writeError(w, r, flow.AppError{Error: "request_forbidden", Description: "The request is not allowed.", StatusCode: http.StatusForbidden})
			return
		}
		if legacy {
			w.Header().Set("Deprecation", deprecation)
			w.Header().Set("Link", "</admin"+e.path+`>; rel="successor-version"`)
			h.warnLegacy(r, e.path, ip)
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
				// The app hung up: nothing to answer.
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

// write answers the engine's response: a login or consent request, a
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
