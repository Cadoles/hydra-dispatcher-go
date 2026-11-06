// Package audit writes the audit log: a stream of its own, for a SIEM, of the events of
// security the engine decided, with the full IP and the subject pseudonymised by an HMAC,
// without anything sensitive of the authentication (doc, Durcissements point 8).
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

// pseudonymSize is what a pseudonym keeps of its HMAC: 128 bits, in hexadecimal.
const pseudonymSize = 32

// Log is the audit log. Observe is a flow.Observer.
type Log struct {
	logger *slog.Logger
	key    []byte
	// clear writes the subject as it is (observability.audit.pseudonymize_subject: false).
	clear bool
}

// New writes to logger, and pseudonymises the subjects with key, unless clear.
func New(logger *slog.Logger, key []byte, clear bool) *Log {
	return &Log{logger: logger, key: key, clear: clear}
}

// subject is what the log holds of a subject: "" for none. The array of encoding/json
// is unambiguous whatever the subject, and its first member keeps this HMAC apart from
// any other made with the key.
func (l *Log) subject(s string) string {
	if s == "" || l.clear {
		return s
	}
	data, _ := json.Marshal([]string{"dispatcher-audit", s}) // strings always marshal
	mac := hmac.New(sha256.New, l.key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))[:pseudonymSize]
}

func clientIP(ctx context.Context) string {
	if ip := httpx.ClientIP(ctx); ip.IsValid() {
		return ip.String()
	}
	return "unknown"
}

// subjectOf is the subject of the request, from what is the surest: the accept sent,
// then the flow, then what Hydra served.
func subjectOf(o flow.Observation) string {
	a := o.Answers
	if a.Accept != nil && a.Accept.Err == nil && a.Accept.Call.AcceptLogin.Subject != "" {
		return a.Accept.Call.AcceptLogin.Subject
	}
	for _, f := range []*flow.Flow{o.Before, o.After} {
		if f == nil {
			continue
		}
		if f.Sent != nil && f.Sent.Subject != "" {
			return f.Sent.Subject
		}
		if f.Subject != "" {
			return f.Subject
		}
	}
	switch {
	case a.Consent != nil && a.Consent.Request != nil:
		return a.Consent.Request.GetSubject()
	case a.Logout != nil && a.Logout.Request != nil:
		return a.Logout.Request.GetSubject()
	case a.Login != nil && a.Login.Request != nil:
		return a.Login.Request.Subject
	}
	return ""
}

// clientOf is the OAuth2 client of the request.
func clientOf(o flow.Observation) string {
	for _, f := range []*flow.Flow{o.Before, o.After} {
		if id := f.ClientID(); id != "" {
			return id
		}
	}
	a := o.Answers
	switch {
	case a.Consent != nil && a.Consent.Request != nil && a.Consent.Request.Client != nil:
		return a.Consent.Request.Client.GetClientId()
	case a.Logout != nil && a.Logout.Request != nil && a.Logout.Request.Client != nil:
		return a.Logout.Request.Client.GetClientId()
	case a.Login != nil && a.Login.Request != nil:
		return a.Login.Request.Client.GetClientId()
	}
	return ""
}

// flowOf is the flow of the request, and its apps in order: a reduced flow no longer
// has them, the flow read does.
func flowOf(o flow.Observation) (id string, apps []string) {
	apps = []string{}
	for _, f := range []*flow.Flow{o.After, o.Before} {
		if f == nil {
			continue
		}
		if id == "" {
			id = f.FlowID
		}
		if len(apps) == 0 {
			for _, s := range f.Steps {
				apps = append(apps, s.App)
			}
		}
	}
	return id, apps
}

// Observe writes the events of security among what a request decided.
func (l *Log) Observe(ctx context.Context, o flow.Observation) {
	for _, r := range o.Reports {
		switch r.Event {
		case "hydra.login_accepted":
			id, apps := flowOf(o)
			if r.Flow != "" {
				id = r.Flow // a skip's, from the cookie
			}
			l.logger.InfoContext(ctx, "auth.succeeded", "flow", id, "steps", len(apps), "apps", apps, "result", "accepted",
				"skip", r.Flow != "", "client_id", clientOf(o), "ip", clientIP(ctx), "subject", l.subject(subjectOf(o)))
		case "flow.rejected":
			id, apps := flowOf(o)
			level := slog.LevelInfo
			if r.Audit {
				level = slog.LevelWarn // A3, a reject of what the dispatcher did not accept
			}
			l.logger.Log(ctx, level, "auth.failed", "flow", id, "steps", len(apps), "apps", apps, "result", "rejected", "reason", r.Detail,
				"client_id", clientOf(o), "ip", clientIP(ctx), "subject", l.subject(subjectOf(o)))
		case "skip.accepted":
			l.logger.InfoContext(ctx, "skip.accepted", "kind", r.Kind, "flow", r.Flow, "client_id", clientOf(o), "ip", clientIP(ctx))
		case "skip.ignored":
			id, _ := flowOf(o)
			l.logger.InfoContext(ctx, "skip.ignored", "kind", r.Kind, "reason", r.Reason, "flow", id, "client_id", clientOf(o), "ip", clientIP(ctx))
		case "step.subject_mismatch":
			id, _ := flowOf(o)
			app, rule := "", ""
			if f := o.Before; f != nil && f.Current >= 1 && f.Current <= len(f.Steps) {
				app, rule = f.Steps[f.Current-1].App, f.Steps[f.Current-1].Check
			}
			if rule == "" {
				rule = "same_accept" // no rule: a second accept of the step changed the subject
			}
			l.logger.WarnContext(ctx, "step.subject_mismatch", "flow", id, "app", app, "rule", rule, "client_id", clientOf(o), "ip", clientIP(ctx))
		case "logout.started":
			rp := r.RP != nil && *r.RP
			l.logger.InfoContext(ctx, "logout.started", "client_id", clientOf(o), "rp_initiated", rp, "apps", r.Apps, "again", r.Again,
				"ip", clientIP(ctx), "subject", l.subject(subjectOf(o)))
		case "logout.session_revoked":
			l.logger.InfoContext(ctx, "logout.session_revoked", "client_id", clientOf(o), "ip", clientIP(ctx), "subject", l.subject(subjectOf(o)))
		case "security.ip_rejected":
			surface, _, _ := strings.Cut(r.Detail, ":")
			l.Refused(ctx, surface)
		}
	}
}

// Refused writes a refusal of an IP filter on surface: emulated, metrics, or admin.
func (l *Log) Refused(ctx context.Context, surface string) {
	l.logger.WarnContext(ctx, "security.ip_rejected", "surface", surface, "ip", clientIP(ctx))
}
