package flow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// RememberedFormat is the version of the remembered login (v): a cookie of
// another version is unreadable (MEM-2).
const RememberedFormat = 1

// Remembered is the content of the dispatcher_remember cookie, the memory of
// the skip (Mémoire du skip): what the final login accept and the consent
// accept sent, to send again when Hydra says skip. Written once, at the
// consent accept that finishes the flow (WRT-1, Q39); internal/remember
// seals it. Times are Unix seconds.
type Remembered struct {
	V int `json:"v"`
	// SID and Sub bind it to Hydra's session and subject (MEM-4, MEM-5).
	SID string `json:"sid"`
	Sub string `json:"sub"`
	// Flow and FH are the flow chosen and the fingerprint of its steps
	// (MEM-6, MEM-7).
	Flow string `json:"flow"`
	FH   string `json:"fh"`
	// ACR, AMR and Ctx are those of the final login accept, after the
	// webhook; Ctx without x_dispatcher_* members.
	ACR string   `json:"acr"`
	AMR []string `json:"amr"`
	Ctx Object   `json:"ctx,omitempty"`
	// Scp are the scopes the consent granted (MEM-8); IDT and ACT its claims,
	// after the webhook.
	Scp []string `json:"scp"`
	IDT Object   `json:"idt,omitempty"`
	ACT Object   `json:"act,omitempty"`
	IAT int64    `json:"iat"`
	// Exp is iat plus the remember_for sent; 0 for remember_for 0, a cookie
	// of the browser's session, as Hydra's then is.
	Exp int64 `json:"exp,omitempty"`
}

// Memory is the dispatcher_remember cookie as a page read it: its content,
// or why there is none. The zero value is a cookie absent.
type Memory struct {
	Content *Remembered
	// Reason is why Content is nil (MEM-1, MEM-2): SkipAbsent, the cookie or
	// its second part missing, or SkipUnreadable, no key opening it, or of a
	// version unknown. "" counts as absent.
	Reason string
}

// The reasons of skip.ignored (doc, Journalisation), one per check of the
// cookie, MEM-1 to MEM-9 in order.
const (
	SkipAbsent      = "absent"
	SkipUnreadable  = "unreadable"
	SkipExpired     = "expired"
	SkipSession     = "session"
	SkipSubject     = "subject"
	SkipFlow        = "flow"
	SkipComposition = "composition"
	SkipScopes      = "scopes"
	SkipACR         = "acr"
)

// Composition is the fingerprint of a flow's steps, their apps in order
// (fh, MEM-7): a truncated SHA-256 of their JSON list.
func Composition(apps []string) string {
	if apps == nil {
		apps = []string{}
	}
	data, _ := json.Marshal(apps) // a list of strings always marshals
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// composition is the fingerprint of the steps f followed.
func (f *Flow) composition() string {
	apps := make([]string, len(f.Steps))
	for i, s := range f.Steps {
		apps[i] = s.App
	}
	return Composition(apps)
}

// SkipMarker is x_dispatcher_skip (Q22, Q38): the HMAC, by the active
// challenge key, of the session, the subject, the acr and the amr sent at the
// accept of a login in skip, and of the SHA-256 of the login request's
// request_url, which carries the client's state and nonce. Hydra gives them
// back as they were in the consent request that follows: the consent without
// a flow requires the marker on them, a marker copied from another consent
// request only standing for the same authorization request. An amr absent is
// [], as Hydra serves it.
func (k Keys) SkipMarker(sid, sub, acr string, amr []string, requestURL string) string {
	return skipMarker(k[0], sid, sub, acr, amr, requestURL)
}

// validSkipMarker checks a marker with the active key then each previous
// one (Rotation des clés), in constant time.
func (k Keys) validSkipMarker(marker, sid, sub, acr string, amr []string, requestURL string) bool {
	for _, key := range k {
		if hmac.Equal([]byte(skipMarker(key, sid, sub, acr, amr, requestURL)), []byte(marker)) {
			return true
		}
	}
	return false
}

func skipMarker(key []byte, sid, sub, acr string, amr []string, requestURL string) string {
	if amr == nil {
		amr = []string{}
	}
	url := sha256.Sum256([]byte(requestURL))
	// A JSON list is unambiguous whatever the strings hold, and its first
	// member sets it apart from the step challenges' messages.
	return mac(key, []any{"dispatcher-skip", sid, sub, acr, amr, hex.EncodeToString(url[:])})
}

// ClaimsPrint is the fingerprint of the claims the consent screen without a
// flow shows (SKC-2, Q37): their HMAC by the active challenge key, which its
// form carries. At its POST, claims of the cookie read again that no longer
// give it were written meanwhile by another tab: the screen is shown again
// (SKC-12), what is sent being what was shown.
func (k Keys) ClaimsPrint(idt, act Object) string {
	return claimsPrint(k[0], idt, act)
}

// validClaimsPrint checks a fingerprint with the active key then each
// previous one, in constant time.
func (k Keys) validClaimsPrint(print string, idt, act Object) bool {
	for _, key := range k {
		if hmac.Equal([]byte(claimsPrint(key, idt, act)), []byte(print)) {
			return true
		}
	}
	return false
}

func claimsPrint(key []byte, idt, act Object) string {
	if idt == nil {
		idt = Object{}
	}
	if act == nil {
		act = Object{}
	}
	return mac(key, []any{"dispatcher-claims", idt, act})
}

// mac is the HMAC-SHA256 of the JSON of message, in hexadecimal. The members
// of an Object are sorted and its values compacted: the same claims give the
// same JSON.
func mac(key []byte, message []any) string {
	data, _ := json.Marshal(message) // strings, lists of strings and Objects
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}
