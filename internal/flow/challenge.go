package flow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"time"
)

const (
	refLen       = 20
	signatureLen = 12
	challengeLen = refLen + signatureLen
	// Generations is how many former generations a challenge is still
	// recognised from as stale (Q26): beyond, it matches nothing. Without a
	// bound, whoever chains returns to the choice on their own
	// authentication would make every call of the emulated API pay one HMAC
	// per generation and app.
	Generations = 16
)

// Kind is the kind of a step challenge, that of the endpoint it is sent to.
type Kind string

const (
	KindLogin   Kind = "login"
	KindConsent Kind = "consent"
	// KindLogout signs a logout's challenge, whose generation is the position
	// in its chain.
	KindLogout Kind = "logout"
)

// Keys are secrets.challenge_key then secrets.challenge_keys_previous: the
// first signs, all verify, for a rotation without downtime.
type Keys [][]byte

// Challenge returns the challenge of a step: ref ‖ hex(HMAC(ref|gen|app|kind))
// cut to 12 characters, 32 hexadecimal characters as the apps expect. The
// separator is in no app id: without it, generation 12 of app 3x and
// generation 123 of app x would sign alike.
func (k Keys) Challenge(ref string, gen int64, app string, kind Kind) string {
	return ref + signature(k[0], ref, gen, app, kind)
}

func signature(key []byte, ref string, gen int64, app string, kind Kind) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(ref + "|" + strconv.FormatInt(gen, 10) + "|" + app + "|" + string(kind)))
	return hex.EncodeToString(m.Sum(nil))[:signatureLen]
}

// ChallengeRef returns the reference a step challenge carries, its first 20
// characters, or false for one that is not 32 hexadecimal characters
// (point 1 of the common checks, EMU-1).
func ChallengeRef(challenge string) (string, bool) {
	if len(challenge) != challengeLen {
		return "", false
	}
	for _, c := range []byte(challenge) {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return "", false
		}
	}
	return challenge[:refLen], true
}

// Verdict is the outcome of a step challenge's checks.
type Verdict int

const (
	// ChallengeForged: no signature matches, or only a future step's
	// (EMU-3): served as an unknown challenge.
	ChallengeForged Verdict = iota
	// ChallengeOtherApp: the challenge's app is not the caller (EMU-4).
	ChallengeOtherApp
	// ChallengeFinished: the flow is finished (EMU-5).
	ChallengeFinished
	// ChallengeExpired: the flow is past ExpiresAt, not accepted on Hydra
	// (EMU-6). An accepted flow's challenges get the answers of an accepted
	// flow: its expiry is its consent's (Q31).
	ChallengeExpired
	// ChallengeStale: one of the 16 former generations (EMU-7).
	ChallengeStale
	// ChallengeCurrent: the current generation, step Check.Step.
	ChallengeCurrent
)

var verdictNames = [...]string{"forged", "other_app", "finished", "expired", "stale", "current"}

func (v Verdict) String() string { return verdictNames[v] }

// Check is a verified challenge.
type Check struct {
	Verdict Verdict
	// App is the app the signature names, "" when forged.
	App string
	// Step is the position of the challenge's step, from 1, on the current
	// generation of a flow that has steps.
	Step int
}

// Verify checks a step challenge against f, the flow read under its
// reference, in the order of the common checks of the emulated API, points 3
// to 7; point 8, the step against the current one, is the endpoint's.
// apps are the ids of the configuration snapshot; caller tells whether the
// app identified by its sources (P4) is the one named; nil refuses all.
//
// Signatures are compared in constant time with each pair possible: the
// current generation with the apps of the flow's steps, then the former
// generations, at most 16 and none before Gen0, with the snapshot's apps.
// A flow without steps compares its current generation with the snapshot's
// apps too (Q28): reduced, a finished flow still recognises its challenges.
func (k Keys) Verify(f *Flow, challenge string, kind Kind, apps []string, caller func(app string) bool, now time.Time) Check {
	ref, sig := challenge[:refLen], challenge[refLen:]
	gen, app, step, ok := k.match(f, ref, sig, kind, apps)
	switch {
	case !ok:
		return Check{Verdict: ChallengeForged}
	case gen == f.Gen && len(f.Steps) > 0 && step > f.Current:
		// A future step's challenge cannot have been served.
		return Check{Verdict: ChallengeForged}
	case gen == f.Gen && len(f.Steps) == 0 && !f.Done:
		// A flow in choice has issued no challenge of its generation.
		return Check{Verdict: ChallengeForged}
	case caller == nil || !caller(app):
		return Check{Verdict: ChallengeOtherApp, App: app}
	case f.Done:
		return Check{Verdict: ChallengeFinished, App: app}
	case now.UnixMilli() > f.ExpiresAt && f.HydraRedirect == "":
		return Check{Verdict: ChallengeExpired, App: app}
	case gen < f.Gen:
		return Check{Verdict: ChallengeStale, App: app}
	}
	return Check{Verdict: ChallengeCurrent, App: app, Step: step}
}

// match finds the generation and the app whose signature is sig, and the
// position of the app's step on the current generation (0 elsewhere).
func (k Keys) match(f *Flow, ref, sig string, kind Kind, apps []string) (int64, string, int, bool) {
	equal := func(key []byte, gen int64, app string) bool {
		return hmac.Equal([]byte(signature(key, ref, gen, app, kind)), []byte(sig))
	}
	for _, key := range k {
		if len(f.Steps) == 0 {
			for _, app := range apps {
				if equal(key, f.Gen, app) {
					return f.Gen, app, 0, true
				}
			}
		}
		for i, s := range f.Steps {
			if equal(key, f.Gen, s.App) {
				return f.Gen, s.App, i + 1, true
			}
		}
	}
	former := apps
	for _, s := range f.Steps {
		if !slices.Contains(former, s.App) {
			former = append(slices.Clip(former), s.App)
		}
	}
	for gen := f.Gen - 1; gen >= max(f.Gen0, f.Gen-Generations); gen-- {
		for _, key := range k {
			for _, app := range former {
				if equal(key, gen, app) {
					return gen, app, 0, true
				}
			}
		}
	}
	return 0, "", 0, false
}
