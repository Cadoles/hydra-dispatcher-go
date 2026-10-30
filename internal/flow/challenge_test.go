package flow

import (
	"strings"
	"testing"
	"time"
)

func TestChallenge(t *testing.T) {
	ref := Ref("L")
	c := testKeys.Challenge(ref, 7, "sql", KindLogin)
	if len(c) != 32 || !strings.HasPrefix(c, ref) {
		t.Fatalf("challenge %q: want 32 characters starting with the ref %q", c, ref)
	}
	if got, ok := ChallengeRef(c); !ok || got != ref {
		t.Errorf("ChallengeRef = %q, %v; want %q", got, ok, ref)
	}
	if c != testKeys.Challenge(ref, 7, "sql", KindLogin) {
		t.Error("a challenge is not deterministic")
	}
	for _, other := range []string{
		testKeys.Challenge(ref, 8, "sql", KindLogin),
		testKeys.Challenge(ref, 7, "2fa", KindLogin),
		testKeys.Challenge(ref, 7, "sql", KindConsent),
		testKeys.Challenge(Ref("L2"), 7, "sql", KindLogin),
		Keys{oldKey}.Challenge(ref, 7, "sql", KindLogin),
	} {
		if other == c {
			t.Errorf("challenge %q signs another generation, app, kind, flow or key alike", c)
		}
	}
	// Without a separator, ref‖12‖3x and ref‖123‖x would be one message.
	if testKeys.Challenge(ref, 12, "3x", KindLogin) == testKeys.Challenge(ref, 123, "x", KindLogin) {
		t.Error("generation and app are not separated in the signed message")
	}
}

func TestChallengeRef(t *testing.T) {
	for _, tc := range []struct {
		name, challenge string
		ok              bool
	}{
		{"common checks 1, 32 hex", "0123456789abcdef0123456789abcdef", true},
		{"common checks 1, upper case is hex", "0123456789ABCDEF0123456789abcdef", true},
		{"EMU-1, 31 characters", "0123456789abcdef0123456789abcde", false},
		{"EMU-1, 33 characters", "0123456789abcdef0123456789abcdef0", false},
		{"EMU-1, not hex", "0123456789abcdef0123456789abcdeg", false},
		{"EMU-1, empty", "", false},
		{"EMU-1, a Hydra 2.2 challenge", strings.Repeat("A-_=", 8), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, ok := ChallengeRef(tc.challenge)
			if ok != tc.ok || ok && ref != tc.challenge[:20] {
				t.Errorf("ChallengeRef(%q) = %q, %v; want ok %v", tc.challenge, ref, ok, tc.ok)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	env := testEnv()
	apps := env.appIDs()
	ref := "0123456789abcdef0123"
	only := func(app string) func(string) bool { return func(a string) bool { return a == app } }
	running := func(mod func(f *Flow)) *Flow {
		f := &Flow{
			V: Format, FlowID: "hydra-sql-2fa", Gen0: 1000, Gen: 1003, Current: 2,
			Steps:          []Step{{App: "sql", LoginOK: true, ConsentOK: true}, {App: "2fa"}},
			ExpiresAt:      testNow.UnixMilli(),
			HydraExpiresAt: testNow.Add(time.Hour).UnixMilli(),
		}
		if mod != nil {
			mod(f)
		}
		return f
	}
	sign := func(keys Keys, gen int64, app string, kind Kind) string { return keys.Challenge(ref, gen, app, kind) }

	for _, tc := range []struct {
		name      string
		flow      *Flow
		challenge string
		kind      Kind
		caller    func(string) bool
		now       time.Time
		want      Check
	}{
		{"common checks 8, current step", running(nil), sign(testKeys, 1003, "2fa", KindLogin), KindLogin, only("2fa"), testNow,
			Check{Verdict: ChallengeCurrent, App: "2fa", Step: 2}},
		{"common checks 8, past step", running(nil), sign(testKeys, 1003, "sql", KindConsent), KindConsent, only("sql"), testNow,
			Check{Verdict: ChallengeCurrent, App: "sql", Step: 1}},
		{"I1, valid until exp inclusive", running(nil), sign(testKeys, 1003, "2fa", KindLogin), KindLogin, only("2fa"), testNow,
			Check{Verdict: ChallengeCurrent, App: "2fa", Step: 2}},
		{"common checks 3, previous key verifies", running(nil), sign(Keys{oldKey}, 1003, "2fa", KindLogin), KindLogin, only("2fa"), testNow,
			Check{Verdict: ChallengeCurrent, App: "2fa", Step: 2}},
		{"EMU-3, future step", running(func(f *Flow) { f.Current = 1 }), sign(testKeys, 1003, "2fa", KindLogin), KindLogin, only("2fa"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-3, other kind", running(nil), sign(testKeys, 1003, "2fa", KindLogin), KindConsent, only("2fa"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-3, unknown key", running(nil), sign(Keys{[]byte("another key of thirty-two bytes!")}, 1003, "2fa", KindLogin), KindLogin, only("2fa"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-3, app outside the flow and the snapshot", running(nil), sign(testKeys, 1003, "ghost", KindLogin), KindLogin, only("ghost"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-3, before g0", running(nil), sign(testKeys, 999, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-3 Q26, beyond 16 generations", running(func(f *Flow) { f.Gen0, f.Gen = 0, 100 }), sign(testKeys, 83, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-3, choice flow, current generation", running(func(f *Flow) { f.FlowID, f.Current, f.Steps = "", 0, nil }), sign(testKeys, 1003, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeForged}},
		{"EMU-4, other app", running(nil), sign(testKeys, 1003, "2fa", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeOtherApp, App: "2fa"}},
		{"EMU-4, no caller", running(nil), sign(testKeys, 1003, "2fa", KindLogin), KindLogin, nil, testNow,
			Check{Verdict: ChallengeOtherApp, App: "2fa"}},
		{"EMU-4 before EMU-5", running(func(f *Flow) { *f = *f.Reduce() }), sign(testKeys, 1003, "sql", KindLogin), KindLogin, only("2fa"), testNow,
			Check{Verdict: ChallengeOtherApp, App: "sql"}},
		{"EMU-5 Q28, finished flow, current generation", running(func(f *Flow) { *f = *f.Reduce() }), sign(testKeys, 1003, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeFinished, App: "sql"}},
		{"EMU-5, finished flow, former generation", running(func(f *Flow) { *f = *f.Reduce() }), sign(testKeys, 1001, "oidc", KindConsent), KindConsent, only("oidc"), testNow,
			Check{Verdict: ChallengeFinished, App: "oidc"}},
		{"EMU-6, expired", running(nil), sign(testKeys, 1003, "2fa", KindLogin), KindLogin, only("2fa"), testNow.Add(time.Millisecond),
			Check{Verdict: ChallengeExpired, App: "2fa"}},
		{"EMU-6 before EMU-7", running(nil), sign(testKeys, 1002, "2fa", KindLogin), KindLogin, only("2fa"), testNow.Add(time.Millisecond),
			Check{Verdict: ChallengeExpired, App: "2fa"}},
		{"EMU-7, previous generation", running(nil), sign(testKeys, 1002, "oidc", KindLogin), KindLogin, only("oidc"), testNow,
			Check{Verdict: ChallengeStale, App: "oidc"}},
		{"EMU-7, g0", running(nil), sign(testKeys, 1000, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeStale, App: "sql"}},
		{"EMU-7 Q26, 16 generations back", running(func(f *Flow) { f.Gen0, f.Gen = 0, 100 }), sign(Keys{oldKey}, 84, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeStale, App: "sql"}},
		{"EMU-7, step app removed from the snapshot", running(func(f *Flow) { f.Steps[1].App = "gone" }), sign(testKeys, 1001, "gone", KindLogin), KindLogin, only("gone"), testNow,
			Check{Verdict: ChallengeStale, App: "gone"}},
		{"EMU-7, choice flow", running(func(f *Flow) { f.FlowID, f.Current, f.Steps = "", 0, nil }), sign(testKeys, 1002, "sql", KindLogin), KindLogin, only("sql"), testNow,
			Check{Verdict: ChallengeStale, App: "sql"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := testKeys.Verify(tc.flow, tc.challenge, tc.kind, apps, tc.caller, tc.now); got != tc.want {
				t.Errorf("Verify = %+v; want %+v", got, tc.want)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	if ChallengeForged.String() != "forged" || ChallengeCurrent.String() != "current" {
		t.Errorf("verdict names: %s, %s", ChallengeForged, ChallengeCurrent)
	}
}
