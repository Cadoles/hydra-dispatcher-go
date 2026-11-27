package flow

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"github.com/Cadoles/hydra-dispatcher-go/internal/hydra/flowcodec"
)

// hydraReader is the admin API of a fake Hydra, which counts its reads.
type hydraReader struct {
	r     *ory.OAuth2LoginRequest
	c     *ory.OAuth2ConsentRequest
	err   error
	got   string
	reads int
}

func (h *hydraReader) LoginRequest(_ context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	h.got, h.reads = challenge, h.reads+1
	if h.err != nil {
		return nil, h.err
	}
	return h.r, nil
}

func (h *hydraReader) ConsentRequest(_ context.Context, challenge string) (*ory.OAuth2ConsentRequest, error) {
	h.got, h.reads = challenge, h.reads+1
	if h.err != nil {
		return nil, h.err
	}
	return h.c, nil
}

// created is the flow ENT-1 creates at now from what the source gives for
// the login challenge l.
func created(t *testing.T, src Source, l string, now time.Time) *Flow {
	t.Helper()
	read := src.LoginRequest(context.Background(), l)
	if read.Err != nil {
		t.Fatal(read.Err)
	}
	env := testEnv()
	env.Now = now
	out := Decide(Input{Event: Entry{LoginChallenge: l, Cookie: cookie}, Loaded: true, Env: env, Answers: Answers{Login: &read}})
	if out.Write == nil {
		t.Fatalf("no flow created: %+v", out)
	}
	return out.Write
}

func TestFallback(t *testing.T) {
	r := loginRequest(t)
	r.RequestedAccessTokenAudience = nil
	h := &hydraReader{r: r, c: consentRequest(lref, nil)}
	src := Fallback{Hydra: h, Now: func() time.Time { return testNow }}

	// The first read stands for requested_at (ENT-1, Q2).
	f := created(t, src, hydraL, testNow)
	if h.got != hydraL {
		t.Errorf("read %q", h.got)
	}
	if f.HydraExpiresAt != testNow.Add(30*time.Minute).UnixMilli() || f.ExpiresAt != testNow.Add(29*time.Minute).UnixMilli() {
		t.Errorf("Q2, fallback: exp %d hx %d", f.ExpiresAt, f.HydraExpiresAt)
	}
	// A null audience is served [] (P3).
	if f.Hydra.Audience == nil {
		t.Error("audience null")
	}
	read := src.LoginRequest(context.Background(), hydraL)
	if got := read.Request.RequestedAccessTokenAudience; got == nil || len(got) != 0 {
		t.Errorf("audience %#v", got)
	}
	// Q34: Hydra 2.1 names L itself in the consent request; a 2.2
	// challenge read on the admin API gives no id.
	if read.LoginID != hydraL || f.Hydra.LoginID != hydraL || read.Decrypted || read.Reports != nil {
		t.Errorf("2.1: login id %q, kept %q, decrypted %v, reports %v", read.LoginID, f.Hydra.LoginID, read.Decrypted, read.Reports)
	}
	if read := src.LoginRequest(context.Background(), "A-_z0123456789abcdef0123456789ab=="); read.LoginID != "" {
		t.Errorf("2.2 in fallback: login id %q", read.LoginID)
	}
	if read := src.ConsentRequest(context.Background(), hydraC); read.Err != nil || read.Request.GetSubject() != "alice" || read.Decrypted {
		t.Errorf("consent %+v", read)
	}

	// Hydra's errors as internal/hydra gives them.
	h.err = err404
	if read := src.LoginRequest(context.Background(), hydraL); !errors.Is(read.Err, err404) || !read.RequestedAt.IsZero() || read.Request != nil {
		t.Errorf("login %+v", read)
	}
	if read := src.ConsentRequest(context.Background(), hydraC); !errors.Is(read.Err, err404) || read.Request != nil {
		t.Errorf("consent %+v", read)
	}
	h.err = nil
	if read := (Fallback{Hydra: h}).LoginRequest(context.Background(), hydraL); time.Since(read.RequestedAt) > time.Minute {
		t.Errorf("the default clock: %v", read.RequestedAt)
	}
}

// Challenges of Hydra 2.2 and 2.3, recorded by tools/flowfixtures against
// Hydras whose secrets.system is devSecret.
const (
	devSecret  = "youReallyNeedToChangeThis"
	fixtures22 = "../hydra/flowcodec/testdata/hydra-v2.2.0/"
	fixtures23 = "../hydra/flowcodec/testdata/hydra-v2.3.0/"
)

func challengeFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func newCodec(t *testing.T, v flowcodec.Version, secrets ...string) *flowcodec.Codec {
	t.Helper()
	c, err := flowcodec.New(v, secrets)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// DEC-2 to DEC-6 (Déchiffrement local of Table de transitions.md), with the
// reports of Q32: each read either decrypted without calling Hydra, or on
// the admin API, which then counts one read. A challenge the admin API does
// not know either is reported forged by the page that answers E1001 (ENT-12,
// CST-2), not by the read: the source says nothing of it, nor of a challenge
// past its lifetime (ENT-11, CST-4) or of Hydra's clock ahead, which the
// flow's creation reports (revue R18).
func TestDecrypt(t *testing.T) {
	l, c := challengeFixture(t, fixtures22+"login_challenge.txt"), challengeFixture(t, fixtures22+"consent_challenge.txt")
	codec := newCodec(t, flowcodec.Hydra22, devSecret)
	loginFlow, err := codec.LoginChallenge(l)
	if err != nil {
		t.Fatal(err)
	}
	requestedAt := loginFlow.RequestedAt
	other := newCodec(t, flowcodec.Hydra22, "a-secret-Hydra-does-not-have-0123")
	rotated := newCodec(t, flowcodec.Hydra22, "a-newer-system-secret-01234", devSecret)
	v23 := newCodec(t, flowcodec.Hydra23, devSecret)
	forged := "AAAA" + strings.Repeat("0123456789abcdefABCDEF-_", 6) + "=="

	for _, tc := range []struct {
		name      string
		codec     Codec
		consent   bool
		challenge string
		// at is now, from requestedAt; adminErr the admin API's answer.
		at       time.Duration
		adminErr error
		// What the read gives: decrypted or not, its error, the admin API's
		// reads, the report ("event detail", its start for decrypt_fallback).
		decrypted bool
		err       error
		reads     int
		report    string
	}{
		{name: "DEC-3, read locally", codec: codec, challenge: l, at: time.Minute, decrypted: true},
		{name: "DEC-3, the last instant of its lifetime", codec: codec, challenge: l, at: 30*time.Minute - time.Millisecond, decrypted: true},
		{name: "DEC-4, at its lifetime: gone, without a call, the page reports it", codec: codec, challenge: l, at: 30 * time.Minute,
			decrypted: true, err: ErrChallengeExpired},
		{name: "DEC-3, Hydra's clock 10 s ahead: read, the creation reports it", codec: codec, challenge: l, at: -10 * time.Second, decrypted: true},
		{name: "DEC-2, a Hydra 2.1 challenge: fallback, silent", codec: codec, challenge: hydraL, reads: 1},
		{name: "DEC-2, 32 hexadecimals unknown to Hydra: no decryption alert", codec: codec, challenge: "00000000000000000000000000000000",
			adminErr: err404, err: err404, reads: 1},
		{name: "DEC-5, no secret opens it, unknown to Hydra: no decryption alert (Q32)", codec: other, challenge: l, adminErr: err404,
			err: err404, reads: 1},
		{name: "DEC-5, random base64url", codec: codec, challenge: forged, adminErr: err404, err: err404, reads: 1},
		{name: "DEC-5, another purpose: a consent challenge as a login one", codec: codec, challenge: c, adminErr: err404,
			err: err404, reads: 1},
		{name: "DEC-5, Hydra knows it: a secret missing (Q32)", codec: other, challenge: l, reads: 1,
			report: "hydra.decrypt_fallback flowcodec: invalid challenge"},
		{name: "DEC-5, Hydra knows it, expired", codec: other, challenge: l, adminErr: err401, err: err401, reads: 1,
			report: "hydra.decrypt_fallback flowcodec: invalid challenge"},
		{name: "DEC-5, Hydra 2.1 knows it, handled (switch-over)", codec: other, challenge: l, adminErr: err410, err: err410, reads: 1,
			report: "hydra.decrypt_fallback flowcodec: invalid challenge"},
		{name: "DEC-5, Hydra unavailable: nothing to tell", codec: other, challenge: l, adminErr: errDown, err: errDown, reads: 1},
		{name: "rotation: the secret second in the list opens it", codec: rotated, challenge: l, at: time.Minute, decrypted: true},
		{name: "DEC-6, read as Hydra 2.3", codec: v23, challenge: l, reads: 1, report: "hydra.decrypt_fallback flowcodec: unexpected flow format"},
		{name: "DEC-3, a consent read locally", codec: codec, consent: true, challenge: c, at: time.Minute, decrypted: true},
		{name: "DEC-4, a consent at its lifetime", codec: codec, consent: true, challenge: c, at: 30 * time.Minute,
			decrypted: true, err: ErrChallengeExpired},
		{name: "DEC-5, a login challenge as a consent one", codec: codec, consent: true, challenge: l, adminErr: err404,
			err: err404, reads: 1},
		{name: "DEC-3, a consent, Hydra's clock ahead: nothing reported", codec: codec, consent: true, challenge: c, at: -time.Minute, decrypted: true},
		{name: "DEC-6, a consent read as Hydra 2.3", codec: v23, consent: true, challenge: c, reads: 1,
			report: "hydra.decrypt_fallback flowcodec: unexpected flow format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin := &hydraReader{r: loginRequest(t), c: consentRequest(lref, nil), err: tc.adminErr}
			now := requestedAt.Add(tc.at)
			src := Decrypt{Codec: tc.codec, Fallback: Fallback{Hydra: admin, Now: func() time.Time { return now }},
				TTL: 30 * time.Minute, Now: func() time.Time { return now }}
			var decrypted bool
			var err error
			var reports []Report
			if tc.consent {
				read := src.ConsentRequest(context.Background(), tc.challenge)
				decrypted, err, reports = read.Decrypted, read.Err, read.Reports
				if tc.decrypted && err == nil && (read.Request.GetChallenge() != tc.challenge || read.Request.GetLoginChallenge() != loginFlow.ID || read.Request.GetSubject() != "alice") {
					t.Errorf("consent request %+v", read.Request)
				}
			} else {
				read := src.LoginRequest(context.Background(), tc.challenge)
				decrypted, err, reports = read.Decrypted, read.Err, read.Reports
				if tc.decrypted && err == nil && (read.Request.GetChallenge() != tc.challenge || !read.RequestedAt.Equal(requestedAt) || read.LoginID != loginFlow.ID) {
					t.Errorf("login request %q at %v, login id %q", read.Request.GetChallenge(), read.RequestedAt, read.LoginID)
				}
			}
			if decrypted != tc.decrypted || !errors.Is(err, tc.err) || err == nil && tc.err != nil || admin.reads != tc.reads {
				t.Errorf("decrypted %v, err %v, admin reads %d; want %v, %v, %d", decrypted, err, admin.reads, tc.decrypted, tc.err, tc.reads)
			}
			var got []string
			for _, r := range reports {
				got = append(got, r.Event+" "+r.Detail)
			}
			switch {
			case tc.report == "" && len(got) > 0, tc.report != "" && (len(got) != 1 || !strings.HasPrefix(got[0], tc.report)):
				t.Errorf("reports %q; want %q", got, tc.report)
			}
		})
	}
}

// Decrypted, the flow ends with L at Hydra, from Hydra's requested_at (Q2),
// and keeps the id of L that the consent request names (Q34); DEC-4 is
// gone, as Hydra 2.2's 401.
func TestDecryptedSource(t *testing.T) {
	l := challengeFixture(t, fixtures23+"login_challenge.txt")
	codec := newCodec(t, flowcodec.Hydra23, devSecret)
	lf, err := codec.LoginChallenge(l)
	if err != nil {
		t.Fatal(err)
	}
	now := lf.RequestedAt.Add(10 * time.Minute)
	src := Decrypt{Codec: codec, Fallback: Fallback{Hydra: &hydraReader{}}, TTL: 30 * time.Minute, Now: func() time.Time { return now }}
	f := created(t, src, l, now)
	hx := lf.RequestedAt.Add(30 * time.Minute)
	exp := now.Add(testEnv().Config.Settings.ChallengeTTL)
	if bound := hx.Add(-hydraMargin); bound.Before(exp) {
		exp = bound
	}
	if f.HydraExpiresAt != hx.UnixMilli() || f.ExpiresAt != exp.UnixMilli() || f.Hydra.LoginID != lf.ID {
		t.Errorf("Q2, decrypted: exp %d hx %d, login id %q; want %d, %d, %q", f.ExpiresAt, f.HydraExpiresAt, f.Hydra.LoginID, exp.UnixMilli(), hx.UnixMilli(), lf.ID)
	}
	if classify(ErrChallengeExpired) != gone {
		t.Error("DEC-4 is not gone")
	}
}

// flowCodec opens every challenge as f.
type flowCodec struct{ f *flowcodec.Flow }

func (c flowCodec) LoginChallenge(string) (*flowcodec.Flow, error)   { return c.f, nil }
func (c flowCodec) ConsentChallenge(string) (*flowcodec.Flow, error) { return c.f, nil }

// DEC-6: a flow opened and read whose request does not build (its client is
// not an object) falls back, as a flow of another format.
func TestDecryptUnbuilt(t *testing.T) {
	f := &flowcodec.Flow{ID: hydraFlowID, RequestedAt: testNow, Client: []byte(`[]`), RequestURL: "http://public.hydra.test/oauth2/auth", Subject: "alice"}
	admin := &hydraReader{r: loginRequest(t), c: consentRequest(lref, nil)}
	src := Decrypt{Codec: flowCodec{f}, Fallback: Fallback{Hydra: admin}, TTL: 30 * time.Minute, Now: func() time.Time { return testNow }}
	login, consent := src.LoginRequest(context.Background(), hydraL), src.ConsentRequest(context.Background(), hydraC)
	for _, read := range []struct {
		decrypted bool
		err       error
		reports   []Report
	}{{login.Decrypted, login.Err, login.Reports}, {consent.Decrypted, consent.Err, consent.Reports}} {
		if read.decrypted || read.err != nil || len(read.reports) != 1 || read.reports[0].Event != "hydra.decrypt_fallback" ||
			read.reports[0].Detail != "flowcodec: unexpected flow format: the request does not build" {
			t.Errorf("read %+v", read)
		}
	}
	if admin.reads != 2 {
		t.Errorf("admin reads %d", admin.reads)
	}
}
