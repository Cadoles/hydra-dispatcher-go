package flow

import (
	"encoding/json"
	"testing"
)

// MEM-7: the fingerprint of a flow's steps, their apps in order.
func TestComposition(t *testing.T) {
	sql2fa := Composition([]string{"sql", "2fa"})
	for _, c := range []struct {
		name string
		apps []string
		same bool
	}{
		{"MEM-7, the same apps", []string{"sql", "2fa"}, true},
		{"MEM-7, in another order", []string{"2fa", "sql"}, false},
		{"MEM-7, one app less", []string{"sql"}, false},
		{"MEM-7, an app renamed across the separator", []string{"sql2", "fa"}, false},
	} {
		if got := Composition(c.apps); (got == sql2fa) != c.same {
			t.Errorf("%s: %s, sql then 2fa %s", c.name, got, sql2fa)
		}
	}
	if len(sql2fa) != 16 || Composition(nil) != Composition([]string{}) {
		t.Errorf("fh %q; of no app %q and %q", sql2fa, Composition(nil), Composition([]string{}))
	}
	if got := atStep(t, 2, true, true).composition(); got != sql2fa {
		t.Errorf("composition of hydra-sql-2fa's steps %s, want %s", got, sql2fa)
	}
}

// Q38: the marker signs the session, the subject, the acr, the amr and the
// request_url's SHA-256; any of them changed gives another marker, and an
// amr absent is the same as an empty one, as Hydra serves it [].
func TestSkipMarker(t *testing.T) {
	const url = "http://public.hydra.test/oauth2/auth?client_id=c&nonce=n&state=s"
	amr := []string{"pwd", "otp"}
	marker := testKeys.SkipMarker(sessionID, "alice", "2", amr, url)
	for _, c := range []struct {
		name               string
		sid, sub, acr, url string
		amr                []string
		valid              bool
	}{
		{"Q38, the same values", sessionID, "alice", "2", url, amr, true},
		{"SKC-8, another session", "other", "alice", "2", url, amr, false},
		{"SKC-8, another subject", sessionID, "bob", "2", url, amr, false},
		{"SKC-8, another acr", sessionID, "alice", "1", url, amr, false},
		{"SKC-8, another amr", sessionID, "alice", "2", url, []string{"pwd"}, false},
		{"SKC-8, the amr in another order", sessionID, "alice", "2", url, []string{"otp", "pwd"}, false},
		{"SKC-8, another request_url (state)", sessionID, "alice", "2", url + "x", amr, false},
		{"SKC-8, members shifted across a separator", sessionID, "alice2", "", url, amr, false},
	} {
		if got := testKeys.validSkipMarker(marker, c.sid, c.sub, c.acr, c.amr, c.url); got != c.valid {
			t.Errorf("%s: valid %v, want %v", c.name, got, c.valid)
		}
	}
	if testKeys.SkipMarker(sessionID, "alice", "2", nil, url) != testKeys.SkipMarker(sessionID, "alice", "2", []string{}, url) {
		t.Error("Q38: an amr absent and an empty one sign apart")
	}
	// Rotation des clés: signed by the key now previous, still valid; by
	// none of the keys, not.
	former := Keys{oldKey}.SkipMarker(sessionID, "alice", "2", amr, url)
	if !testKeys.validSkipMarker(former, sessionID, "alice", "2", amr, url) {
		t.Error("a marker of the previous key refused")
	}
	if (Keys{[]byte("another key, of 32 bytes........")}).validSkipMarker(marker, sessionID, "alice", "2", amr, url) {
		t.Error("a marker of another key accepted")
	}
	// Not a step challenge's signature, nor a claims print.
	if marker == testKeys.ClaimsPrint(nil, nil) || len(marker) != 64 {
		t.Errorf("marker %q", marker)
	}
}

// Q37, SKC-12: the print of the claims a screen without a flow shows.
func TestClaimsPrint(t *testing.T) {
	idt := Object{"email": json.RawMessage(`"alice@example.org"`), "name": json.RawMessage(`"Alice"`)}
	print := testKeys.ClaimsPrint(idt, Object{})
	for _, c := range []struct {
		name     string
		idt, act Object
		valid    bool
	}{
		{"Q37, the same claims", idt, Object{}, true},
		{"Q37, the same claims, written otherwise", Object{"name": json.RawMessage(` "Alice"`), "email": json.RawMessage(`"alice@example.org" `)}, nil, true},
		{"SKC-12, a claim changed", Object{"email": json.RawMessage(`"bob@example.org"`), "name": json.RawMessage(`"Alice"`)}, Object{}, false},
		{"SKC-12, a claim more", Object{"email": json.RawMessage(`"alice@example.org"`), "name": json.RawMessage(`"Alice"`), "x": json.RawMessage(`1`)}, Object{}, false},
		{"SKC-12, moved to the access token", Object{"name": json.RawMessage(`"Alice"`)}, Object{"email": json.RawMessage(`"alice@example.org"`)}, false},
	} {
		if got := testKeys.validClaimsPrint(print, c.idt, c.act); got != c.valid {
			t.Errorf("%s: valid %v, want %v", c.name, got, c.valid)
		}
	}
	if !testKeys.validClaimsPrint(Keys{oldKey}.ClaimsPrint(idt, nil), idt, nil) {
		t.Error("a print of the previous key refused")
	}
}

// SKP-11: the prompt of the authorization request, as request_url shows it.
func TestPromptNone(t *testing.T) {
	for raw, want := range map[string]bool{
		"":                                 false,
		"http://h/oauth2/auth":             false,
		"http://h/oauth2/auth?prompt=none": true,
		"http://h/oauth2/auth?client_id=c&prompt=none&state=s":             true,
		"http://h/oauth2/auth?prompt=none+login":                           true,
		"http://h/oauth2/auth?prompt=login":                                false,
		"http://h/oauth2/auth?prompt=consent":                              false,
		"http://h/oauth2/auth?prompt=nonesuch":                             false,
		"http://h/oauth2/auth?state=prompt%3Dnone":                         false,
		"http://h/oauth2/auth?redirect_uri=http%3A%2F%2Fc%3Fprompt%3Dnone": false,
		"http://h\x7f/%zz":                                                 false,
	} {
		if got := promptNone(raw); got != want {
			t.Errorf("promptNone(%q) = %v, want %v", raw, got, want)
		}
	}
}
