//go:build integration

package store

import (
	"context"
	"errors"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"slices"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seal"
)

// keyA and keyB are keys of the pre-check, in hex and base64.
var (
	keyA = strings.Repeat("0a", 32)
	keyB = "s7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7M="
)

// rawAppKey is the skip_check_key the table holds for the app id.
func rawAppKey(t *testing.T, p *Postgres, id string) string {
	t.Helper()
	var v *string
	if err := p.db.QueryRow(`SELECT skip_check_key FROM app WHERE id = $1`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return ""
	}
	return *v
}

// flowOf is the flow id of snap.
func flowOf(t *testing.T, snap *Snapshot, id string) Flow {
	t.Helper()
	i := slices.IndexFunc(snap.Flows, func(f Flow) bool { return f.ID == id })
	if i < 0 {
		t.Fatalf("no flow %s", id)
	}
	return snap.Flows[i]
}

func skipCheckApp(id, key string) App {
	return App{ID: id, LoginURL: "https://" + id + "/login", ConsentURL: "https://" + id + "/consent", Method: "otp", AuthMode: "network",
		SkipCheckURL: "https://" + id + "/skip-check", SkipCheckKey: key, SkipCheckSignals: []string{"ip", "device_age"}}
}

// The key of the pre-check of an app (P26): encrypted in its row, bound to
// the app, in clear in the snapshot; refused without secrets.encryption_key;
// kept when unchanged; named by secrets status; turned by Rekey, once.
func TestSkipCheckKeyOnPostgres(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	if err := p.CreateApp(ctx, "test", skipCheckApp("a", keyA)); !violated(err, "skip_check_key") {
		t.Fatalf("without secrets.encryption_key: %v", err)
	}
	p.SetSecrets(keyring(t, encKeyA))
	if err := p.CreateApp(ctx, "test", skipCheckApp("a", keyA)); err != nil {
		t.Fatal(err)
	}
	raw := rawAppKey(t, p, "a")
	if strings.Contains(raw, keyA) || !strings.HasPrefix(raw, "v1:"+seal.KeyID(encKeyA)+":") {
		t.Errorf("in the table: %s", raw)
	}
	snap, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := snap.App("a")
	if a.SkipCheckKey != keyA || a.SkipCheckURL != "https://a/skip-check" || !slices.Equal(a.SkipCheckSignals, []string{"ip", "device_age"}) {
		t.Errorf("snapshot: %+v", a)
	}
	if snap.Encrypted["apps.a.skip_check_key"] != seal.KeyID(encKeyA) || snap.Sealed["apps.a.skip_check_key"] == "" {
		t.Errorf("encrypted values: %v %v", snap.Encrypted, snap.Sealed)
	}
	// Another field changed: the key keeps its row, and its digest.
	if err := p.UpdateApp(ctx, "test", "a", func(a *App) error { a.Method = "totp"; return nil }); err != nil {
		t.Fatal(err)
	}
	if after := rawAppKey(t, p, "a"); after != raw {
		t.Error("an unchanged key sealed again")
	}
	// Another key: sealed again.
	if err := p.UpdateApp(ctx, "test", "a", func(a *App) error { a.SkipCheckKey = keyB; return nil }); err != nil {
		t.Fatal(err)
	}
	if after := rawAppKey(t, p, "a"); after == raw {
		t.Error("a new key not written")
	}
	if snap, _ := p.Snapshot(ctx); snap.Apps[0].SkipCheckKey != keyB || snap.Sealed["apps.a.skip_check_key"] == "" {
		t.Errorf("new key: %+v", snap.Apps[0])
	}

	// Bound to its app: the value of a copied to b opens nowhere.
	if err := p.CreateApp(ctx, "test", skipCheckApp("b", keyA)); err != nil {
		t.Fatal(err)
	}
	ofB := rawAppKey(t, p, "b")
	exec(t, p, `UPDATE app SET skip_check_key = (SELECT skip_check_key FROM app WHERE id = 'a') WHERE id = 'b'`)
	var u unreadable
	if _, err := p.Snapshot(ctx); !errors.As(err, &u) || !strings.Contains(err.Error(), "app b: skip_check_key") {
		t.Errorf("a key copied to another app: %v", err)
	}
	exec(t, p, `UPDATE app SET skip_check_key = '`+ofB+`' WHERE id = 'b'`)

	// secrets status, then a rotation: the previous key opens, Rekey turns
	// both apps once, their authors kept.
	l, err := p.EncryptedSettings(ctx)
	if err != nil || !slices.Equal(l, []EncryptedSetting{{"apps.a.skip_check_key", seal.KeyID(encKeyA)}, {"apps.b.skip_check_key", seal.KeyID(encKeyA)}}) {
		t.Errorf("EncryptedSettings = %v, %v", l, err)
	}
	p.SetSecrets(keyring(t, encKeyB, encKeyA))
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatalf("under the previous key: %v", err)
	}
	done, err := p.Rekey(ctx)
	if err != nil || !slices.Equal(done, []string{"apps.a.skip_check_key", "apps.b.skip_check_key"}) {
		t.Errorf("Rekey = %q, %v", done, err)
	}
	if done, err := p.Rekey(ctx); err != nil || len(done) != 0 {
		t.Errorf("Rekey again = %q, %v", done, err)
	}
	p.SetSecrets(keyring(t, encKeyB))
	snap, err = p.Snapshot(ctx)
	if err != nil || snap.Apps[0].SkipCheckKey != keyB || snap.Apps[1].SkipCheckKey != keyA {
		t.Fatalf("after Rekey, under the new key alone: %v", err)
	}
	var by string
	if err := p.db.QueryRow(`SELECT updated_by FROM app WHERE id = 'a'`).Scan(&by); err != nil || by != "test" {
		t.Errorf("updated_by after Rekey = %q, %v", by, err)
	}
	// Without the URL, neither key nor signals: the row holds none.
	if err := p.UpdateApp(ctx, "test", "b", func(a *App) error {
		a.SkipCheckURL, a.SkipCheckKey, a.SkipCheckSignals = "", "", nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if raw := rawAppKey(t, p, "b"); raw != "" {
		t.Errorf("key of an app without the pre-check: %q", raw)
	}
}

// The steps that ask for the pre-check: never the first, only on an app with
// a URL, which then keeps it; the acr values a flow tolerates kept.
func TestSkipCheckStepsOnPostgres(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	p.SetSecrets(keyring(t, encKeyA))
	plain := skipCheckApp("pwd", "")
	plain.SkipCheckURL, plain.SkipCheckSignals = "", nil
	for _, a := range []App{plain, skipCheckApp("otp", keyA)} {
		if err := p.CreateApp(ctx, "test", a); err != nil {
			t.Fatal(err)
		}
	}
	f := Flow{ID: "f", Title: map[string]string{"fr": "F"}, Description: map[string]string{"fr": "D"}, Enabled: true,
		SkipCheckAllowedACR: []string{"loa1", "loa2"},
		Steps:               []Step{{AppID: "pwd", Position: 0, SubjectCheck: "none"}, {AppID: "otp", Position: 1, SubjectCheck: "equal", SkipCheck: true}}}
	first := f
	first.Steps = []Step{{AppID: "otp", Position: 0, SubjectCheck: "none", SkipCheck: true}, {AppID: "pwd", Position: 1, SubjectCheck: "none"}}
	if err := p.CreateFlow(ctx, "test", first); !violated(err, "steps[0].skip_check") {
		t.Errorf("on the first step: %v", err)
	}
	noURL := f
	noURL.Steps = []Step{{AppID: "otp", Position: 0, SubjectCheck: "none"}, {AppID: "pwd", Position: 1, SubjectCheck: "none", SkipCheck: true}}
	var refused *RefusedError
	if err := p.CreateFlow(ctx, "test", noURL); !errors.As(err, &refused) || !strings.Contains(err.Error(), "app pwd has no skip_check_url") {
		t.Errorf("on an app without a URL: %v", err)
	}
	if err := p.CreateFlow(ctx, "test", f); err != nil {
		t.Fatal(err)
	}
	snap, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := flowOf(t, snap, "f")
	if !slices.Equal(got.SkipCheckAllowedACR, f.SkipCheckAllowedACR) || got.Steps[0].SkipCheck || !got.Steps[1].SkipCheck {
		t.Errorf("flow read back: %+v", got)
	}
	// The app of a step that asks for the pre-check keeps its URL.
	err = p.UpdateApp(ctx, "test", "otp", func(a *App) error {
		a.SkipCheckURL, a.SkipCheckKey, a.SkipCheckSignals = "", "", nil
		return nil
	})
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), "flow f: steps[1].skip_check: app otp has no skip_check_url") {
		t.Errorf("URL removed under a step: %v", err)
	}
	// A flow without the tolerated values reads them back as none.
	if err := p.UpdateFlow(ctx, "test", "f", func(f *Flow) error { f.SkipCheckAllowedACR = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if snap, _ := p.Snapshot(ctx); snap.Flows[0].SkipCheckAllowedACR != nil {
		t.Errorf("no tolerated acr: %q", snap.Flows[0].SkipCheckAllowedACR)
	}
}

// bootstrap and the pre-check: a seed that names the URL without the key
// keeps the key held, as config dump writes it; another key is a change of a
// secret, shown without its value.
func TestBootstrapSkipCheck(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	p.SetSecrets(keyring(t, encKeyA))
	seed := func(key string) string {
		return `
dispatcher:
  apps:
    - { id: pwd, login_url: https://pwd/login, consent_url: https://pwd/consent, method: pwd }
    - { id: otp, login_url: https://otp/login, consent_url: https://otp/consent, method: otp,
        skip_check_url: https://otp/skip-check, ` + key + ` skip_check_signals: [full_ip, user_agent] }
  flows:
    - { id: f, title: F, description: D, skip_check_allowed_acr: [loa2],
        steps: [{ id: pwd, order: 0 }, { id: otp, order: 1, skip_check: true }] }
`
	}
	if _, err := p.Bootstrap(ctx, loadSeed(t, seed("skip_check_key: "+keyA+",")), Force, true); err != nil {
		t.Fatal(err)
	}
	raw := rawAppKey(t, p, "otp")
	changes, err := p.Bootstrap(ctx, loadSeed(t, seed("")), Force, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := actions(changes); !slices.Contains(got, "same app otp") || !slices.Contains(got, "same flow f") {
		t.Errorf("without the key: %q", got)
	}
	if after := rawAppKey(t, p, "otp"); after != raw {
		t.Error("the key held rewritten by a seed without it")
	}
	changes, err = p.Bootstrap(ctx, loadSeed(t, seed("skip_check_key: '"+keyB+"',")), Force, false)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(changes, func(c Change) bool { return c.Kind == "app" && c.ID == "otp" })
	if i < 0 || len(changes[i].Fields) != 1 || changes[i].Fields[0] != (FieldChange{Name: "skip_check_key", Secret: true}) {
		t.Errorf("another key: %+v", changes)
	}
	snap, _ := p.Snapshot(ctx)
	if f := flowOf(t, snap, "f"); !f.Steps[1].SkipCheck || !slices.Equal(f.SkipCheckAllowedACR, []string{"loa2"}) {
		t.Errorf("flow: %+v", f)
	}
}

// R48, B1: a seed that names the URL without the key, on a database that
// holds none, is refused, by the dry run too, and writes nothing; an empty
// ${K} does the same.
func TestBootstrapSkipCheckWithoutKey(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	p.SetSecrets(keyring(t, encKeyA))
	for _, key := range []string{"", "skip_check_key: '',"} {
		seed := loadSeed(t, `
dispatcher:
  apps:
    - { id: pwd, login_url: https://pwd/login, consent_url: https://pwd/consent, method: pwd }
    - { id: otp, login_url: https://otp/login, consent_url: https://otp/consent, method: otp,
        skip_check_url: https://otp/skip-check, `+key+` }
  flows:
    - { id: f, title: F, description: D, steps: [{ id: pwd, order: 0 }, { id: otp, order: 1, skip_check: true }] }
`)
		for _, write := range []bool{false, true} {
			_, err := p.Bootstrap(ctx, seed, Force, write)
			var refused *RefusedError
			if !errors.As(err, &refused) || !strings.Contains(err.Error(), "app otp: skip_check_key: is required") {
				t.Errorf("%q, write %v: %v", key, write, err)
			}
		}
		if snap, err := p.Snapshot(ctx); err != nil || len(snap.Apps) != 0 || len(snap.Flows) != 0 {
			t.Errorf("%q: written: %+v %v", key, snap, err)
		}
	}
}

// R48 hors liste, Q139: under -force, a seed silent on skip_check_url keeps
// the URL, the key and the signals the database holds, the steps following
// the seed; ~ or "" removes them.
func TestBootstrapSkipCheckSilentSeed(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	p.SetSecrets(keyring(t, encKeyA))
	seed := func(otp string) config.Seed {
		return loadSeed(t, `
dispatcher:
  apps:
    - { id: pwd, login_url: https://pwd/login, consent_url: https://pwd/consent, method: pwd }
    - { id: otp, login_url: https://otp/login, consent_url: https://otp/consent, method: otp`+otp+` }
  flows:
    - { id: f, title: F, description: D, steps: [{ id: pwd, order: 0 }, { id: otp, order: 1 }] }
`)
	}
	if _, err := p.Bootstrap(ctx, seed(", skip_check_url: https://otp/skip-check, skip_check_key: "+keyA+", skip_check_signals: [ip]"), Force, true); err != nil {
		t.Fatal(err)
	}
	raw := rawAppKey(t, p, "otp")
	changes, err := p.Bootstrap(ctx, seed(""), Force, true)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := p.Snapshot(ctx)
	a, _ := snap.App("otp")
	if !slices.Contains(actions(changes), "same app otp") || a.SkipCheckURL != "https://otp/skip-check" || !slices.Equal(a.SkipCheckSignals, []string{"ip"}) ||
		rawAppKey(t, p, "otp") != raw {
		t.Errorf("a silent seed: %q, %+v", actions(changes), a)
	}
	for _, removal := range []string{", skip_check_url: ~", `, skip_check_url: ""`} {
		if _, err := p.Bootstrap(ctx, seed(", skip_check_url: https://otp/skip-check, skip_check_key: "+keyA), Force, true); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Bootstrap(ctx, seed(removal), Force, true); err != nil {
			t.Fatalf("%q: %v", removal, err)
		}
		snap, _ := p.Snapshot(ctx)
		if a, _ := snap.App("otp"); a.SkipCheckURL != "" || a.SkipCheckKey != "" || len(a.SkipCheckSignals) != 0 {
			t.Errorf("%q: %+v", removal, a)
		}
	}
}
