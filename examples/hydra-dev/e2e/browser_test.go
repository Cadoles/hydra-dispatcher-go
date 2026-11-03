package main

import (
	"net/url"
	"strings"
	"testing"
)

// testPage holds the shapes the e2e meets: the dispatcher's choice page (radio,
// unnamed button, a second form), an app's login form (checked box, single
// quotes, an escaped value) and a consent form (buttons sharing a name).
const testPage = `<html><body>
<form method="post" class="locales"><input type="hidden" name="return" value="/?login_challenge=L"><button formaction="/locale/en">en</button></form>
<form method="post" action="/?login_challenge=L&amp;x=1">
<input type="hidden" name="csrf_token" value="tok">
<input type="hidden" name="login_challenge" value="L">
<label><input type="radio" name="flow" value="hydra-oidc" required></label>
<label><input type="radio" name="flow" value="hydra-sql" required checked></label>
<button type="submit" autofocus>Continuer</button>
</form>
<FORM action='http://sql.hydra.test/login' METHOD='POST'>
<input type=text name=login value="">
<input type="password" name="password">
<input type="checkbox" name="remember" value="1" checked>
<input type="checkbox" name="other" value="1">
<input type="hidden" name="note" value="a &quot;b&quot; &amp; c">
</FORM>
<form method="post" action="/consent">
<input type="hidden" name="consent_challenge" value="C">
<button type="submit" name="action" value="accept">Accept</button>
<button type="submit" name="action" value="reject">Reject</button>
</form>
<form action="/search"><input name="q" value="x"></form>
</body></html>`

func TestFormValues(t *testing.T) {
	base, _ := url.Parse("http://dispatcher.hydra.test/?login_challenge=L")
	forms := parseForms(base, testPage)
	if len(forms) != 5 {
		t.Fatalf("%d forms, want 5", len(forms))
	}
	for _, tc := range []struct {
		name    string
		form    int
		set     map[string]string
		press   *pressed
		action  string
		method  string
		want    string // url.Values.Encode
		wantErr string
	}{
		{
			name: "choice, checked radio kept", form: 1,
			action: "http://dispatcher.hydra.test/?login_challenge=L&x=1", method: "POST",
			want: "csrf_token=tok&flow=hydra-sql&login_challenge=L",
		},
		{
			name: "choice, radio set to another of its values", form: 1,
			set:    map[string]string{"flow": "hydra-oidc"},
			action: "http://dispatcher.hydra.test/?login_challenge=L&x=1", method: "POST",
			want: "csrf_token=tok&flow=hydra-oidc&login_challenge=L",
		},
		{
			name: "choice, radio set to a value it does not have", form: 1,
			set:     map[string]string{"flow": "hydra-sql-2fa"},
			wantErr: "no field flow",
		},
		{
			name: "login form: unchecked box left out, text set, entities unescaped", form: 2,
			set:    map[string]string{"login": "test2@test.com", "password": "123456"},
			action: "http://sql.hydra.test/login", method: "POST",
			want: "login=test2%40test.com&note=a+%22b%22+%26+c&password=123456&remember=1",
		},
		{
			name: "unknown field", form: 2,
			set:     map[string]string{"otp": "X"},
			wantErr: "no field otp",
		},
		{
			name: "consent, button chosen by value", form: 3,
			press:  &pressed{"action", "reject"},
			action: "http://dispatcher.hydra.test/consent", method: "POST",
			want: "action=reject&consent_challenge=C",
		},
		{
			name: "consent, button missing", form: 3,
			press:   &pressed{"form[accept]", ""},
			wantErr: "no button form[accept]",
		},
		{
			name: "form without method: GET", form: 4,
			action: "http://dispatcher.hydra.test/search", method: "GET",
			want: "q=x",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := forms[tc.form]
			got, err := f.values(tc.set, tc.press)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.Action.String() != tc.action || f.Method != tc.method {
				t.Errorf("%s %s, want %s %s", f.Method, f.Action, tc.method, tc.action)
			}
			if got.Encode() != tc.want {
				t.Errorf("values %s, want %s", got.Encode(), tc.want)
			}
		})
	}
}

func TestFind(t *testing.T) {
	base, _ := url.Parse("http://dispatcher.hydra.test/")
	p := page{URL: base, Body: testPage}
	for name, want := range map[string]string{
		"flow":              "http://dispatcher.hydra.test/?login_challenge=L&x=1",
		"password":          "http://sql.hydra.test/login",
		"consent_challenge": "http://dispatcher.hydra.test/consent",
		"action":            "http://dispatcher.hydra.test/consent",
	} {
		f, ok := p.find(name)
		if !ok || f.Action.String() != want {
			t.Errorf("find(%q) = %v, %v; want the form of %s", name, f.Action, ok, want)
		}
	}
	if _, ok := p.find("otp"); ok {
		t.Error("find(otp) found a form")
	}
}

func TestIdentityCheck(t *testing.T) {
	want := identity{Sub: "test2@test.com", Email: "test2@test.com", AMR: []string{"pwd", "otp"}}
	for _, tc := range []struct {
		name    string
		claims  map[string]any
		wantErr string
	}{
		{"all there", map[string]any{"sub": "test2@test.com", "email": "test2@test.com", "amr": []any{"pwd", "otp"}}, ""},
		{"email lost", map[string]any{"sub": "test2@test.com", "email": nil, "amr": []any{"pwd", "otp"}}, "email <nil>"},
		{"amr in another order", map[string]any{"sub": "test2@test.com", "email": "test2@test.com", "amr": []any{"otp", "pwd"}}, "amr"},
		{"other subject", map[string]any{"sub": "test3@test.com", "email": "test2@test.com", "amr": []any{"pwd", "otp"}}, "sub test3@test.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := want.check(tc.claims)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatal(err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want %q", err, tc.wantErr)
			}
		})
	}
}
