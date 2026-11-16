package domain

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// violations collects what a check reports, as "field: message" lines.
func violations(check func(Fail)) []string {
	var got []string
	check(func(field, format string, args ...any) {
		got = append(got, field+": "+fmt.Sprintf(format, args...))
	})
	return got
}

// wants tells whether got holds a line starting with each of want, and
// nothing else.
func wants(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.ContainsFunc(got, func(g string) bool { return strings.HasPrefix(g, w) }) {
			t.Errorf("%s: no %q in %q", name, w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: %d violations %q, want %d", name, len(got), got, len(want))
	}
}

const fingerprint = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

func validApp() App {
	return App{ID: "a", LoginURL: "http://a/login", ConsentURL: "https://a/consent", Method: "pwd", AuthMode: "network",
		AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, ReceiveClaims: []string{"email"}}
}

func TestApp(t *testing.T) {
	for name, tt := range map[string]struct {
		change func(*App)
		want   []string
	}{
		"valid":           {func(*App) {}, nil},
		"mtls":            {func(a *App) { a.AuthMode, a.AllowedSources, a.ClientCertFingerprint = "mtls", nil, fingerprint }, nil},
		"no id":           {func(a *App) { a.ID = "" }, []string{"id: is required"}},
		"id with a slash": {func(a *App) { a.ID = "a/b" }, []string{`id: "a/b" is not an id`}},
		"id of 129":       {func(a *App) { a.ID = strings.Repeat("a", 129) }, []string{"id: "}},
		"relative URL":    {func(a *App) { a.LoginURL = "/login" }, []string{"login_url: is not an absolute"}},
		"no consent URL":  {func(a *App) { a.ConsentURL = "" }, []string{"consent_url: is required"}},
		"ftp logout":      {func(a *App) { a.LogoutURL = "ftp://a/out" }, []string{`logout_url: "ftp://a/out" is not`}},
		"no method":       {func(a *App) { a.Method = "" }, []string{"method: is required"}},
		"long method":     {func(a *App) { a.Method = strings.Repeat("é", 65) }, []string{"method: is longer than 64 characters"}},
		"method of 64":    {func(a *App) { a.Method = strings.Repeat("é", 64) }, nil},
		"NUL in a method": {func(a *App) { a.Method = "m\x00" }, []string{"method: contains a NUL character"}},
		"invalid UTF-8":   {func(a *App) { a.Method = "m\xff" }, []string{"method: is not UTF-8"}},
		"auth mode":       {func(a *App) { a.AuthMode = "" }, []string{`auth_mode: "" is not network or mtls`}},
		"fingerprint":     {func(a *App) { a.ClientCertFingerprint = fingerprint }, []string{"client_cert_fingerprint: only applies to auth_mode: mtls"}},
		"sources in mtls": {func(a *App) { a.AuthMode, a.ClientCertFingerprint = "mtls", fingerprint }, []string{"allowed_sources: only applies to auth_mode: network"}},
		"no fingerprint":  {func(a *App) { a.AuthMode, a.AllowedSources = "mtls", nil }, []string{"client_cert_fingerprint: must be the SHA-256"}},
		"uppercase": {func(a *App) {
			a.AuthMode, a.AllowedSources, a.ClientCertFingerprint = "mtls", nil, strings.ToUpper(fingerprint)
		}, []string{"client_cert_fingerprint: must be the SHA-256"}},
		"unmasked source":     {func(a *App) { a.AllowedSources = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")} }, []string{`allowed_sources[0]: "10.1.2.3/8" is not a network`}},
		"zero source":         {func(a *App) { a.AllowedSources = []netip.Prefix{{}} }, []string{"allowed_sources[0]: "}},
		"empty claim":         {func(a *App) { a.ReceiveClaims = []string{"email", ""} }, []string{"receive_claims[1]: is empty"}},
		"no claim":            {func(a *App) { a.ReceiveClaims = []string{} }, nil},
		"NUL in a claim":      {func(a *App) { a.ReceiveClaims = []string{"a\x00"} }, []string{"receive_claims[0]: contains a NUL character"}},
		"every claim (nil)":   {func(a *App) { a.ReceiveClaims = nil }, nil},
		"several at once":     {func(a *App) { a.ID, a.Method = "", "" }, []string{"id: is required", "method: is required"}},
		"URL with a password": {func(a *App) { a.LoginURL = "ftp://user:secret@a/?token=t" }, []string{`login_url: "ftp://user:xxxxx@a/" is not`}},
		// The pre-check of a step (phase 4): all of it or none of it.
		"pre-check":          {skipCheck(), nil},
		"pre-check, base64":  {func(a *App) { skipCheck()(a); a.SkipCheckKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }, nil},
		"pre-check, signals": {func(a *App) { skipCheck()(a); a.SkipCheckSignals = SkipCheckSignals[1:] }, nil},
		"pre-check, no key": {func(a *App) { skipCheck()(a); a.SkipCheckKey = "" },
			[]string{"skip_check_key: is required with a skip_check_url"}},
		"pre-check, short key": {func(a *App) { skipCheck()(a); a.SkipCheckKey = strings.Repeat("ab", 16) },
			[]string{"skip_check_key: key must be 32 bytes"}},
		"pre-check, relative URL": {func(a *App) { skipCheck()(a); a.SkipCheckURL = "/check" }, []string{"skip_check_url: is not an absolute"}},
		"pre-check, a user":       {func(a *App) { skipCheck()(a); a.SkipCheckURL = "https://u:secret-pw@a/check" }, []string{"skip_check_url: carries no user nor password"}},
		"key without URL":         {func(a *App) { a.SkipCheckKey = key32 }, []string{"skip_check_key: only applies with a skip_check_url"}},
		"signals without URL": {func(a *App) { a.SkipCheckSignals = []string{"ip"} },
			[]string{"skip_check_signals: only apply with a skip_check_url"}},
		"unknown signal": {func(a *App) { skipCheck()(a); a.SkipCheckSignals = []string{"ip", "cookies"} },
			[]string{`skip_check_signals[1]: "cookies" is not one of ip, full_ip`}},
		"signal twice": {func(a *App) { skipCheck()(a); a.SkipCheckSignals = []string{"user_agent", "user_agent"} },
			[]string{`skip_check_signals[1]: "user_agent" is already given`}},
		"ip and full_ip": {func(a *App) { skipCheck()(a); a.SkipCheckSignals = []string{"ip", "full_ip"} },
			[]string{"skip_check_signals: ip and full_ip are exclusive"}},
	} {
		a := validApp()
		tt.change(&a)
		wants(t, name, violations(a.Check), tt.want...)
	}
}

// key32 is a key of the pre-check, in hex.
var key32 = strings.Repeat("0a", 32)

// skipCheck gives an app the pre-check of a step.
func skipCheck() func(*App) {
	return func(a *App) { a.SkipCheckURL, a.SkipCheckKey = "https://a/skip-check", key32 }
}

func validFlow() Flow {
	return Flow{ID: "f", Title: map[string]string{"fr": "F"}, Description: map[string]string{"": "D"}, Enabled: true, ACR: "loa2",
		Steps: []Step{{AppID: "a", Position: 0, SubjectCheck: "none"}, {AppID: "b", Position: 10, SubjectCheck: "claim:email"}}}
}

func TestFlow(t *testing.T) {
	apps := func(id string) bool { return id == "a" || id == "b" }
	for name, tt := range map[string]struct {
		change func(*Flow)
		want   []string
	}{
		"valid":              {func(*Flow) {}, nil},
		"no id":              {func(f *Flow) { f.ID = "" }, []string{"id: is required"}},
		"no title":           {func(f *Flow) { f.Title = nil }, []string{"title: is required"}},
		"empty title":        {func(f *Flow) { f.Title = map[string]string{"fr": ""} }, []string{"title: is required"}},
		"no description":     {func(f *Flow) { f.Description = map[string]string{} }, []string{"description: is required"}},
		"NUL in a locale":    {func(f *Flow) { f.Title["fr\x00"] = "F" }, []string{`title: key "fr\x00" contains a NUL`}},
		"NUL in an icon":     {func(f *Flow) { f.IconURL = map[string]string{"": "http://i\x00"} }, []string{"icon_url: contains a NUL"}},
		"no steps":           {func(f *Flow) { f.Steps = nil }, []string{"steps: is empty"}},
		"unknown app":        {func(f *Flow) { f.Steps[1].AppID = "c" }, []string{`steps[1]: app "c" is not declared`}},
		"app twice":          {func(f *Flow) { f.Steps[1].AppID = "a" }, []string{`steps[1]: app "a" is already a step of this flow`}},
		"position twice":     {func(f *Flow) { f.Steps[1].Position = 0 }, []string{"steps[1]: position 0 is already taken"}},
		"position of 2^31":   {func(f *Flow) { f.Steps[1].Position = 1 << 31 }, []string{"steps[1]: position 2147483648 is out of range"}},
		"negative position":  {func(f *Flow) { f.Steps[1].Position = -1 << 31 }, nil},
		"no subject check":   {func(f *Flow) { f.Steps[0].SubjectCheck = "" }, []string{`steps[0].subject_check: "" is not none, equal or claim:<name>`}},
		"claim: alone":       {func(f *Flow) { f.Steps[0].SubjectCheck = "claim:" }, []string{`steps[0].subject_check: "claim:" is not`}},
		"long subject check": {func(f *Flow) { f.Steps[0].SubjectCheck = "claim:" + strings.Repeat("c", 123) }, []string{"steps[0].subject_check: is longer than 128 characters"}},
		"acr with a space":   {func(f *Flow) { f.ACR = "loa 2" }, []string{`acr: "loa 2" contains a space`}},
		"long acr":           {func(f *Flow) { f.ACR = strings.Repeat("a", 256) }, []string{"acr: is longer than 255 characters"}},
		"no acr":             {func(f *Flow) { f.ACR = "" }, nil},
		// The pre-check of a step (phase 4).
		"pre-check of a later step": {func(f *Flow) { f.Steps[1].SkipCheck = true }, nil},
		"pre-check of the first": {func(f *Flow) { f.Steps[0].SkipCheck = true },
			[]string{"steps[0].skip_check: is refused on the first step"}},
		// The first step is the lowest position, wherever it is in the list.
		"first by position": {func(f *Flow) { f.Steps[1].Position, f.Steps[1].SkipCheck = -5, true },
			[]string{"steps[1].skip_check: is refused on the first step"}},
		"allowed acr":          {func(f *Flow) { f.SkipCheckAllowedACR = []string{"loa1", "loa2"} }, nil},
		"allowed acr, empty":   {func(f *Flow) { f.SkipCheckAllowedACR = []string{""} }, []string{"skip_check_allowed_acr[0]: is empty"}},
		"allowed acr, a space": {func(f *Flow) { f.SkipCheckAllowedACR = []string{"loa 1"} }, []string{`skip_check_allowed_acr[0]: "loa 1" contains a space`}},
		"allowed acr, twice": {func(f *Flow) { f.SkipCheckAllowedACR = []string{"loa1", "loa1"} },
			[]string{`skip_check_allowed_acr[1]: "loa1" is already given`}},
		"allowed acr, long": {func(f *Flow) { f.SkipCheckAllowedACR = []string{strings.Repeat("a", 256)} },
			[]string{"skip_check_allowed_acr[0]: is longer than 255 characters"}},
	} {
		f := validFlow()
		tt.change(&f)
		wants(t, name, violations(func(fail Fail) { f.Check(fail, apps) }), tt.want...)
	}
}

func TestAPIClient(t *testing.T) {
	hash, err := HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		c    APIClient
		want []string
	}{
		"valid":            {APIClient{ID: "c", SecretHash: hash, Scopes: []string{"admin:flows"}}, nil},
		"Symfony's hash":   {APIClient{ID: "c", SecretHash: symfonyHash, Scopes: []string{}}, nil},
		"no hash":          {APIClient{ID: "c"}, []string{"secret: is not a bcrypt hash"}},
		"plain secret":     {APIClient{ID: "c", SecretHash: "s3cret"}, []string{"secret: is not a bcrypt hash"}},
		"empty scope":      {APIClient{ID: "c", SecretHash: hash, Scopes: []string{""}}, []string{"scopes[0]: is empty"}},
		"scope with space": {APIClient{ID: "c", SecretHash: hash, Scopes: []string{"a", "admin flows"}}, []string{`scopes[1]: "admin flows" contains a space`}},
		"bad id":           {APIClient{ID: ".c", SecretHash: hash}, []string{`id: ".c" is not an id`}},
		"cost 31":          {APIClient{ID: "c", SecretHash: costly(t, 31)}, []string{"secret: is a bcrypt hash of cost 31: 14 at most"}},
		"cost 15":          {APIClient{ID: "c", SecretHash: costly(t, 15)}, []string{"secret: is a bcrypt hash of cost 15"}},
		"cost 14":          {APIClient{ID: "c", SecretHash: costly(t, 14)}, nil},
	} {
		wants(t, name, violations(tt.c.Check), tt.want...)
	}
	if !SecretMatches(hash, "s3cret") || SecretMatches(hash, "s3cre") {
		t.Error("SecretMatches")
	}
}

// costly is a hash of cost 4 that announces cost: bcrypt reads the cost from
// the hash, and would compute 2^cost rounds to compare it.
func costly(t *testing.T, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(h), "$04$", fmt.Sprintf("$%02d$", cost), 1)
}

// A hash of a cost over MaxSecretCost is never computed: the test would hold a
// CPU for hours otherwise.
func TestSecretCost(t *testing.T) {
	// In a goroutine: a regression would compute 2^31 rounds, and the test
	// fails after a second rather than hold the suite (revue R34).
	hash := costly(t, 31)
	// Of the form IsHash takes, and of another one that bcrypt computes all
	// the same (revue R37).
	for _, h := range []string{hash, strings.Replace(hash, "$2a$", "$2x$", 1), hash + "x"} {
		matched := make(chan bool, 1)
		go func() { matched <- SecretMatches(h, "s3cret") }()
		select {
		case m := <-matched:
			if m {
				t.Errorf("%s matches", h)
			}
		case <-time.After(time.Second):
			t.Fatalf("SecretMatches computes %s", h)
		}
	}
	if !SecretCostTooHigh(hash) || SecretCostTooHigh(costly(t, 14)) || SecretCostTooHigh("not a hash") {
		t.Error("SecretCostTooHigh")
	}
}

// symfonyHash is the hash Symfony's NativePasswordHasher (bcrypt, cost 4)
// gave symfonySecret, 100 bytes long.
const symfonyHash = "$2y$04$iuml1FnUXrHaDd/Sxqt9UOniJuDi.W.KCQHk3.1uwFwFUwQmLYt5W"

var symfonySecret = strings.Repeat("0123456789", 10)

// A secret past 72 bytes is hashed first, as Symfony does: its first 72 bytes
// are another secret. A shorter one is hashed as is.
func TestBcryptInput(t *testing.T) {
	if err := bcrypt.CompareHashAndPassword([]byte(symfonyHash), BcryptInput(symfonySecret)); err != nil {
		t.Errorf("Symfony's hash: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(symfonyHash), BcryptInput(symfonySecret[:72])) == nil {
		t.Error("the first 72 bytes check too")
	}
	if got := string(BcryptInput("s3cret")); got != "s3cret" {
		t.Errorf("short secret: %q", got)
	}
	if got := BcryptInput("s3\x00cret"); len(got) != 72 || strings.Contains(string(got), "cret") {
		t.Errorf("secret with a NUL: %q", got)
	}
	if !SecretMatches(symfonyHash, symfonySecret) {
		t.Error("SecretMatches on Symfony's hash")
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes([]string{"10.1.2.3", "10.1.2.3/16", "::ffff:10.0.0.0/104", "2001:db8::1"})
	want := []netip.Prefix{
		netip.MustParsePrefix("10.1.2.3/32"), netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::1/128"),
	}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("ParsePrefixes = %v, %v; want %v", got, err, want)
	}
	if _, err := ParsePrefixes([]string{"pod-a"}); err == nil || !strings.Contains(err.Error(), `"pod-a" is neither`) {
		t.Errorf("pod-a: %v", err)
	}
	// What ParsePrefixes gives, App.Check takes.
	a := validApp()
	a.AllowedSources = got
	wants(t, "parsed sources", violations(a.Check))
}

// A bcrypt hash is its whole form: what bcrypt.Cost alone took and stored as
// it is matched nothing, or failed in Postgres (revue R35).
func TestIsHash(t *testing.T) {
	hash, err := HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(hash, "$2a$10$")
	for s, want := range map[string]bool{
		hash:                           true,
		symfonyHash:                    true,
		"$2b$10$" + body:               true,
		costly(t, 31):                  true,
		"$2x$10$" + body:               false,
		"$2$10$" + body:                false,
		"$2a$03$" + body:               false,
		"$2a$32$" + body:               false,
		"$2a$1$" + body:                false,
		hash + "x":                     false,
		hash + "\n":                    false,
		hash[:59]:                      false,
		hash[:20] + "\x00" + hash[21:]: false,
		hash[:20] + "!" + hash[21:]:    false,
		"s3cret":                       false,
		"":                             false,
	} {
		if IsHash(s) != want {
			t.Errorf("IsHash(%q) = %v", s, !want)
		}
	}
	if !NeedsRehash(symfonyHash) || NeedsRehash(hash) || NeedsRehash("s3cret") || !NeedsRehash(costly(t, 13)) {
		t.Error("NeedsRehash")
	}
	if SecretCostTooHigh("$2x$31$" + body) {
		t.Error("SecretCostTooHigh of what is not a hash")
	}
	wants(t, "junk after", violations(APIClient{ID: "c", SecretHash: hash + "x"}.Check), "secret: is not a bcrypt hash")
}

func TestNewSecret(t *testing.T) {
	a, b := NewSecret(), NewSecret()
	if len(a) != 43 || a == b || strings.ContainsAny(a, "+/=") || IsHash(a) {
		t.Errorf("NewSecret: %q, %q", a, b)
	}
}

func TestAdminUser(t *testing.T) {
	hash, err := HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		u    AdminUser
		want []string
	}{
		"admin":               {AdminUser{Username: "alice", PasswordHash: hash, Role: RoleAdmin}, nil},
		"viewer by OIDC":      {AdminUser{Username: "bob@example.org", OIDCSub: "248289761001", Role: RoleViewer}, nil},
		"Symfony's hash":      {AdminUser{Username: "admin", PasswordHash: symfonyHash, Role: RoleAdmin}, nil},
		"a colon":             {AdminUser{Username: "a:b", Role: RoleViewer}, nil},
		"180 characters":      {AdminUser{Username: strings.Repeat("é", 180), Role: RoleViewer}, nil},
		"no name":             {AdminUser{Role: RoleAdmin}, []string{"username: is required"}},
		"181 characters":      {AdminUser{Username: strings.Repeat("é", 181), Role: RoleViewer}, []string{"username: is longer than 180 characters"}},
		"space at the end":    {AdminUser{Username: "alice ", Role: RoleViewer}, []string{`username: "alice " starts or ends with a space`}},
		"NUL":                 {AdminUser{Username: "a\x00b", Role: RoleViewer}, []string{"username: contains a control character"}},
		"new line":            {AdminUser{Username: "a\nb", Role: RoleViewer}, []string{"username: contains a control character"}},
		"not UTF-8":           {AdminUser{Username: "a\xffb", Role: RoleViewer}, []string{"username: is not UTF-8"}},
		"super_admin":         {AdminUser{Username: "a", Role: "super_admin"}, []string{`role: "super_admin" is not admin or viewer`}},
		"no role":             {AdminUser{Username: "a"}, []string{`role: "" is not admin or viewer`}},
		"plain password":      {AdminUser{Username: "a", PasswordHash: "s3cret", Role: RoleAdmin}, []string{"password: is not a bcrypt hash"}},
		"password of cost 15": {AdminUser{Username: "a", PasswordHash: costly(t, 15), Role: RoleAdmin}, []string{"password: is a bcrypt hash of cost 15: 14 at most, each login computing it"}},
		"long subject":        {AdminUser{Username: "a", OIDCSub: strings.Repeat("s", 256), Role: RoleViewer}, []string{"oidc_sub: is longer than 255 characters"}},
	} {
		wants(t, name, violations(tt.u.Check), tt.want...)
	}
}

// Q121: 12 characters at least, counted as characters, without composition.
func TestCheckPassword(t *testing.T) {
	for password, want := range map[string]string{
		"aaaaaaaaaaaa":  "",
		"éééééééééééé":  "",
		"aaaaaaaaaaa":   "password: has 11 characters: 12 at least",
		"ééééééééééé":   "password: has 11 characters: 12 at least",
		"":              "password: has 0 characters: 12 at least",
		"correct horse": "",
	} {
		got := ""
		if v := Collect(func(fail Fail) { CheckPassword(fail, password) }); v != nil {
			got = v.Error()
		}
		if got != want {
			t.Errorf("%q: %q, want %q", password, got, want)
		}
	}
}

func TestParseKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i) * 7
	}
	for name, s := range map[string]string{
		"hex":          fmt.Sprintf("%x", raw),
		"base64":       base64.StdEncoding.EncodeToString(raw),
		"base64 url":   base64.URLEncoding.EncodeToString(raw),
		"raw base64":   base64.RawStdEncoding.EncodeToString(raw),
		"spaces round": " " + base64.StdEncoding.EncodeToString(raw) + "\n",
	} {
		if got, err := ParseKey(s); err != nil || string(got) != string(raw) {
			t.Errorf("%s: ParseKey = %x, %v", name, got, err)
		}
	}
	if got, err := ParseKey(""); got != nil || err != nil {
		t.Errorf("ParseKey(\"\") = %x, %v", got, err)
	}
	for name, s := range map[string]string{
		"31 bytes":   base64.StdEncoding.EncodeToString(raw[:31]),
		"33 bytes":   base64.StdEncoding.EncodeToString(append(raw, 0)),
		"63 hex":     fmt.Sprintf("%x", raw)[:63],
		"not a key":  "correct horse battery staple, one more time",
		"hex of 31b": fmt.Sprintf("%x", raw[:31]),
	} {
		if _, err := ParseKey(s); err == nil || err.Error() != "key must be 32 bytes, given as 64 hex characters or base64" {
			t.Errorf("%s: ParseKey error = %v", name, err)
		}
	}
}

func TestCheckSkipChecks(t *testing.T) {
	withURL := validApp()
	skipCheck()(&withURL)
	without := validApp()
	without.ID = "b"
	f := validFlow()
	f.Steps[1].SkipCheck = true // app b
	if err := CheckSkipChecks([]App{withURL, without}, []Flow{f}); err == nil || err.Error() != "flow f: steps[1].skip_check: app b has no skip_check_url" {
		t.Errorf("app without a URL: %v", err)
	}
	f.Steps[0].AppID, f.Steps[1].AppID = "b", "a" // the step on a, which has one
	if err := CheckSkipChecks([]App{withURL, without}, []Flow{f}); err != nil {
		t.Errorf("app with a URL: %v", err)
	}
	f.Steps[1].SkipCheck = false
	if err := CheckSkipChecks([]App{without}, []Flow{f}); err != nil {
		t.Errorf("no pre-check asked: %v", err)
	}
}
