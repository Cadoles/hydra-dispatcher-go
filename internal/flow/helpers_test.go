package flow

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// loginFixture is Hydra 2.1's login request of capture 14 (sql-2fa).
const loginFixture = "../../testdata/protocol/symfony-hydra-2.1/14-sql-2fa-consent-skipped/0032-hydra-GET-admin_oauth2_auth_requests_login.json"

var (
	testKey  = []byte("0123456789abcdef0123456789abcdef")
	oldKey   = []byte("fedcba9876543210fedcba9876543210")
	testKeys = Keys{testKey, oldKey}
	// testNow is a fixed instant, in milliseconds.
	testNow = time.UnixMilli(1_790_000_000_000)
)

// testApps are those of hydra-dev, plus an app that only receives the email.
func testApps() []store.App {
	return []store.App{
		{ID: "sql", LoginURL: "http://sql.hydra.test/login", ConsentURL: "http://sql.hydra.test/consent", Method: "pwd"},
		{ID: "2fa", LoginURL: "http://2fa.hydra.test/login", ConsentURL: "http://2fa.hydra.test/consent", Method: "otp",
			ReceiveClaims: []string{"email"}},
		{ID: "oidc", LoginURL: "http://oidc.hydra.test/login", ConsentURL: "http://oidc.hydra.test/consent", Method: "oidc"},
	}
}

func testFlows() []store.Flow {
	return []store.Flow{
		{ID: "hydra-sql", Enabled: true, Steps: []store.Step{{AppID: "sql", Position: 1, SubjectCheck: "none"}}},
		{ID: "hydra-sql-2fa", Enabled: true, Steps: []store.Step{
			{AppID: "sql", Position: 1, SubjectCheck: "none"},
			{AppID: "2fa", Position: 2, SubjectCheck: "equal"},
		}},
		{ID: "hydra-oidc", Enabled: true, Steps: []store.Step{{AppID: "oidc", Position: 1, SubjectCheck: "none"}}},
	}
}

func testEnv() Env {
	return Env{
		Config:          store.NewSnapshot(testApps(), testFlows(), store.DefaultSettings()),
		BaseURL:         "http://dispatcher.hydra.test/",
		LoginConsentTTL: 30 * time.Minute,
		Keys:            testKeys,
		Now:             testNow,
		Draw:            Draw{Gen0: 5000, CSRF: newCSRF},
	}
}

// cookie is the browser's dispatcher_flow_csrf; newCSRF the value drawn for
// a browser without one.
var (
	cookie  = strings.Repeat("ab", 32)
	newCSRF = strings.Repeat("cd", 32)
)

// loginRequest decodes the fixture as the admin client does: the client and
// the oidc_context as served.
func loginRequest(t *testing.T) *ory.OAuth2LoginRequest {
	t.Helper()
	data, err := os.ReadFile(loginFixture)
	if err != nil {
		t.Fatal(err)
	}
	var exchange struct {
		Response struct {
			Body json.RawMessage `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &exchange); err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(exchange.Response.Body, &members); err != nil {
		t.Fatal(err)
	}
	client, err := hydra.DecodeClient(members["client"])
	if err != nil {
		t.Fatal(err)
	}
	oidc, err := hydra.DecodeOIDCContext(members["oidc_context"])
	if err != nil {
		t.Fatal(err)
	}
	members["client"] = json.RawMessage("{}") // the SDK requires one; set below
	delete(members, "oidc_context")
	rest, _ := json.Marshal(members)
	var r ory.OAuth2LoginRequest
	if err := json.Unmarshal(rest, &r); err != nil {
		t.Fatal(err)
	}
	r.Client, r.OidcContext = *client, oidc
	return &r
}

// twoSteps is a flow of hydra-sql-2fa on its second step, login and consent
// of the first accepted.
func twoSteps(t *testing.T) *Flow {
	t.Helper()
	r := loginRequest(t)
	snap, sid, err := SnapshotOf(r)
	if err != nil {
		t.Fatal(err)
	}
	return &Flow{
		V:              Format,
		LoginChallenge: r.Challenge,
		HydraSessionID: sid,
		Hydra:          snap,
		FlowID:         "hydra-sql-2fa",
		Gen0:           1000,
		Gen:            1003,
		CSRF:           "csrf",
		Subject:        "alice",
		Current:        2,
		Steps: []Step{
			{App: "sql", Subject: "alice", LoginOK: true, ConsentOK: true, AMR: []string{"pwd"},
				LoginContext:   Object{"login": json.RawMessage(`"sql"`)},
				ConsentContext: Object{"from": json.RawMessage(`"sql"`), "sql": json.RawMessage(`1`)},
				IDToken:        Object{"email": json.RawMessage(`"alice@example.org"`), "name": json.RawMessage(`"Alice"`)},
				AccessToken:    Object{}},
			{App: "2fa", Check: "equal"},
		},
		ExpiresAt:      testNow.Add(10 * time.Minute).UnixMilli(),
		HydraExpiresAt: testNow.Add(30 * time.Minute).UnixMilli(),
	}
}
