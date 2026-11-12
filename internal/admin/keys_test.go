package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuer = "https://dispatcher.example"

func pemOf(t testing.TB, typ string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func pkcs8(t testing.TB, k crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf(t, "PRIVATE KEY", der)
}

func pkix(t testing.TB, k crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf(t, "PUBLIC KEY", der)
}

func ecKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// rsaKeys are generated once: RSA keys are slow to make.
var rsaKeys = sync.OnceValues(func() (*rsa.PrivateKey, *rsa.PrivateKey) {
	k2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	k1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return k2048, k1024
})

func mustKeys(t testing.TB, private, public string, previous ...string) *Keys {
	t.Helper()
	k, err := ParseKeys(private, public, previous)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// symfonyKeys are the keys of .env.test of the Symfony dispatcher.
func symfonyKeys(t *testing.T) (private, public string) {
	t.Helper()
	data, err := os.ReadFile("testdata/symfony-env-test.keys")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(data)) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "OAUTH2_PRIVATE_KEY="); ok {
			private = v
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "OAUTH2_PUBLIC_KEY="); ok {
			public = v
		}
	}
	return private, public
}

// The RSA keys of Symfony, the base64 of a PEM in PKCS#8, are taken as they
// are and sign in PS256, never in RS256.
func TestSymfonyKeys(t *testing.T) {
	private, public := symfonyKeys(t)
	k := mustKeys(t, private, public)
	if k.active.method != jwt.SigningMethodPS256 {
		t.Errorf("method = %s, want PS256", k.active.method.Alg())
	}
	now := time.Now()
	token, err := k.Issue(issuer, "admin-client", []string{"admin:flows"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(header)
	if !strings.Contains(string(raw), `"alg":"PS256"`) || !strings.Contains(string(raw), `"kid":"`+k.KeyID()+`"`) {
		t.Errorf("header = %s", raw)
	}
	claims, err := k.Verify(token, issuer, now)
	if err != nil || claims.Subject != "admin-client" || claims.Scope != "admin:flows" {
		t.Errorf("claims = %+v, %v", claims, err)
	}
	// The same key, given without its public part, with line breaks.
	wrapped := ""
	for i := 0; i < len(private); i += 76 {
		wrapped += private[i:min(i+76, len(private))] + "\n"
	}
	if k2 := mustKeys(t, wrapped, ""); k2.KeyID() != k.KeyID() {
		t.Error("the same key gives another kid")
	}
}

func TestParseKeys(t *testing.T) {
	ec := ecKey(t, elliptic.P256())
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	r2048, _ := rsaKeys()
	for name, tt := range map[string]struct {
		private, public string
		alg             string
	}{
		"EC in PKCS#8":            {pkcs8(t, ec), pkix(t, &ec.PublicKey), "ES256"},
		"EC in SEC 1":             {pemOf(t, "EC PRIVATE KEY", sec1), "", "ES256"},
		"EC in base64":            {base64.StdEncoding.EncodeToString([]byte(pkcs8(t, ec))), base64.StdEncoding.EncodeToString([]byte(pkix(t, &ec.PublicKey))), "ES256"},
		"spaces around":           {"\n  " + pkcs8(t, ec) + "\n\n", "", "ES256"},
		"openssl ecparam -genkey": {pemOf(t, "EC PARAMETERS", []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}) + pemOf(t, "EC PRIVATE KEY", sec1), "", "ES256"},
		"RSA in PKCS#1":           {pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(r2048)), pemOf(t, "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&r2048.PublicKey)), "PS256"},
		"base64 without padding":  {base64.RawStdEncoding.EncodeToString([]byte(pkcs8(t, ec))), "", "ES256"},
		"RSA public in PKIX form": {pkcs8(t, r2048), pkix(t, &r2048.PublicKey), "PS256"},
	} {
		k, err := ParseKeys(tt.private, tt.public, nil)
		if err != nil || k.active.method.Alg() != tt.alg || len(k.KeyID()) != 16 {
			t.Errorf("%s: %v", name, err)
		}
	}

	other := ecKey(t, elliptic.P256())
	_, r1024 := rsaKeys()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	encrypted := "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00000000000000000000000000000000\n\nAAAA\n-----END EC PRIVATE KEY-----\n"
	for name, tt := range map[string]struct {
		private, public string
		previous        []string
		want            string
	}{
		"empty":             {"", "", nil, "admin.api.private_key: is empty"},
		"garbage":           {"not a key", "", nil, "admin.api.private_key: is neither a PEM nor the base64"},
		"base64 of garbage": {base64.StdEncoding.EncodeToString([]byte("garbage")), "", nil, "admin.api.private_key: is neither"},
		"P-384":             {pkcs8(t, ecKey(t, elliptic.P384())), "", nil, "admin.api.private_key: is an EC key on P-384"},
		"RSA 1024":          {pkcs8(t, r1024), "", nil, "admin.api.private_key: is an RSA key of 1024 bits"},
		"Ed25519":           {pkcs8(t, ed), "", nil, "admin.api.private_key: is a ed25519.PublicKey key"},
		"other public key":  {pkcs8(t, ec), pkix(t, &other.PublicKey), nil, "admin.api.public_key: is not the public key of admin.api.private_key"},
		"public as private": {pkix(t, &ec.PublicKey), "", nil, `admin.api.private_key: is a PEM block "PUBLIC KEY"`},
		"encrypted PKCS#8":  {pemOf(t, "ENCRYPTED PRIVATE KEY", []byte("x")), "", nil, "admin.api.private_key: is encrypted"},
		"encrypted SEC 1":   {encrypted, "", nil, "admin.api.private_key: is encrypted"},
		"two blocks":        {pkcs8(t, ec) + pkcs8(t, other), "", nil, "admin.api.private_key: holds more than one PEM block"},
		"broken DER":        {pemOf(t, "PRIVATE KEY", []byte("MIIBroken")), "", nil, "admin.api.private_key: is not a readable private key"},
		"previous broken":   {pkcs8(t, ec), "", []string{pkix(t, &other.PublicKey), "x"}, "admin.api.public_keys_previous[1]: is neither"},
		"previous RSA 1024": {pkcs8(t, ec), "", []string{pkix(t, &r1024.PublicKey)}, "admin.api.public_keys_previous[0]: is an RSA key of 1024 bits"},
	} {
		_, err := ParseKeys(tt.private, tt.public, tt.previous)
		if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
			continue
		}
		// A key never shows in an error.
		if strings.Contains(err.Error(), "MII") || strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: the error quotes the key: %v", name, err)
		}
	}
}

// sign makes a token with any method and header, as an attacker would.
func sign(t *testing.T, method jwt.SigningMethod, kid string, claims Claims, key any) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerify(t *testing.T) {
	ec := ecKey(t, elliptic.P256())
	k := mustKeys(t, pkcs8(t, ec), "")
	r2048, _ := rsaKeys()
	rk := mustKeys(t, pkcs8(t, r2048), "")
	now := time.Unix(1_800_000_000, 0)
	valid := Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "c", IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)), ID: "j"},
		Scope:            "admin:apps admin:read",
	}
	token, err := k.Issue(issuer, "c", []string{"admin:apps", "admin:read"}, 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := k.Verify(token, issuer, now); err != nil || c.Subject != "c" || len(c.Scopes()) != 2 || c.ID == "" {
		t.Fatalf("valid token: %+v, %v", c, err)
	}
	rsaPublicDER, _ := x509.MarshalPKIXPublicKey(&r2048.PublicKey)
	noSub := valid
	noSub.Subject = ""
	noExp := valid
	noExp.ExpiresAt = nil
	future := valid
	future.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute))
	parts := strings.Split(token, ".")
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + issuer + `","sub":"c","scope":"admin:clients","iat":1800000000,"exp":1800000900}`))
	for name, tt := range map[string]struct {
		keys  *Keys
		token string
		at    time.Time
	}{
		"expired":              {k, token, now.Add(15*time.Minute + clockSkew + time.Second)},
		"other issuer":         {k, sign(t, jwt.SigningMethodES256, k.KeyID(), Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "x", Subject: "c", IssuedAt: valid.IssuedAt, ExpiresAt: valid.ExpiresAt}}, ec), now},
		"no subject":           {k, sign(t, jwt.SigningMethodES256, k.KeyID(), noSub, ec), now},
		"no expiry":            {k, sign(t, jwt.SigningMethodES256, k.KeyID(), noExp, ec), now},
		"issued in the future": {k, sign(t, jwt.SigningMethodES256, k.KeyID(), future, ec), now},
		"no kid":               {k, sign(t, jwt.SigningMethodES256, "", valid, ec), now},
		"unknown kid":          {k, sign(t, jwt.SigningMethodES256, "0123456789abcdef", valid, ec), now},
		"other key, same kid":  {k, sign(t, jwt.SigningMethodES256, k.KeyID(), valid, ecKey(t, elliptic.P256())), now},
		"alg none":             {k, sign(t, jwt.SigningMethodNone, k.KeyID(), valid, jwt.UnsafeAllowNoneSignatureType), now},
		"HS256 by public key":  {rk, sign(t, jwt.SigningMethodHS256, rk.KeyID(), valid, rsaPublicDER), now},
		"RS256 by the key":     {rk, sign(t, jwt.SigningMethodRS256, rk.KeyID(), valid, r2048), now},
		"PS256 for an EC key":  {k, sign(t, jwt.SigningMethodPS256, k.KeyID(), valid, r2048), now},
		"Symfony's RS256":      {rk, sign(t, jwt.SigningMethodRS256, "", valid, r2048), now},
		"tampered signature":   {k, parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])), now},
		"tampered payload":     {k, parts[0] + "." + tamperedPayload + "." + parts[2], now},
		"not a token":          {k, "abc", now},
	} {
		if c, err := tt.keys.Verify(tt.token, issuer, tt.at); err == nil {
			t.Errorf("%s: accepted, claims %+v", name, c)
		}
	}
	// Within the skew of clocks.
	if _, err := k.Verify(token, issuer, now.Add(15*time.Minute+clockSkew-time.Second)); err != nil {
		t.Errorf("just within the skew: %v", err)
	}
}

// A rotation: the new key signs, the old one verifies its tokens until it is
// removed from public_keys_previous.
func TestRotation(t *testing.T) {
	old, next := ecKey(t, elliptic.P256()), ecKey(t, elliptic.P256())
	now := time.Now()
	before := mustKeys(t, pkcs8(t, old), "")
	token, err := before.Issue(issuer, "c", nil, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	during := mustKeys(t, pkcs8(t, next), pkix(t, &next.PublicKey), pkix(t, &old.PublicKey), pkix(t, &next.PublicKey))
	if _, err := during.Verify(token, issuer, now); err != nil {
		t.Errorf("a token of the previous key: %v", err)
	}
	fresh, _ := during.Issue(issuer, "c", nil, time.Hour, now)
	if _, err := before.Verify(fresh, issuer, now); err == nil {
		t.Error("an instance not yet given the new key accepted its token")
	}
	after := mustKeys(t, pkcs8(t, next), "")
	if _, err := after.Verify(token, issuer, now); err == nil {
		t.Error("a token of a key removed is accepted")
	}
	// An RSA key of Symfony kept as previous verifies only PS256.
	private, public := symfonyKeys(t)
	symfony := mustKeys(t, private, public)
	mixed := mustKeys(t, pkcs8(t, next), "", public)
	ps, _ := symfony.Issue(issuer, "c", nil, time.Hour, now)
	if _, err := mixed.Verify(ps, issuer, now); err != nil {
		t.Errorf("PS256 of a previous RSA key: %v", err)
	}
}
