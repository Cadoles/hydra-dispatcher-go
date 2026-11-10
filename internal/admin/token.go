package admin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// clockSkew is the difference of clocks tolerated between the instance that
// signs a token and the one that verifies it.
const clockSkew = 30 * time.Second

// Claims are those of a token: iss, sub (the client id), iat, exp and jti,
// and the scopes granted, separated by spaces.
type Claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

// Scopes are the scopes of the token.
func (c *Claims) Scopes() []string { return strings.Fields(c.Scope) }

// Issue signs a token for client, with scopes, valid ttl from now, issued by
// issuer. Its header names the key (kid).
func (k *Keys) Issue(issuer, client string, scopes []string, ttl time.Duration, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	t := jwt.NewWithClaims(k.active.method, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   client,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        hex.EncodeToString(jti),
		},
		Scope: strings.Join(scopes, " "),
	})
	t.Header["kid"] = k.active.id
	return t.SignedString(k.private)
}

// errToken is the error of a token refused, which the API does not detail.
var errToken = errors.New("invalid token")

// Verify checks token, signed by a key of the ring, issued by issuer, not
// expired at now, and returns its claims. The key is the one the kid names,
// and the method that of the key, whatever the header says: alg none, RS256,
// or a method other than the key's, are refused.
func (k *Keys) Verify(token, issuer string, now time.Time) (*Claims, error) {
	var claims Claims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg(), jwt.SigningMethodPS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	_, err := parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		id, _ := t.Header["kid"].(string)
		key, ok := k.byID[id]
		switch {
		case !ok:
			return nil, fmt.Errorf("%w: unknown key", errToken)
		case t.Method.Alg() != key.method.Alg():
			return nil, fmt.Errorf("%w: %s for a key of %s", errToken, t.Method.Alg(), key.method.Alg())
		}
		return key.public, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errToken, err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", errToken)
	}
	return &claims, nil
}
