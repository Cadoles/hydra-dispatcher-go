package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// MaxCause bounds the cause of a failed outgoing call in the logs.
const MaxCause = 200

// IdleConnTimeout closes an idle connection to Hydra or a webhook (Q84): under
// the idle timeouts of common balancers (60 s for an AWS ALB, 75 s for nginx,
// 5 s for Apache's keep-alive), a connection they would close first could
// fail a PUT Go does not replay, the final accept of an authentication.
const IdleConnTimeout = 30 * time.Second

// PingTimeout is how long an HTTP/2 connection waits for the answer to a ping,
// sent once it has been silent for the timeout of a call: a peer gone without
// a reset would otherwise hold every call multiplexed on the connection until
// TCP gives up.
const PingTimeout = 2 * time.Second

// tls12Suites are the TLS 1.2 suites the ANSSI TLS guide recommends: ECDHE
// with an AEAD. Go still enables ECDHE with AES-CBC-SHA by default. TLS 1.3
// suites are all AEAD and not configurable.
var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// ClientTLS is the TLS of an outgoing call: minVersion ("1.3", else 1.2) with
// the suites above; the authorities of caFile instead of the system's when it
// is set.
func ClientTLS(minVersion, caFile string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: tls12Suites}
	if minVersion == "1.3" {
		c.MinVersion = tls.VersionTLS13
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate in %s", caFile)
		}
	}
	return c, nil
}

// BoundedCause cuts a cause to MaxCause, on a character boundary.
func BoundedCause(cause string) string {
	if len(cause) > MaxCause {
		return strings.ToValidUTF8(cause[:MaxCause], "") + "…"
	}
	return cause
}

// cited finds where a library starts citing what it could not read: a double quote, or
// the name of an XML element, as the SDK's decoder gives it; not the '<' of
// encoding/json, a single character.
var cited = regexp.MustCompile(`"|<[^']`)

// Uncited is the text of an error up to what it cites of a request or an answer: a log
// line never holds such a value (Q64, Q67).
func Uncited(text string) string {
	if at := cited.FindStringIndex(text); at != nil {
		text = text[:at[0]]
	}
	return strings.TrimRight(text, " :")
}
