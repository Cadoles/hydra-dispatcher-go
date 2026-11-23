package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/api"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/web"
)

// docsCSP is the policy of the page of the documentation, its own: Scalar
// injects <style> elements, the only reason for 'unsafe-inline', on this page
// alone; its scripts, its JSON and its requests stay on the dispatcher.
const docsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// docsPage loads Scalar and its starter beside it; docs.json is the document.
const docsPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hydra dispatcher API</title>
</head>
<body>
<div id="app"></div>
<script src="docs/scalar.js"></script>
<script src="docs/init.js"></script>
</body>
</html>
`

// asset is a file of the page, served with its ETag: the browser asks again
// at each visit and gets 304 while the binary is the same.
type asset struct {
	contentType string
	data        []byte
	etag        string
}

func newAsset(contentType string, data []byte) asset {
	sum := sha256.Sum256(data)
	return asset{contentType: contentType, data: data, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
}

func (a asset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", a.etag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(a.data))
}

// registerDocs serves the document, /docs.json, and the page that shows it,
// /docs, to the addresses of the allowlist, without a token, as Symfony did.
func (a *API) registerDocs() error {
	doc, err := api.JSON()
	if err != nil {
		return fmt.Errorf("openapi: %w", err)
	}
	scalar, err := web.Scalar.ReadFile("scalar/standalone.js")
	if err != nil {
		return err
	}
	init, err := web.Scalar.ReadFile("scalar/init.js")
	if err != nil {
		return err
	}
	page := newAsset("text/html; charset=utf-8", []byte(docsPage))
	a.route("GET "+Prefix+"/docs.json", newAsset("application/json", doc))
	a.route("GET "+Prefix+"/docs", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", docsCSP)
		// The page links out (Scalar's own site): the dispatcher's address
		// does not go with a click (revue R36).
		w.Header().Set("Referrer-Policy", "no-referrer")
		page.ServeHTTP(w, r)
	}))
	a.route("GET "+Prefix+"/docs/scalar.js", newAsset("text/javascript; charset=utf-8", scalar))
	a.route("GET "+Prefix+"/docs/init.js", newAsset("text/javascript; charset=utf-8", init))
	return nil
}
