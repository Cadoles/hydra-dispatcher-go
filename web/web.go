// Package web holds the templates and the static files of the pages (choice
// of the flow, consent, error), embedded in the binary.
package web

import "embed"

// FS holds templates/ (the layout, each page and its partials) and static/
// (the CSS of the pages).
//
//go:embed templates static
var FS embed.FS

// Scalar holds scalar/: the bundle of Scalar's API reference and its starter,
// for the page of /admin/v1/docs. Apart from static/, which a theme overlays
// and the pages serve.
//
//go:embed scalar/standalone.js scalar/init.js
var Scalar embed.FS
