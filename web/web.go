// Package web holds the templates and the static files of the pages (choice
// of the flow, consent, error), embedded in the binary.
package web

import "embed"

// FS holds templates/ (the layout, each page and its partials) and static/
// (the CSS of the pages).
//
//go:embed templates static
var FS embed.FS
