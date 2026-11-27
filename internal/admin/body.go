package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
)

// maxResourceBody bounds the body of a write: a flow and its texts, many times.
const maxResourceBody = 1 << 20

// httpError is an error of the request the API answers with its status: 400,
// 413, 415.
type httpError struct {
	status int
	detail string
}

func (e *httpError) Error() string { return e.detail }

func badRequest(format string, args ...any) error {
	return &httpError{status: http.StatusBadRequest, detail: fmt.Sprintf(format, args...)}
}

// body is the JSON object of a write, field by field: a field is absent, null,
// or a value of its type.
type body map[string]json.RawMessage

// readBody reads the object of a write: POST and PUT in application/json,
// PATCH in application/merge-patch+json or application/json (Q104).
func readBody(w http.ResponseWriter, r *http.Request) (body, error) {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	allowed := []string{"application/json"}
	if r.Method == http.MethodPatch {
		allowed = append(allowed, "application/merge-patch+json")
	}
	if !slices.Contains(allowed, mediaType) {
		return nil, &httpError{status: http.StatusUnsupportedMediaType,
			detail: fmt.Sprintf("The content-type %q is not supported. Supported MIME types are %q.", mediaType, strings.Join(allowed, `", "`))}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxResourceBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &httpError{status: http.StatusRequestEntityTooLarge, detail: fmt.Sprintf("The body exceeds %d bytes.", maxResourceBody)}
		}
		return nil, badRequest("The body could not be read.")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var b body
	if err := dec.Decode(&b); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return nil, badRequest("The body must be a JSON object.")
		}
		return nil, badRequest("Syntax error")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, badRequest("Syntax error")
	}
	if b == nil {
		return nil, badRequest("The body must be a JSON object.")
	}
	return b, nil
}

// kind names the JSON type of raw, as Symfony's messages do, but for an
// object: PHP calls it an array, and an object passed for a list then passed
// the check of its type (revue R35).
func kind(raw json.RawMessage) string {
	switch t := bytes.TrimSpace(raw); {
	case len(t) == 0:
		return "nothing"
	case t[0] == '"':
		return "string"
	case t[0] == '{':
		return "object"
	case t[0] == '[':
		return "array"
	case t[0] == 't' || t[0] == 'f':
		return "bool"
	case t[0] == 'n':
		return "null"
	case bytes.ContainsAny(t, ".eE"):
		return "float"
	default:
		return "int"
	}
}

func typeError(field, want string, raw json.RawMessage) error {
	return badRequest("The type of the %q attribute must be %q, %q given.", field, want, kind(raw))
}

// has tells whether the field is in the body, null or not.
func (b body) has(field string) bool {
	_, ok := b[field]
	return ok
}

// null tells whether the field is in the body as null.
func (b body) null(field string) bool {
	raw, ok := b[field]
	return ok && kind(raw) == "null"
}

// str reads a string field, "" when null.
func (b body) str(field string) (string, error) {
	raw := b[field]
	if kind(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", typeError(field, "string", raw)
	}
	return s, nil
}

// boolean reads a bool field; null is def.
func (b body) boolean(field string, def bool) (bool, error) {
	raw := b[field]
	if kind(raw) == "null" {
		return def, nil
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, typeError(field, "bool", raw)
	}
	return v, nil
}

// texts reads a map of locale to text, nil when null; a null text is no
// text.
func (b body) texts(field string) (map[string]string, error) {
	raw := b[field]
	if kind(raw) == "null" {
		return nil, nil
	}
	var v map[string]*string
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return nil, typeError(field, "array", raw)
	}
	m := map[string]string{}
	for locale, text := range v {
		if text != nil && *text != "" {
			m[locale] = *text
		}
	}
	return m, nil
}

// strs reads a list of strings, nil when null.
func (b body) strs(field string) ([]string, error) {
	raw := b[field]
	if kind(raw) == "null" {
		return nil, nil
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return nil, typeError(field, "array", raw)
	}
	return v, nil
}

// unknown refuses the fields of the body that are none of known, nor of
// ignored, the read-only fields of the representation and those of Symfony
// left out (Q110).
func (b body) unknown(known []string, ignored ...string) error {
	var v requestViolations
	for _, field := range slices.Sorted(maps.Keys(b)) {
		if !slices.Contains(known, field) && !slices.Contains(ignored, field) {
			v = append(v, domain.Violation{Field: field, Message: "is not a field of this resource"})
		}
	}
	if v == nil {
		return nil
	}
	return v
}

// fieldsOf names the fields of the body that are among known, for the audit.
func (b body) fieldsOf(known []string) []string {
	var fields []string
	for _, k := range known {
		if b.has(k) {
			fields = append(fields, k)
		}
	}
	return fields
}

// pageSize is the size of a page of a collection, Symfony's (Q103).
const pageSize = 30

// page reads ?page, 1 when absent.
func page(r *http.Request) (int, error) {
	p := r.URL.Query().Get("page")
	if p == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(p)
	switch {
	case err != nil:
		return 0, badRequest("Page must be an integer")
	case n < 1:
		return 0, badRequest("Page should not be less than 1")
	}
	return n, nil
}

// paginate gives the page n of items.
func paginate[T any](items []T, n int) []T {
	start := (n - 1) * pageSize
	if start >= len(items) || start < 0 {
		return []T{}
	}
	return items[start:min(start+pageSize, len(items))]
}
