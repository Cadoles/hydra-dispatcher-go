package adminui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Writer writes the configuration by the methods of the store the admin API
// writes by (admin.Writer): a write of a screen is one of the API, the same
// rules, the same lock, the same refresh of the instances.
type Writer interface {
	CreateApp(ctx context.Context, by string, a store.App) error
	UpdateApp(ctx context.Context, by, id string, change func(*store.App) error) error
	DeleteApp(ctx context.Context, id string) error
	CreateAPIClient(ctx context.Context, by string, c store.APIClient) error
	UpdateAPIClient(ctx context.Context, by, id string, change func(*store.APIClient) error) error
	DeleteAPIClient(ctx context.Context, id string) error
	CreateFlow(ctx context.Context, by string, f store.Flow) error
	UpdateFlow(ctx context.Context, by, id string, change func(*store.Flow) error) error
	DeleteFlow(ctx context.Context, id string) error
	UpdateSettings(ctx context.Context, by string, values map[string]json.RawMessage) error
	CreateScope(ctx context.Context, by string, s store.Scope) error
	UpdateScope(ctx context.Context, by, name string, change func(*store.Scope) error) error
	DeleteScope(ctx context.Context, name string) error
}

// Snapshots give the configuration of the moment: a write refreshes that of
// its instance before it returns, so the page that follows shows it.
type Snapshots interface {
	Snapshot() *store.Snapshot
}

// maxAuthor is the length of updated_by in the store.
const maxAuthor = 180

// author is the updated_by of a write of the account: admin:<name>, cut to
// the length of the column, which a name of 180 characters with its prefix
// would pass.
func author(username string) string {
	by := "admin:" + username
	if utf8.RuneCountInString(by) > maxAuthor {
		by = string([]rune(by)[:maxAuthor])
	}
	return by
}

// fieldErrors are the violations of a form by its fields: the field of a
// violation up to its subfield (steps[1].subject_check is steps[1]) when the
// form shows it, up to its index otherwise (allowed_sources[1] is
// allowed_sources), "" for those of no field.
type fieldErrors map[string][]string

// For gives the messages of field.
func (e fieldErrors) For(field string) []string { return e[field] }

// errorsOf sorts v by the fields of the form; those of a field it does not
// show go above it, their field named, for none to be lost.
func errorsOf(v domain.Violations, fields []string) fieldErrors {
	e := fieldErrors{}
	for _, x := range v {
		field, _, _ := strings.Cut(x.Field, ".")
		base, _, _ := strings.Cut(field, "[")
		switch {
		case x.Field == "":
			e[""] = append(e[""], x.Message)
		case slices.Contains(fields, x.Field): // a key of the table: admin_oidc.issuer
			e[x.Field] = append(e[x.Field], x.Message)
		case slices.Contains(fields, field):
			e[field] = append(e[field], x.Message)
		case slices.Contains(fields, base):
			e[base] = append(e[base], x.Message)
		default:
			e[""] = append(e[""], x.Field+": "+x.Message)
		}
	}
	return e
}

// failed answers a write refused or failed: the form again, by again, with
// what refuses it, or a page that says why it stops. The cause of a failure
// of the dispatcher goes to the log, never to the page.
func (ui *UI) failed(w http.ResponseWriter, r *http.Request, s *current, err error, fields []string, again func(status int, errs fieldErrors)) {
	var v domain.Violations
	var ref *store.ReferencedError
	var refused *store.RefusedError
	switch {
	case errors.As(err, &v):
		again(http.StatusUnprocessableEntity, errorsOf(v, fields))
	case errors.As(err, &refused):
		again(http.StatusUnprocessableEntity, errorsOf(refused.Violations(), fields))
	case errors.Is(err, store.ErrExists):
		if slices.Contains(fields, "username") {
			again(http.StatusConflict, fieldErrors{"username": {"is taken: another account has this name"}})
		} else {
			again(http.StatusConflict, fieldErrors{"id": {"is taken: another has this id"}})
		}
	case errors.As(err, &ref):
		again(http.StatusConflict, fieldErrors{"": {"It is a step of the flows " + strings.Join(ref.Flows, ", ") + ": take it out of them first."}})
	case errors.Is(err, errChanged):
		again(http.StatusConflict, fieldErrors{"": {"Another admin changed it since you opened this page. Your changes are below, not saved: " +
			"save again to write them over theirs, or open the page anew to see theirs."}})
	case errors.Is(err, store.ErrLastAdmin):
		again(http.StatusConflict, fieldErrors{"": {"It is the last account of the role admin: give the role to another first."}})
	case errors.Is(err, store.ErrNotFound):
		ui.status(w, r, http.StatusNotFound, "Not found", "It does not exist, or no longer: another admin may have deleted it.", s)
	default:
		if ui.o.Logger != nil {
			ui.o.Logger.ErrorContext(r.Context(), "admin.write_failed", "cause", err.Error())
		}
		ui.status(w, r, http.StatusServiceUnavailable, "Unavailable", "The configuration cannot be written now: try again in a moment.", s)
	}
}

// errChanged refuses the save of a form whose entity changed since the form
// was shown: two admins on the same flow would lose the changes of one
// without a word.
var errChanged = errors.New("adminui: changed since the form was shown")

// version is that of an entity as a form shows it: the form carries it, and
// its save is refused when the entity no longer has it.
func version(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}

// wrote tells the audit of a write of the account done.
func (ui *UI) wrote(ctx context.Context, s *current, resource, id, action string, fields []string) {
	if ui.o.Wrote != nil {
		ui.o.Wrote(ctx, s.account.Username, resource, id, action, fields)
	}
}

// words splits a field of several values: one per line, or separated by
// spaces or commas.
func words(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == ',' })
}

// lines splits a field of one value per line, as the claims, whose names may
// hold a space or a comma: the spaces at the ends of a line and the empty
// lines left out (revue R41).
func lines(s string) []string {
	var l []string
	for line := range strings.Lines(s) {
		if line = strings.TrimSpace(line); line != "" {
			l = append(l, line)
		}
	}
	return l
}

// changes names the fields that differ, in their order.
type changes []string

func (c *changes) add(field string, differ bool) {
	if differ {
		*c = append(*c, field)
	}
}

// notices are what a page says of the write that led to it, by the done of
// its address: fixed texts, an address cannot make a page say anything else.
var notices = map[string]string{"created": "Created.", "saved": "Saved.", "deleted": "Deleted."}
