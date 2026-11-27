package adminui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// settingRow is a setting as its form shows it: its field by the type of its
// default (a box, a number of seconds, a text, a list).
type settingRow struct {
	Key, Help, Kind, Value, Default string
	On                              bool
	// Shown is the value the page showed, which a save compares with: a
	// setting this form does not change keeps the value another admin gave
	// it meanwhile.
	Shown string
	// Stored tells whether the setting table holds it; otherwise it has its
	// default.
	Stored bool
}

type settingsPage struct {
	Rows   []settingRow
	Errors fieldErrors
}

// kindOf is the type of a value in JSON: bool, number, string or array.
func kindOf(raw json.RawMessage) string {
	switch b := bytes.TrimSpace(raw); {
	case len(b) == 0:
		return ""
	case b[0] == 't' || b[0] == 'f':
		return "bool"
	case b[0] == '"':
		return "string"
	case b[0] == '[':
		return "array"
	default:
		return "number"
	}
}

// text is a value as a field shows it.
func text(raw json.RawMessage) string {
	switch kindOf(raw) {
	case "string":
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	case "array":
		var l []string
		_ = json.Unmarshal(raw, &l)
		return strings.Join(l, ", ")
	}
	return string(bytes.TrimSpace(raw))
}

func valuesOf(s store.Settings) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	for _, v := range s.Document() {
		m[v.Key] = v.Value
	}
	return m
}

// settingRows are the rows of the registry, in its order, with the values of
// the moment, or those of the form r when it is given.
func settingRows(snap *store.Snapshot, r *http.Request) []settingRow {
	values, defaults := valuesOf(snap.Settings), valuesOf(store.DefaultSettings())
	var rows []settingRow
	for _, k := range store.SettingKeys() {
		row := settingRow{Key: k.Key, Help: k.Help, Kind: kindOf(defaults[k.Key]), Value: text(values[k.Key]),
			Default: text(defaults[k.Key]), Stored: slices.Contains(snap.StoredSettings, k.Key)}
		row.On, row.Shown = row.Value == "true", row.Value
		if r != nil {
			row.Value, row.On, row.Shown = strings.TrimSpace(r.PostFormValue(k.Key)), r.PostFormValue(k.Key) != "", r.PostFormValue("shown_"+k.Key)
		}
		rows = append(rows, row)
	}
	return rows
}

// settingJSON is the value of a field of the kind of a setting in JSON;
// false for a number that is not one.
func settingJSON(kind, v string, on bool) (json.RawMessage, bool) {
	switch kind {
	case "bool":
		return json.RawMessage(strconv.FormatBool(on)), true
	case "number":
		if !wholeNumber.MatchString(v) {
			return nil, false
		}
		return json.RawMessage(v), true
	case "array":
		raw, _ := json.Marshal(append([]string{}, words(v)...))
		return raw, true
	}
	raw, _ := json.Marshal(v)
	return raw, true
}

func sameJSON(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}

func (ui *UI) registerSettings() {
	ui.mux.Handle("GET /admin/settings", ui.authed(anyRole, ui.settings))
	if ui.o.Writer != nil {
		ui.mux.Handle("POST /admin/settings", ui.authed(adminRole, ui.updateSettings))
	}
}

func (ui *UI) settings(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "settings", "Settings", "settings", settingsPage{Rows: settingRows(ui.o.Config.Snapshot(), nil)})
}

var wholeNumber = regexp.MustCompile(`^-?[0-9]+$`)

// updateSettings writes the settings the form changes from what it showed,
// and those it gives back their default: a setting another admin changed
// meanwhile, and this form not, keeps their value.
func (ui *UI) updateSettings(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	now, defaults := valuesOf(snap.Settings), valuesOf(store.DefaultSettings())
	reset := r.PostForm["reset"]
	values, errs := map[string]json.RawMessage{}, fieldErrors{}
	var keys []string
	for _, k := range store.SettingKeys() {
		keys = append(keys, k.Key)
		if slices.Contains(reset, k.Key) {
			if slices.Contains(snap.StoredSettings, k.Key) {
				values[k.Key] = json.RawMessage("null")
			}
			continue
		}
		kind := kindOf(defaults[k.Key])
		shownText := r.PostFormValue("shown_" + k.Key)
		// The field as the page showed it, its spaces too: untouched, the
		// value stays as stored (revue R41).
		if kind != "bool" && r.PostFormValue(k.Key) == shownText {
			continue
		}
		raw, ok := settingJSON(kind, strings.TrimSpace(r.PostFormValue(k.Key)), r.PostFormValue(k.Key) != "")
		if !ok {
			errs[k.Key] = append(errs[k.Key], "is not a whole number of seconds")
			continue
		}
		shown, ok := settingJSON(kind, shownText, shownText == "true")
		if (!ok || !sameJSON(raw, shown)) && !sameJSON(raw, now[k.Key]) {
			values[k.Key] = raw
		}
	}
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "settings", "Settings", "settings", settingsPage{Rows: settingRows(snap, r), Errors: errs})
	}
	if len(errs) > 0 {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	if len(values) > 0 {
		if err := ui.o.Writer.UpdateSettings(r.Context(), author(s.account.Username), values); err != nil {
			ui.failed(w, r, s, err, keys, again)
			return
		}
		var written []string
		for _, k := range keys {
			if _, ok := values[k]; ok {
				written = append(written, k)
			}
		}
		ui.wrote(r.Context(), s, "settings", "", "update", written)
	}
	http.Redirect(w, r, ui.base+"/settings?done=saved", http.StatusSeeOther)
}
