package admin

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"slices"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// settingsIgnored are the fields of Symfony's document the Go does not keep:
// written, they are ignored and logged (Q105).
var settingsIgnored = []string{"id", "hydraPublicUrl", "adminAuthorizedHosts"}

// settingsAlias is Symfony's name of loginRememberFor (Q105).
const settingsAlias = "sessionTtl"

// document writes the settings in the document of the API: each key of the
// registry in camelCase, in its order, a webhook absent as null (Q105).
func document(s store.Settings) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, v := range s.Document() {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(camel(v.Key))
		b.Write(key)
		b.WriteByte(':')
		value := v.Value
		if bytes.Equal(value, []byte(`""`)) && slices.Contains([]string{"login_accept_webhook_url", "consent_accept_webhook_url"}, v.Key) {
			value = json.RawMessage("null")
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// settingKinds are the JSON types of the settings, by their key in camelCase,
// those of their defaults: bool, int (seconds), string, array.
func settingKinds() map[string]string {
	kinds := map[string]string{}
	for _, v := range store.DefaultSettings().Document() {
		kinds[camel(v.Key)] = kind(v.Value)
	}
	return kinds
}

// settingKeys maps the keys of the API to those of the registry.
func settingKeys() map[string]string {
	keys := map[string]string{}
	for _, k := range store.SettingKeys() {
		keys[camel(k.Key)] = k.Key
	}
	return keys
}

// settingValues reads a document of settings, partial: the keys sent, each
// checked against the type of the setting, sessionTtl read as
// loginRememberFor, the fields of Symfony left out ignored, an unknown key
// refused (Q110).
func settingValues(b body) (values map[string]json.RawMessage, written, ignored []string, err error) {
	keys, kinds := settingKeys(), settingKinds()
	if err := b.unknown(append(slices.Collect(maps.Keys(keys)), settingsAlias), settingsIgnored...); err != nil {
		return nil, nil, nil, err
	}
	if b.has(settingsAlias) {
		if b.has("loginRememberFor") && !bytes.Equal(bytes.TrimSpace(b[settingsAlias]), bytes.TrimSpace(b["loginRememberFor"])) {
			return nil, nil, nil, requestViolations{{Field: settingsAlias, Message: "is the Symfony name of loginRememberFor, which is set otherwise: keep loginRememberFor"}}
		}
		if !b.has("loginRememberFor") {
			b["loginRememberFor"] = b[settingsAlias]
		}
	}
	values = map[string]json.RawMessage{}
	for _, field := range slices.Sorted(maps.Keys(b)) {
		switch {
		case slices.Contains(settingsIgnored, field):
			ignored = append(ignored, field)
			continue
		case field == settingsAlias:
			continue
		}
		raw := b[field]
		if k := kind(raw); k != "null" && k != kinds[field] {
			return nil, nil, nil, typeError(field, kinds[field], raw)
		}
		values[keys[field]] = raw
		written = append(written, field)
	}
	return values, written, ignored, nil
}

func (a *API) registerSettings() {
	a.Handle("GET "+Prefix+"/settings", Settings, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeResource(w, http.StatusOK, document(a.o.Config.Snapshot().Settings))
	}))
	// PUT is partial as PATCH is, as Symfony's PUT of the settings was.
	write := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(w, r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		values, written, ignored, err := settingValues(b)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		if len(ignored) > 0 && a.o.Logger != nil {
			a.o.Logger.InfoContext(r.Context(), "admin.settings_ignored", "fields", ignored)
		}
		if len(values) > 0 {
			if err := a.o.Writer.UpdateSettings(r.Context(), author(r), values); err != nil {
				a.fail(w, r, "", err)
				return
			}
		}
		a.wrote(r, Settings, "", written)
		writeResource(w, http.StatusOK, document(a.o.Config.Snapshot().Settings))
	})
	a.Handle("PUT "+Prefix+"/settings", Settings, write)
	a.Handle("PATCH "+Prefix+"/settings", Settings, write)
}
