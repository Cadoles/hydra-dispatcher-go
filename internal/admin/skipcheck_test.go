package admin

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// skipCheckKey is a key of the pre-check, in hex.
var skipCheckKey = strings.Repeat("5c", 32)

// The fields of the pre-check of an app (P26b): the key written, never read,
// kept by a write without it; the URL removed with its key and signals; a
// PUT of Symfony's fields keeps them (Q107); a representation read back, its
// skipCheckKeySet included, written again as it is; the key in no log.
func TestAppSkipCheck(t *testing.T) {
	r := newResources(t)
	w := r.do(r.all, http.MethodPost, "/admin/v1/apps", "", `{"id": "otp", "loginUrl": "https://otp/login", "consentUrl": "https://otp/consent",
		"method": "otp", "skipCheckUrl": "https://otp/skip-check", "skipCheckKey": "`+skipCheckKey+`", "skipCheckSignals": ["ip", "device_age"]}`)
	app := decodeInto[appJSON](t, w)
	if w.Code != http.StatusCreated || app.SkipCheckURL == nil || *app.SkipCheckURL != "https://otp/skip-check" || !app.SkipCheckKeySet ||
		!slices.Equal(app.SkipCheckSignals, []string{"ip", "device_age"}) || strings.Contains(w.Body.String(), skipCheckKey) {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	if got := r.writer.apps[0].SkipCheckKey; got != skipCheckKey {
		t.Errorf("key written: %q", got)
	}
	// Another field: the key held stays.
	w = r.do(r.all, http.MethodPatch, "/admin/v1/apps/otp", "application/merge-patch+json", `{"method": "totp"}`)
	if app = decodeInto[appJSON](t, w); w.Code != 200 || !app.SkipCheckKeySet || r.writer.apps[0].SkipCheckKey != skipCheckKey {
		t.Errorf("PATCH method: %d %s", w.Code, w.Body)
	}
	// PUT of a tool written for Symfony: the fields of the pre-check kept.
	w = r.do(r.all, http.MethodPut, "/admin/v1/apps/otp", "", `{"loginUrl": "https://otp/login", "consentUrl": "https://otp/consent", "logoutUrl": "", "method": "otp"}`)
	if app = decodeInto[appJSON](t, w); w.Code != 200 || app.SkipCheckURL == nil || !app.SkipCheckKeySet || len(app.SkipCheckSignals) != 2 {
		t.Errorf("PUT of Symfony's fields: %d %s", w.Code, w.Body)
	}
	// The representation read back, skipCheckKeySet included, written again.
	read := r.do(r.reader, http.MethodGet, "/admin/v1/apps/otp", "", "").Body.String()
	if w = r.do(r.all, http.MethodPut, "/admin/v1/apps/otp", "", read); w.Code != 200 || r.writer.apps[0].SkipCheckKey != skipCheckKey {
		t.Errorf("PUT of the read: %d %s", w.Code, w.Body)
	}
	// Bad writes: a short key, unnamed in the answer; an unknown signal; a URL
	// without a key on an app that has none; signals without the URL.
	for name, tt := range map[string]struct{ path, body, field string }{
		"short key":         {"/admin/v1/apps/otp", `{"skipCheckKey": "c2hvcnQ="}`, "skipCheckKey"},
		"unknown signal":    {"/admin/v1/apps/otp", `{"skipCheckSignals": ["cookies"]}`, "skipCheckSignals[0]"},
		"signals, no URL":   {"/admin/v1/apps/otp", `{"skipCheckUrl": null, "skipCheckSignals": ["ip"]}`, "skipCheckSignals"},
		"key, no URL":       {"/admin/v1/apps/otp", `{"skipCheckUrl": "", "skipCheckKey": "` + skipCheckKey + `"}`, "skipCheckKey"},
		"relative URL":      {"/admin/v1/apps/otp", `{"skipCheckUrl": "/check"}`, "skipCheckUrl"},
		"URL without a key": {"/admin/v1/apps", `{"id": "b", "loginUrl": "https://b/l", "consentUrl": "https://b/c", "method": "m", "skipCheckUrl": "https://b/check"}`, "skipCheckKey"},
	} {
		method, contentType := http.MethodPatch, "application/merge-patch+json"
		if !strings.HasSuffix(tt.path, "/otp") {
			method, contentType = http.MethodPost, ""
		}
		w := r.do(r.all, method, tt.path, contentType, tt.body)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"propertyPath":"`+tt.field+`"`) || strings.Contains(w.Body.String(), "c2hvcnQ") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// A key of another type: refused as the other types are, unquoted.
	if w := r.do(r.all, http.MethodPatch, "/admin/v1/apps/otp", "application/merge-patch+json", `{"skipCheckKey": 1}`); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), `\"skipCheckKey\" attribute must be \"string\"`) {
		t.Errorf("key not a string: %d %s", w.Code, w.Body)
	}
	// The URL removed: its key and signals with it.
	w = r.do(r.all, http.MethodPatch, "/admin/v1/apps/otp", "application/merge-patch+json", `{"skipCheckUrl": null}`)
	if app = decodeInto[appJSON](t, w); w.Code != 200 || app.SkipCheckURL != nil || app.SkipCheckKeySet || len(app.SkipCheckSignals) != 0 ||
		!strings.Contains(w.Body.String(), `"skipCheckSignals":[]`) || r.writer.apps[0].SkipCheckKey != "" {
		t.Errorf("URL removed: %d %s", w.Code, w.Body)
	}
	if strings.Contains(r.logs.String(), skipCheckKey) {
		t.Errorf("the key in the logs:\n%s", r.logs.String())
	}
}

// The pre-check in a flow (P26b): the acr values and the steps written and
// read; skipCheck absent keeps the step's, false for a new app; refused on
// the first step.
func TestFlowSkipCheck(t *testing.T) {
	r := newResources(t)
	r.withApps("a", "b", "c")
	w := r.do(r.all, http.MethodPost, "/admin/v1/flows", "", `{"id": "f", "title": {"fr": "F"}, "description": {"fr": "D"},
		"skipCheckAllowedAcr": ["loa1", "loa2"], "steps": [{"appId": "a", "stepOrder": 0}, {"appId": "b", "stepOrder": 1, "skipCheck": true}]}`)
	f := decodeInto[flowJSON](t, w)
	if w.Code != http.StatusCreated || !slices.Equal(f.SkipCheckAllowedACR, []string{"loa1", "loa2"}) || f.Steps[0].SkipCheck || !f.Steps[1].SkipCheck {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
	// The steps again without skipCheck, c added: b keeps it, c has none.
	w = r.do(r.all, http.MethodPatch, "/admin/v1/flows/f", "application/merge-patch+json",
		`{"steps": [{"appId": "a", "stepOrder": 0}, {"appId": "b", "stepOrder": 1}, {"appId": "c", "stepOrder": 2}]}`)
	if f = decodeInto[flowJSON](t, w); w.Code != 200 || !f.Steps[1].SkipCheck || f.Steps[2].SkipCheck {
		t.Errorf("steps without skipCheck: %d %s", w.Code, w.Body)
	}
	// null or [] for no acr value; a PUT of Symfony's fields keeps them.
	w = r.do(r.all, http.MethodPatch, "/admin/v1/flows/f", "application/merge-patch+json", `{"skipCheckAllowedAcr": null}`)
	if f = decodeInto[flowJSON](t, w); w.Code != 200 || f.SkipCheckAllowedACR == nil || len(f.SkipCheckAllowedACR) != 0 {
		t.Errorf("no acr value: %d %s", w.Code, w.Body)
	}
	for name, tt := range map[string]struct{ body, field string }{
		"first step":       {`{"steps": [{"appId": "a", "stepOrder": 0, "skipCheck": true}, {"appId": "b", "stepOrder": 1}]}`, "steps[0].skipCheck"},
		"acr with a space": {`{"skipCheckAllowedAcr": ["loa 1"]}`, "skipCheckAllowedAcr[0]"},
	} {
		w := r.do(r.all, http.MethodPatch, "/admin/v1/flows/f", "application/merge-patch+json", tt.body)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"propertyPath":"`+tt.field+`"`) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	w = r.do(r.all, http.MethodPatch, "/admin/v1/flows/f", "application/merge-patch+json", `{"steps": [{"appId": "a", "stepOrder": 0}, {"appId": "b", "stepOrder": 1, "skipCheck": "yes"}]}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `\"steps[1].skipCheck\" attribute must be \"boolean\"`) {
		t.Errorf("not a boolean: %d %s", w.Code, w.Body)
	}
}
