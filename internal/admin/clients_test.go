package admin

import (
	"net/http"
	"testing"
)

// An absent client answers 404 before its body is read, as at P18 and as
// the apps and the flows (revue R38).
func TestAbsentClientFirst(t *testing.T) {
	r := newResources(t)
	for _, tt := range []struct{ method, body string }{
		{http.MethodPut, `{"id": "absent", "bogus": 1}`},
		{http.MethodPatch, `{"secret": null}`},
		{http.MethodPatch, `{"secret": 1}`},
		{http.MethodPatch, `{"secret": "a-new-s3cret"}`},
	} {
		ct := "application/merge-patch+json"
		if tt.method == http.MethodPut {
			ct = "application/json"
		}
		if w := r.do(r.all, tt.method, "/admin/v1/oauth2-clients/absent", ct, tt.body); w.Code != http.StatusNotFound {
			t.Errorf("%s %s: %d %s", tt.method, tt.body, w.Code, w.Body)
		}
	}
}
