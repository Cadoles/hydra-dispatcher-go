package seedfile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The scopes of the table, dumped as the seed takes them; none, no section.
func TestScopes(t *testing.T) {
	snap := store.NewSnapshot(nil, nil, store.DefaultSettings())
	snap.Scopes = []store.Scope{
		{Name: "groups", Label: map[string]string{"fr": "Vos groupes"}, Claims: []store.ScopeClaim{{Claim: "groups", Label: map[string]string{"fr": "Groupes"}}}},
		{Name: "profile", Label: map[string]string{"en": "Who you are"}},
	}
	var b bytes.Buffer
	if err := Write(&b, snap, map[string]bool{"scopes": true}, Options{}); err != nil {
		t.Fatal(err)
	}
	want := `  scopes:
    - name: groups
      label:
        fr: Vos groupes
      claims:
        - claim: groups
          label:
            fr: Groupes
    - name: profile
      label:
        en: Who you are
`
	if !strings.Contains(b.String(), want) {
		t.Errorf("dump:\n%s", b.String())
	}
	b.Reset()
	if err := Write(&b, store.NewSnapshot(nil, nil, store.DefaultSettings()), map[string]bool{"scopes": true}, Options{}); err != nil || strings.Contains(b.String(), "scopes") {
		t.Errorf("none: %v\n%s", err, b.String())
	}
}
