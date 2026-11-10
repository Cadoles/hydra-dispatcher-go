package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// The document read in JSON: in its order, anchors and merges resolved, a key
// of the mapping winning over a merged one; a key twice refused, which JSON
// would hold twice (revue R36).
func TestToJSON(t *testing.T) {
	got, err := toJSON([]byte(`
shared: &shared { b: 1, c: 2 }
z: { <<: *shared, c: 3, a: [x, "y"] }
`))
	if err != nil || string(got) != `{"shared":{"b":1,"c":2},"z":{"c":3,"a":["x","y"],"b":1}}` {
		t.Errorf("toJSON = %s, %v", got, err)
	}
	if _, err := toJSON([]byte("a:\n  b: 1\n  b: 2\n")); err == nil || !strings.Contains(err.Error(), `"b" twice`) {
		t.Errorf("a key twice: %v", err)
	}
	doc, err := JSON()
	if err != nil || !json.Valid(doc) {
		t.Fatalf("JSON: %v", err)
	}
}
