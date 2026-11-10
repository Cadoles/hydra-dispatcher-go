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
	for name, tt := range map[string]struct{ yaml, err string }{
		"a key twice":            {"a:\n  b: 1\n  b: 2\n", `"b" twice`},
		"a merge of a list":      {"a: &l [x, y]\nb: { <<: *l }\n", "a merge (<<) of something else"},
		"a merge of a scalar":    {"b: { <<: x }\n", "a merge (<<) of something else"},
		"an alias to its holder": {"a: &x { b: *x }\n", "an alias to a node that holds it"},
		"a list holding itself":  {"a: &l [1, *l]\n", "an alias to a node that holds it"},
		"a merge of its holder":  {"a: &x { b: { <<: *x } }\n", "an alias to a node that holds it"},
		"a second document":      {"a: 1\n---\nb: 2\n", "one document"},
	} {
		if _, err := toJSON([]byte(tt.yaml)); err == nil || !strings.Contains(err.Error(), tt.err) {
			t.Errorf("%s: %v, want %q", name, err, tt.err)
		}
	}
	// An alias used twice, apart, is no loop.
	if got, err := toJSON([]byte("s: &s { x: 1 }\na: [*s, *s]\n")); err != nil || string(got) != `{"s":{"x":1},"a":[{"x":1},{"x":1}]}` {
		t.Errorf("an alias twice: %s, %v", got, err)
	}
	doc, err := JSON()
	if err != nil || !json.Valid(doc) {
		t.Fatalf("JSON: %v", err)
	}
}
