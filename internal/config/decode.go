package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	strTag   = "!!str"
	nullTag  = "!!null"
	floatTag = "!!float"
	mergeTag = "!!merge"
)

// quotedStyles make a scalar a string, whatever it holds.
const quotedStyles = yaml.SingleQuotedStyle | yaml.DoubleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle

var (
	unmarshalerType = reflect.TypeFor[yaml.Unmarshaler]()
	ignoredType     = reflect.TypeFor[ignored]()
)

// decodeFile expands ${VAR} in every value, checks every key against the
// schema (an unknown key is an error, so typos do not pass silently) and
// refuses null outside the seed, then decodes. It works on the parsed tree,
// so errors give the lines of the file.
func decodeFile(data []byte, c *Config, lookupEnv func(string) (string, bool)) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) { // empty file
			return nil
		}
		return err
	}
	for {
		// An empty document, such as a trailing ---, holds nothing to lose.
		var next yaml.Node
		err := dec.Decode(&next)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if len(next.Content) > 0 && next.Content[0].ShortTag() != nullTag {
			return fmt.Errorf("line %d: a second YAML document would be ignored, remove it", next.Content[0].Line)
		}
	}

	p := prepare{
		lookupEnv: lookupEnv,
		done:      map[*yaml.Node]bool{},
		walking:   map[*yaml.Node]bool{},
		walked:    map[visit]bool{},
	}
	p.walk(&doc, reflect.TypeFor[Config](), "")
	if err := errors.Join(p.errs...); err != nil {
		return err
	}
	if err := doc.Decode(c); err != nil {
		return err
	}
	c.Seed.NullSettings = nullSettings(&doc)
	nullScopes(&doc, c.Seed.OAuth2Clients)
	return nil
}

// prepare expands and checks a parsed file, collecting every error.
type prepare struct {
	lookupEnv func(string) (string, bool)
	done      map[*yaml.Node]bool // expanded once, even when aliased
	walking   map[*yaml.Node]bool // anchored nodes being walked, to refuse a cycle
	walked    map[visit]bool      // anchors walked through an alias
	errs      []error
}

// visit is an anchor walked as a type; nil for values without a schema.
type visit struct {
	n *yaml.Node
	t reflect.Type
}

func (p *prepare) fail(n *yaml.Node, path, format string, args ...any) {
	p.errs = append(p.errs, fmt.Errorf("line %d: %s: %s", n.Line, path, fmt.Sprintf(format, args...)))
}

// walk prepares n, which decodes into a value of type t at path.
func (p *prepare) walk(n *yaml.Node, t reflect.Type, path string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == ignoredType {
		return // never read
	}
	defer p.enter(n)()
	// yaml.v3 would keep the default of a string, a number or a duration,
	// empty a list, and leave an allowlist to copy the admin one. No
	// expansion gives a null, so an alias is checked where it stands.
	if deref(n).ShortTag() == nullTag && path != "" && !inSeed(path) {
		p.fail(n, path, "is null: remove the key to keep its default, or write \"\" or [] for an empty value")
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, child := range n.Content {
			p.walk(child, t, path)
		}
		return
	case yaml.AliasNode:
		p.alias(n, t, path, func() { p.walk(n.Alias, t, path) })
		return
	case yaml.ScalarNode:
		p.scalar(n, path, t.Kind() == reflect.Interface)
		p.typed(n, t, path)
		return
	}
	switch {
	case t.Kind() == reflect.Interface: // app options
		p.values(n, path, true)
	case reflect.PointerTo(t).Implements(unmarshalerType):
		// List, Localized, SeedStep…: they check their own shape.
		p.values(n, path, false)
	case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode:
		p.mapping(n, t, path)
	case t.Kind() == reflect.Map && n.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p.walk(n.Content[i+1], t.Elem(), join(path, n.Content[i].Value))
		}
	case t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		for i, item := range n.Content {
			p.walk(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i))
		}
	}
	// Any other shape is a type error, which the decoder reports.
}

func (p *prepare) mapping(n *yaml.Node, t reflect.Type, path string) {
	fields := yamlFields(t)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMerge(k) {
			// <<: *anchor, or a list of them: their keys belong to t too.
			merged := []*yaml.Node{v}
			if v.Kind == yaml.SequenceNode {
				merged = v.Content
			}
			for _, m := range merged {
				p.walk(m, t, path)
			}
			continue
		}
		ft, ok := fields[k.Value]
		if !ok {
			p.fail(k, join(path, k.Value), "unknown key")
			continue
		}
		p.walk(v, ft, join(path, k.Value))
	}
}

// values expands every scalar under n, without checking keys.
func (p *prepare) values(n *yaml.Node, path string, keepQuoted bool) {
	defer p.enter(n)()
	switch n.Kind {
	case yaml.ScalarNode:
		p.scalar(n, path, keepQuoted)
	case yaml.AliasNode:
		p.alias(n, nil, path, func() { p.values(n.Alias, path, keepQuoted) })
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p.values(n.Content[i+1], join(path, n.Content[i].Value), keepQuoted)
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			p.values(item, fmt.Sprintf("%s[%d]", path, i), keepQuoted)
		}
	}
}

// enter marks an anchored node as being walked, until the returned function
// runs.
func (p *prepare) enter(n *yaml.Node) (leave func()) {
	if n.Anchor == "" || p.walking[n] {
		return func() {}
	}
	p.walking[n] = true
	return func() { delete(p.walking, n) }
}

// alias walks the anchor of n once per type: aliases cannot multiply the work
// (yaml.v3 bounds them only when decoding), and an anchor that contains
// itself is an error rather than an endless walk.
func (p *prepare) alias(n *yaml.Node, t reflect.Type, path string, walk func()) {
	switch v := (visit{n.Alias, t}); {
	case p.walking[n.Alias]:
		p.fail(n, path, "anchor %q contains itself", n.Value)
	case !p.walked[v]:
		p.walked[v] = true
		walk()
	}
}

// scalar expands ${VAR} in n. An expanded value loses its quoting and is
// typed by what it became ("${TIMEOUT:-5s}" decodes as a duration,
// "${UI:-false}" as a boolean), with three exceptions. An explicit tag stays:
// !!str ${CLIENT_ID} is a string. It is never null: "" stays an empty string,
// so an empty variable empties a list instead of restoring its default. Under
// an any-typed key (app options), a quoted value stays a string:
// "${CLIENT_ID}" holding 0123 must not become the number 83.
func (p *prepare) scalar(n *yaml.Node, path string, keepQuoted bool) {
	if p.done[n] {
		return
	}
	p.done[n] = true
	if strings.Contains(n.Value, "%env(") {
		p.fail(n, path, "Symfony %%env()%% placeholders are not supported, write ${VAR}")
		return
	}
	v, err := expand(n.Value, p.lookupEnv)
	if err != nil {
		p.fail(n, path, "%v", err)
		return
	}
	if v == n.Value {
		return
	}
	quoted := n.Style&quotedStyles != 0
	n.Value, n.Style = v, n.Style&yaml.TaggedStyle
	if n.Style == 0 {
		// The parser tagged the reference itself (!!str): let the value decide.
		n.Tag = ""
		if (keepQuoted && quoted) || n.ShortTag() == nullTag {
			n.Tag = strTag
		}
	}
}

// typed lets a boolean or a number key decide a quoted value, as it decides
// an expanded one: "512" is a number for max_in_flight. It refuses a float
// for an integer, which yaml.v3 would truncate: 1.9 replicas would be 1.
func (p *prepare) typed(n *yaml.Node, t reflect.Type, path string) {
	switch t.Kind() {
	case reflect.Bool, reflect.Float32, reflect.Float64:
	default:
		if !isInteger(t) {
			return
		}
	}
	if n.Style&quotedStyles != 0 && n.Style&yaml.TaggedStyle == 0 {
		n.Style, n.Tag = 0, ""
		if n.ShortTag() == nullTag { // "" stays an error, not the default
			n.Tag = strTag
		}
	}
	if isInteger(t) && n.ShortTag() == floatTag {
		p.fail(n, path, "%s is not an integer", n.Value)
	}
}

var integerKinds = []reflect.Kind{
	reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
	reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
}

// isInteger reports the integer types yaml.v3 decodes itself, truncating a
// float; Duration parses its own value.
func isInteger(t reflect.Type) bool {
	return slices.Contains(integerKinds, t.Kind()) && !reflect.PointerTo(t).Implements(unmarshalerType)
}

// nullSettings lists the seed settings the file sets to null (~).
func nullSettings(doc *yaml.Node) []string {
	seed := mappingValue(doc, "dispatcher")
	t := reflect.TypeFor[SeedSettings]()
	var keys []string
	for i := range t.NumField() {
		k, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if v := mappingValue(seed, k); v != nil && v.ShortTag() == nullTag {
			keys = append(keys, k)
		}
	}
	return keys
}

// nullScopes gives no scope to the clients whose scopes are null, as Symfony
// does: only absent scopes get the default, admin:flows.
func nullScopes(doc *yaml.Node, clients []SeedClient) {
	seq := mappingValue(mappingValue(doc, "dispatcher"), "oauth2_clients")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return
	}
	i := 0
	for _, item := range seq.Content {
		if deref(item).ShortTag() == nullTag || i == len(clients) {
			continue // the decoder drops a null entry
		}
		if s := mappingValue(item, "scopes"); s != nil && s.ShortTag() == nullTag {
			clients[i].Scopes = &List{}
		}
		i++
	}
}

// mappingValue returns the value of key in n, merged keys included: as when
// decoding, a key of the mapping wins over a merged one, and an earlier
// merged mapping over a later one.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n = deref(n); n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = deref(n.Content[0])
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	var merge *yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i]; {
		case isMerge(k):
			merge = n.Content[i+1]
		case k.Value == key:
			return deref(n.Content[i+1])
		}
	}
	if merge != nil {
		for _, m := range mergedMappings(merge) {
			if v := mappingValue(m, key); v != nil {
				return v
			}
		}
	}
	return nil
}

// mergedMappings returns the mappings a << key merges: one, or a list.
func mergedMappings(v *yaml.Node) []*yaml.Node {
	items := []*yaml.Node{deref(v)}
	if items[0].Kind == yaml.SequenceNode {
		items = items[0].Content
	}
	var mappings []*yaml.Node
	for _, m := range items {
		if m = deref(m); m.Kind == yaml.MappingNode {
			mappings = append(mappings, m)
		}
	}
	return mappings
}

func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// yamlFields maps the keys of struct t, inline fields included, to their
// types. As for envKeys, a field without a yaml tag is no key.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		switch {
		case opts == "inline":
			maps.Copy(fields, yamlFields(f.Type))
		case name != "" && name != "-":
			fields[name] = f.Type
		}
	}
	return fields
}

// inSeed reports a path of the dispatcher: block, where ~ has a meaning: it
// resets a setting, and is no icon or no scope.
func inSeed(path string) bool {
	return path == "dispatcher" || strings.HasPrefix(path, "dispatcher.")
}

func isMerge(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" && k.ShortTag() == mergeTag
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// at locates n in an error: "line 12: ", or nothing for a value that comes
// from a variable.
func at(n *yaml.Node) string {
	if n.Line == 0 {
		return ""
	}
	return fmt.Sprintf("line %d: ", n.Line)
}
