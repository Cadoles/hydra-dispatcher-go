package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const envPrefix = "DISPATCHER_"

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// expand replaces ${VAR} by its value (empty when unset) and ${VAR:-default}
// by its value, or by default when unset or empty, as a shell does.
func expand(s string, lookupEnv func(string) (string, bool)) string {
	return envRef.ReplaceAllStringFunc(s, func(ref string) string {
		m := envRef.FindStringSubmatch(ref)
		v, _ := lookupEnv(m[1])
		if v == "" && m[2] != "" {
			return m[3]
		}
		return v
	})
}

// expandNode expands every scalar value (keys are left alone). An expanded
// value loses its quoting and tag, so it is typed by what it became:
// "${TIMEOUT:-5s}" decodes as a duration, "${UI:-false}" as a boolean.
func expandNode(n *yaml.Node, lookupEnv func(string) (string, bool)) {
	switch n.Kind {
	case yaml.ScalarNode:
		if v := expand(n.Value, lookupEnv); v != n.Value {
			n.Value, n.Tag, n.Style = v, "", 0
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			expandNode(n.Content[i], lookupEnv)
		}
	default:
		for _, child := range n.Content {
			expandNode(child, lookupEnv)
		}
	}
}

// envKey is one infrastructure key reachable by a DISPATCHER_* variable.
type envKey struct {
	name  string // DISPATCHER_SERVER_BASE_URL
	path  string // server.base_url
	field reflect.Value
}

// envKeys lists the keys of c that a variable can override: every leaf of
// every section but the seed. Maps (ui.csp_extra) are not reachable.
func envKeys(c *Config) []envKey {
	var keys []envKey
	var walk func(v reflect.Value, path []string)
	walk = func(v reflect.Value, path []string) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			tag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
			if tag == "" || tag == "-" || (len(path) == 0 && tag == "dispatcher") {
				continue
			}
			f, p := v.Field(i), append(append([]string{}, path...), tag)
			switch {
			case f.Kind() == reflect.Map:
			case f.Kind() == reflect.Struct:
				walk(f, p)
			default:
				keys = append(keys, envKey{
					name:  envPrefix + strings.ToUpper(strings.Join(p, "_")),
					path:  strings.Join(p, "."),
					field: f,
				})
			}
		}
	}
	walk(reflect.ValueOf(c).Elem(), nil)
	return keys
}

// applyEnv overrides keys from DISPATCHER_<SECTION>_<KEY> variables. A value
// is decoded like a YAML scalar, so it takes the same forms as in the file:
// "30m", "365d", "a,b,c", "true".
func applyEnv(c *Config, lookupEnv func(string) (string, bool)) error {
	for _, k := range envKeys(c) {
		v, ok := lookupEnv(k.name)
		if !ok {
			continue
		}
		target := k.field
		if target.Kind() == reflect.Pointer {
			// Set, even to "": an empty allowlist means no address, it must
			// not fall back to the admin list.
			target.Set(reflect.New(target.Type().Elem()))
			target = target.Elem()
		}
		node := &yaml.Node{Kind: yaml.ScalarNode, Value: v}
		if err := node.Decode(target.Addr().Interface()); err != nil {
			return fmt.Errorf("%s (%s): %w", k.name, k.path, err)
		}
	}
	return nil
}
