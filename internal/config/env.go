package config

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const envPrefix = "DISPATCHER_"

var envRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// errEnvRef does not quote the value: it may hold a secret.
var errEnvRef = errors.New("unsupported ${...}: write ${VAR} or ${VAR:-default}, and $${ for a literal ${")

// expand replaces ${VAR} by its value (empty when unset) and ${VAR:-default}
// by its value, or by default when unset or empty, as a shell does. $${ is a
// literal ${. Any other ${ is an error rather than left as is: ${VAR-default}
// or a nested ${A:-${B}} would otherwise pass unexpanded.
func expand(s string, lookupEnv func(string) (string, bool)) (string, error) {
	if !strings.Contains(s, "${") {
		return s, nil
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		if i > 0 && s[i-1] == '$' {
			b.WriteString(s[:i-1] + "${")
			s = s[i+2:]
			continue
		}
		b.WriteString(s[:i])
		m := envRef.FindStringSubmatch(s[i:])
		if m == nil || strings.Contains(m[3], "${") {
			return "", errEnvRef
		}
		v, _ := lookupEnv(m[1])
		if v == "" && m[2] != "" {
			v = m[3]
		}
		b.WriteString(v)
		s = s[i+len(m[0]):]
	}
}

// lookupIn looks a variable up in an os.Environ() list; the first entry of a
// name wins, as with os.Getenv.
func lookupIn(environ []string) func(string) (string, bool) {
	vars := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			if _, dup := vars[k]; !dup {
				vars[k] = v
			}
		}
	}
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
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
// "30m", "365d", "a,b,c", "true". It is never null: "" empties a string, a
// list or a key, and is an error for a boolean, a number or a duration.
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
		if v == "" && target.Kind() != reflect.String && target.Kind() != reflect.Slice {
			return fmt.Errorf("%s (%s): is empty", k.name, k.path)
		}
		node := &yaml.Node{Kind: yaml.ScalarNode, Value: v}
		if target.Kind() == reflect.String || node.ShortTag() == nullTag {
			node.Tag = strTag
		}
		if err := node.Decode(target.Addr().Interface()); err != nil {
			var typeErr *yaml.TypeError
			if errors.As(err, &typeErr) { // its message gives a line 0
				return fmt.Errorf("%s (%s): %q is not a valid %s", k.name, k.path, v, target.Kind())
			}
			return fmt.Errorf("%s (%s): %w", k.name, k.path, err)
		}
	}
	return nil
}

// unknownOverrides warns about the DISPATCHER_<SECTION>_* variables that
// reach no key, typos mostly, unless the file references them. Other
// DISPATCHER_* names stay free for ${VAR} references, like
// DISPATCHER_COOKIE_KEY in the design document's example.
func unknownOverrides(environ []string, referenced map[string]bool) []string {
	known := maps.Clone(referenced)
	for _, k := range envKeys(&Config{}) {
		known[k.name] = true
	}
	var sections []string
	t := reflect.TypeFor[Config]()
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		sections = append(sections, envPrefix+strings.ToUpper(tag)+"_")
	}
	var warnings []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if known[name] {
			continue
		}
		known[name] = true // once per name
		for _, s := range sections {
			if strings.HasPrefix(name, s) {
				warnings = append(warnings, name+" is ignored: it names no key (ui.csp_extra and the dispatcher: seed are not overridable)")
				break
			}
		}
	}
	return warnings
}
