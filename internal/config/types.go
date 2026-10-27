package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration accepts Go durations ("5s", "30m"), days ("365d") and bare
// integers as seconds ("900"), the unit of the Symfony settings and of
// OAUTH2_TOKEN_TTL.
type Duration time.Duration

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := parseDuration(strings.TrimSpace(n.Value))
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		if secs < 0 {
			return 0, fmt.Errorf("negative duration %q", s)
		}
		return time.Duration(secs) * time.Second, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// List accepts a YAML sequence or a comma-separated string, the form lists
// take in environment variables ("10.0.0.0/8,172.16.0.0/12").
type List []string

func (l *List) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		var items []string
		if err := n.Decode(&items); err != nil {
			return err
		}
		*l = append(List{}, items...)
		return nil
	}
	*l = splitList(n.Value)
	return nil
}

func splitList(s string) List {
	l := List{}
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			l = append(l, item)
		}
	}
	return l
}

// Key is a 32-byte secret given in hex (64 characters) or base64. Errors
// never quote the value.
type Key []byte

func (k *Key) UnmarshalYAML(n *yaml.Node) error {
	key, err := parseKey(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*k = key
	return nil
}

var errKeySize = errors.New("key must be 32 bytes, given as 64 hex characters or base64")

func parseKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errKeySize
}

// Keys is a list of Key, as a YAML sequence or a comma-separated string.
type Keys []Key

func (ks *Keys) UnmarshalYAML(n *yaml.Node) error {
	var l List
	if err := l.UnmarshalYAML(n); err != nil {
		return err
	}
	keys := Keys{}
	for i, s := range l {
		k, err := parseKey(s)
		if err != nil {
			return fmt.Errorf("line %d, key %d: %w", n.Line, i, err)
		}
		keys = append(keys, k)
	}
	*ks = keys
	return nil
}

// Localized maps a locale to a text. A plain string applies to every locale,
// under the empty locale: lookups fall back to it.
type Localized map[string]string

func (l *Localized) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = Localized{"": n.Value}
		return nil
	}
	var m map[string]string
	if err := n.Decode(&m); err != nil {
		return err
	}
	*l = m
	return nil
}
