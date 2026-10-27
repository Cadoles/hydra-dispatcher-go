package config

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"900":     900 * time.Second,
		"0":       0,
		"5s":      5 * time.Second,
		"1h30m":   90 * time.Minute,
		"365d":    365 * 24 * time.Hour,
		" 30m ":   30 * time.Minute,
		"2629800": 2629800 * time.Second,
	} {
		got, err := parseDuration(strings.TrimSpace(in))
		if err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "soon", "-5s", "-1", "1.5d", "d"} {
		if _, err := parseDuration(in); err == nil {
			t.Errorf("parseDuration(%q): want an error", in)
		}
	}
}

func TestKey(t *testing.T) {
	for _, in := range []string{hexKey, strings.ToUpper(hexKey), base64Key, strings.TrimRight(base64Key, "=")} {
		if k, err := parseKey(in); err != nil || len(k) != 32 {
			t.Errorf("parseKey(%q) = %d bytes, %v", in, len(k), err)
		}
	}
	if k, err := parseKey("  "); err != nil || k != nil {
		t.Errorf("blank key = %v, %v; want unset", k, err)
	}
	for _, in := range []string{"too-short", hexKey[:62], "c2hvcnQ="} {
		_, err := parseKey(in)
		if err == nil {
			t.Errorf("parseKey(%q): want an error", in)
		} else if strings.Contains(err.Error(), in) {
			t.Errorf("error %q quotes the key", err)
		}
	}
}

func TestListAndLocalized(t *testing.T) {
	var doc struct {
		Seq      List      `yaml:"seq"`
		Comma    List      `yaml:"comma"`
		Keys     Keys      `yaml:"keys"`
		Text     Localized `yaml:"text"`
		PerLang  Localized `yaml:"per_lang"`
		Explicit *List     `yaml:"explicit"`
	}
	err := yaml.Unmarshal([]byte(`
seq: [a, b]
comma: "a, b,,c "
keys: "`+hexKey+`,`+base64Key+`"
text: http://example.org/icon.svg
per_lang: { fr: Bonjour, en: Hello }
explicit: []
`), &doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(doc.Seq, "|") != "a|b" || strings.Join(doc.Comma, "|") != "a|b|c" || len(doc.Keys) != 2 ||
		doc.Text[""] != "http://example.org/icon.svg" || doc.PerLang["en"] != "Hello" ||
		doc.Explicit == nil || len(*doc.Explicit) != 0 {
		t.Errorf("decoded = %+v", doc)
	}
}

func TestSeedStep(t *testing.T) {
	var steps []SeedStep
	if err := yaml.Unmarshal([]byte(`[{id: a, order: 0}, {app_id: b, position: 1}]`), &steps); err != nil {
		t.Fatal(err)
	}
	if steps[0] != (SeedStep{"a", 0}) || steps[1] != (SeedStep{"b", 1}) {
		t.Errorf("steps = %+v", steps)
	}
	if err := yaml.Unmarshal([]byte(`[{id: a}]`), &steps); err == nil {
		t.Error("step without order: want an error")
	}
}
