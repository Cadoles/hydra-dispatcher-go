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
		"106751d": 106751 * 24 * time.Hour,
	} {
		got, err := parseDuration(strings.TrimSpace(in))
		if err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "soon", "-5s", "-1", "1.5d", "d", "-1d",
		// Too long for a time.Duration: an error, not a wrapped value.
		"10000000000", "9223372036854775807", "106752d", "2562048h"} {
		if got, err := parseDuration(in); err == nil {
			t.Errorf("parseDuration(%q) = %v, want an error", in, got)
		}
	}
}

func TestKey(t *testing.T) {
	wrapped := base64Key[:20] + "\n" + base64Key[20:]
	for _, in := range []string{hexKey, strings.ToUpper(hexKey), base64Key, strings.TrimRight(base64Key, "="), wrapped, hexKey + "\n"} {
		if k, err := parseKey(in); err != nil || len(k) != 32 {
			t.Errorf("parseKey(%q) = %d bytes, %v", in, len(k), err)
		}
	}
	if k, err := parseKey("  "); err != nil || k != nil {
		t.Errorf("blank key = %v, %v; want unset", k, err)
	}
	for _, in := range []string{"too-short", hexKey[:62], "c2hvcnQ=", "0x" + hexKey, strings.Repeat("a", 32)} {
		_, err := parseKey(in)
		if err == nil {
			t.Errorf("parseKey(%q): want an error", in)
		} else if strings.Contains(err.Error(), in) {
			t.Errorf("error %q quotes the key", err)
		}
	}
	// A list or a map is no key, rather than an unset one.
	var doc struct {
		K Key `yaml:"k"`
	}
	for _, in := range []string{"k: [a, b]", "k: { a: b }"} {
		if err := yaml.Unmarshal([]byte(in), &doc); err == nil || !strings.Contains(err.Error(), "line 1: a key is a string") {
			t.Errorf("%q: err = %v", in, err)
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
		Partial  Localized `yaml:"partial"`
		Nulls    Localized `yaml:"nulls"`
		Blank    Localized `yaml:"blank"`
		Explicit *List     `yaml:"explicit"`
	}
	err := yaml.Unmarshal([]byte(`
seq: [a, b]
comma: "a, b,,c "
keys: "`+hexKey+`,`+base64Key+`"
text: http://example.org/icon.svg
per_lang: { fr: Bonjour, en: Hello }
partial: { fr: Bonjour, en: ~, de: "" }
nulls: { fr: ~, en: ~ }
blank: ""
explicit: []
`), &doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(doc.Seq, "|") != "a|b" || strings.Join(doc.Comma, "|") != "a|b|c" || len(doc.Keys) != 2 ||
		doc.Text[""] != "http://example.org/icon.svg" || doc.PerLang["en"] != "Hello" ||
		len(doc.Partial) != 1 || doc.Partial["fr"] != "Bonjour" || doc.Nulls != nil || doc.Blank != nil ||
		doc.Explicit == nil || len(*doc.Explicit) != 0 {
		t.Errorf("decoded = %+v", doc)
	}
	var lists struct {
		L List `yaml:"l"`
	}
	if err := yaml.Unmarshal([]byte("l: { a: b }"), &lists); err == nil {
		t.Error("map as a list: want an error")
	}
}

func TestSeedStep(t *testing.T) {
	var steps []SeedStep
	if err := yaml.Unmarshal([]byte(`[
  {id: a, order: 0},
  {app_id: b, position: 1, subject_check: equal},
  {id: c, order: "2"},
  {id: d, app_id: d, order: 3, position: 3},
]`), &steps); err != nil {
		t.Fatal(err)
	}
	want := []SeedStep{{AppID: "a"}, {AppID: "b", Position: 1, SubjectCheck: "equal"}, {AppID: "c", Position: 2}, {AppID: "d", Position: 3}}
	for i := range want {
		if steps[i] != want[i] {
			t.Errorf("step %d = %+v, want %+v", i, steps[i], want[i])
		}
	}
	for in, msg := range map[string]string{
		`[{id: a}]`:                           "step without order or position",
		`[{order: 0}]`:                        "step without id or app_id",
		`[{id: a, app_id: b, order: 0}]`:      "step id and app_id differ",
		`[{id: a, order: 0, position: 1}]`:    "step order and position differ",
		`[{id: a, order: first}]`:             `step order "first" is not an integer`,
		`[{ap_id: a, order: 0}]`:              `unknown step key "ap_id"`,
		`[{id: a, order: 0, subject: equal}]`: `unknown step key "subject"`,
		`[a]`:                                 "a step is a mapping",
	} {
		if err := yaml.Unmarshal([]byte(in), &steps); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: err = %v, want %q", in, err, msg)
		}
	}
}
