package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeThemeDir writes files, by their path, under a new directory.
func writeThemeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const themeManifest = "name: demo\nversion: 1.0.0\napi: 1\n"

// theme check takes one directory, after check; its help is not an error.
func TestThemeUsage(t *testing.T) {
	for _, args := range [][]string{{"theme"}, {"theme", "nope"}, {"theme", "check"}, {"theme", "check", "a", "b"}, {"theme", "check", ""}, {"theme", "check", "-nope", "a"}} {
		if err := run(context.Background(), args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v", args, err)
		}
	}
	if err := run(context.Background(), []string{"theme", "check", "-h"}, io.Discard); err != nil {
		t.Errorf("-h: %v", err)
	}
}

// theme check prints one line by problem and fails, or one line for the theme
// that passes.
func TestThemeCheck(t *testing.T) {
	var out bytes.Buffer
	dir := writeThemeDir(t, map[string]string{
		"theme.yaml":                themeManifest,
		"templates/error.html.tmpl": `{{define "content"}}<p style="color: red">{{.Error.Code}}</p>{{end}}`,
		"translations/de.json":      `{"locale.de": "Deutsch"}`,
	})
	if err := themeCheck(dir, &out); !errors.Is(err, errFailed) {
		t.Fatalf("err = %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	for _, want := range []string{
		"page error: attribute style on <p>, which the CSP blocks: a style goes to static/theme.css",
		"catalog de: no text for choice.title",
	} {
		found := false
		for _, l := range lines {
			found = found || l == want
		}
		if !found {
			t.Errorf("no line %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := themeCheck(writeThemeDir(t, map[string]string{"theme.yaml": "name: demo\nversion: 1.0.0\napi: 2\n"}), &out); !errors.Is(err, errFailed) ||
		out.String() != "theme.yaml: api 2 is not supported; this binary supports api 1\n" {
		t.Errorf("api 2: %v, %q", err, out.String())
	}

	out.Reset()
	if err := themeCheck(writeThemeDir(t, map[string]string{"theme.yaml": themeManifest, "static/theme.css": "p {}"}), &out); err != nil || out.String() != "theme demo 1.0.0, api 1, locales en, fr: ok\n" {
		t.Errorf("a theme that passes: %v, %q", err, out.String())
	}
}

// Its exit codes: 1 when the theme fails, its lines on stdout and no fatal line;
// 0 when it passes.
func TestThemeCheckProcess(t *testing.T) {
	broken := writeThemeDir(t, map[string]string{"theme.yaml": themeManifest, "templates/selec.html.tmpl": ""})
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainProcess$")
	cmd.Env = append(os.Environ(), "HYDRA_DISPATCHER_TEST_MAIN=theme check "+broken)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(out), "templates/selec.html.tmpl: not a template of the pages") || strings.Contains(string(out), "fatal") {
		t.Errorf("broken: %v, %q", err, out)
	}
	cmd = exec.Command(os.Args[0], "-test.run=^TestMainProcess$")
	cmd.Env = append(os.Environ(), "HYDRA_DISPATCHER_TEST_MAIN=theme check "+writeThemeDir(t, map[string]string{"theme.yaml": themeManifest}))
	if out, err := cmd.Output(); err != nil || !strings.HasPrefix(string(out), "theme demo 1.0.0, api 1, locales en, fr: ok\n") {
		t.Errorf("passes: %v, %q", err, out)
	}
}
