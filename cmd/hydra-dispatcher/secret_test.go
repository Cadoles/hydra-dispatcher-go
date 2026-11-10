package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// terminalAnswers makes the terminal answer each of answers in turn, or read
// from input when not a terminal.
func terminalAnswers(t *testing.T, terminal bool, input string, answers ...string) {
	t.Helper()
	oldStdin, oldTerminal, oldRead := stdin, stdinIsTerminal, readTerminal
	stdin, stdinIsTerminal = strings.NewReader(input), func() bool { return terminal }
	readTerminal = func() (string, error) {
		if len(answers) == 0 {
			return "", errors.New("no more answers")
		}
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	t.Cleanup(func() { stdin, stdinIsTerminal, readTerminal = oldStdin, oldTerminal, oldRead })
}

// A password or a secret comes from a file, the standard input or the
// terminal, never from an argument (Q113).
func TestSecretInput(t *testing.T) {
	dir, n := t.TempDir(), 0
	file := func(content string) string {
		n++
		path := filepath.Join(dir, fmt.Sprintf("secret-%d", n))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, tt := range map[string]struct {
		args     []string
		terminal bool
		input    string
		answers  []string
		twice    bool
		want     string
		err      string
	}{
		"file":                  {args: []string{"-secret-file", file("  s3cret\n")}, want: "s3cret"},
		"file empty":            {args: []string{"-secret-file", file(" \n")}, err: "-secret-file: is empty"},
		"file missing":          {args: []string{"-secret-file", filepath.Join(dir, "none")}, err: "-secret-file: open"},
		"file too large":        {args: []string{"-secret-file", file(strings.Repeat("s", maxSecretInput+1))}, err: "more than 64 KiB"},
		"file of two lines":     {args: []string{"-secret-file", file("a\nb\n")}, err: "holds more than one line"},
		"stdin of spaces":       {args: []string{"-secret-stdin"}, input: "   \n", err: "-secret-stdin: is empty"},
		"stdin at the limit":    {args: []string{"-secret-stdin"}, input: strings.Repeat("s", maxSecretInput) + "\r\n", want: strings.Repeat("s", maxSecretInput)},
		"stdin over the limit":  {args: []string{"-secret-stdin"}, input: strings.Repeat("s", maxSecretInput+1) + "\n", err: "more than 65536 bytes"},
		"terminal of spaces":    {terminal: true, answers: []string{"  "}, err: "the secret is empty"},
		"stdin":                 {args: []string{"-secret-stdin"}, input: " s3cret \n", want: " s3cret "},
		"stdin CRLF":            {args: []string{"-secret-stdin"}, input: "s3cret\r\n", want: "s3cret"},
		"stdin without newline": {args: []string{"-secret-stdin"}, input: "s3cret", want: "s3cret"},
		"stdin empty":           {args: []string{"-secret-stdin"}, input: "\n", err: "-secret-stdin: is empty"},
		"stdin two lines":       {args: []string{"-secret-stdin"}, input: "a\nb\n", err: "more than one line"},
		"stdin too large":       {args: []string{"-secret-stdin"}, input: strings.Repeat("s", maxSecretInput+1), err: "more than 65536 bytes"},
		"stdin in a terminal":   {args: []string{"-secret-stdin"}, terminal: true, input: "s3cret\n", want: "s3cret"},
		"no terminal":           {err: "usage error"},
		"terminal":              {terminal: true, answers: []string{"s3cret"}, want: "s3cret"},
		"terminal empty":        {terminal: true, answers: []string{""}, err: "the secret is empty"},
		"terminal twice":        {terminal: true, twice: true, answers: []string{"s3cret", "s3cret"}, want: "s3cret"},
		"terminal mismatch":     {terminal: true, twice: true, answers: []string{"s3cret", "s3cre"}, err: "the two secrets differ"},
	} {
		t.Run(name, func(t *testing.T) {
			terminalAnswers(t, tt.terminal, tt.input, tt.answers...)
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			in := newSecretInput(fs, "secret")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			got, err := in.read(tt.twice)
			switch {
			case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
				t.Errorf("err = %v, want %q", err, tt.err)
			case tt.err == "" && (err != nil || got != tt.want):
				t.Errorf("read = %q, %v; want %q", got, err, tt.want)
			case err != nil && strings.Contains(err.Error(), "s3cret"):
				t.Errorf("the error holds the secret: %v", err)
			}
		})
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	in := newSecretInput(fs, "password")
	if err := fs.Parse([]string{"-password-stdin", "-password-file", "f"}); err != nil {
		t.Fatal(err)
	}
	if err := in.check(fs); !errors.Is(err, errUsage) || !in.given() {
		t.Errorf("both flags: %v", err)
	}
}
