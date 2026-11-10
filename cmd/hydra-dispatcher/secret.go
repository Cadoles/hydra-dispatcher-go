package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// secretInput is where a command reads a password or a client secret: never
// from an argument, which ps, /proc, the history of the shell and docker
// inspect show (Q113).
type secretInput struct {
	// what names the value: "password" or "secret", the prefix of the flags.
	what  string
	stdin bool
	file  string
}

// maxSecretInput bounds what the standard input or a file may hold.
const maxSecretInput = 64 << 10

// readTerminal reads a line from the terminal without echo; the tests
// replace it.
var readTerminal = func() (string, error) {
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	return string(b), err
}

func newSecretInput(fs *flag.FlagSet, what string) *secretInput {
	in := &secretInput{what: what}
	fs.BoolVar(&in.stdin, what+"-stdin", false, "read the "+what+" from the standard input: one line, its end removed")
	fs.StringVar(&in.file, what+"-file", "", "read the "+what+" from a file, the spaces around it trimmed")
	return in
}

// given tells whether a flag names where the value is.
func (in *secretInput) given() bool { return in.stdin || in.file != "" }

// check refuses the two flags together.
func (in *secretInput) check(fs *flag.FlagSet) error {
	if in.stdin && in.file != "" {
		fmt.Fprintf(fs.Output(), "-%s-stdin and -%s-file are exclusive\n", in.what, in.what)
		return errUsage
	}
	return nil
}

// read reads the value from the file or the standard input its flags name,
// else from the terminal without echo: twice when twice, for a new password.
// Without a flag or a terminal, it is a usage error.
func (in *secretInput) read(twice bool) (string, error) {
	switch {
	case in.file != "":
		data, err := readLimited(in.file)
		if err != nil {
			return "", fmt.Errorf("-%s-file: %w", in.what, err)
		}
		v := strings.TrimSpace(data)
		if v == "" {
			return "", fmt.Errorf("-%s-file: is empty", in.what)
		}
		return v, nil
	case in.stdin:
		data, err := io.ReadAll(io.LimitReader(stdin, maxSecretInput+1))
		if err != nil {
			return "", fmt.Errorf("-%s-stdin: %w", in.what, err)
		}
		if len(data) > maxSecretInput {
			return "", fmt.Errorf("-%s-stdin: more than %d bytes", in.what, maxSecretInput)
		}
		v := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		switch {
		case v == "":
			return "", fmt.Errorf("-%s-stdin: is empty", in.what)
		case strings.ContainsAny(v, "\r\n"):
			return "", fmt.Errorf("-%s-stdin: holds more than one line", in.what)
		}
		return v, nil
	case !stdinIsTerminal():
		// A usage error, exit 2: the command lacks a flag.
		fmt.Fprintf(os.Stderr, "no %s: give -%s-stdin or -%s-file out of a terminal\n", in.what, in.what, in.what)
		return "", errUsage
	}
	v, err := prompt(capitalize(in.what) + ": ")
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("the %s is empty", in.what)
	}
	if twice {
		again, err := prompt(capitalize(in.what) + " again: ")
		if err != nil {
			return "", err
		}
		if again != v {
			return "", fmt.Errorf("the two %ss differ", in.what)
		}
	}
	return v, nil
}

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	v, err := readTerminal()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read the terminal: %w", err)
	}
	return v, nil
}

func readLimited(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxSecretInput+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSecretInput {
		return "", errors.New("more than 64 KiB")
	}
	return string(data), nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
