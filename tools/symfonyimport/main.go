// Command symfonyimport takes the configuration of the Symfony dispatcher
// over, once, at the switchover (Q116):
//
//	symfonyimport export -url <Symfony> -client-id <id> -client-secret-file <f> > seed.yaml
//	symfonyimport accounts -symfony-dsn-file <f> -config dispatcher.yaml [-dry-run]
//
// export reads the apps, the flows and the settings of Symfony's /admin/v1
// and writes them as a seed, which bootstrap imports; accounts copies the
// admin accounts and the API clients from Symfony's database into the Go one.
// It is not in the image: it runs once, from a host that reaches both.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// errUsage is a usage error: exit 2, the usage printed.
var errUsage = errors.New("usage error")

type command struct {
	name, summary string
	run           func(ctx context.Context, args []string, stdout, stderr io.Writer, stdin io.Reader) error
}

var commands = []command{
	{"export", "write the apps, flows and settings of Symfony's admin API as a seed, on the standard output", export},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Stdin)
	stop()
	switch {
	case errors.Is(err, errUsage):
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "symfonyimport:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, stdin io.Reader) error {
	if len(args) > 0 {
		for _, c := range commands {
			if c.name == args[0] {
				return c.run(ctx, args[1:], stdout, stderr, stdin)
			}
		}
	}
	fmt.Fprintln(stderr, "Usage: symfonyimport <command> [flags]\n\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(stderr, "  %-9s %s\n", c.name, c.summary)
	}
	return errUsage
}

// parse parses the flags of a command, which takes no argument.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		return errUsage
	}
	return nil
}

// readSecret reads a secret from a file, the spaces around it trimmed, or
// from stdin, one line: never from an argument (Q113).
func readSecret(what, file string, fromStdin bool, stdin io.Reader) (string, error) {
	var data []byte
	var err error
	switch {
	case file != "" && fromStdin:
		return "", fmt.Errorf("%s: a file or the standard input, not both", what)
	case file != "":
		data, err = os.ReadFile(file)
	case fromStdin:
		data, err = io.ReadAll(io.LimitReader(stdin, 64<<10))
	default:
		return "", fmt.Errorf("%s: give its file, or read it from the standard input", what)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" || strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("%s: one line, not empty", what)
	}
	return v, nil
}
