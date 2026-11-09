package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/front"
)

// theme is theme check <dir>: the check of serve on a theme directory, without
// a configuration nor a database, for its author and its CI (Thèmes).
func theme(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("theme check", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: hydra-dispatcher theme check <dir>")
		fmt.Fprintln(fs.Output(), "Renders each page of the theme in each locale, as serve does at its start;")
		fmt.Fprintln(fs.Output(), "prints one line by problem and exits 1, or one line and exits 0.")
	}
	if len(args) == 0 || args[0] != "check" {
		fs.Usage()
		return errUsage
	}
	switch err := fs.Parse(args[1:]); {
	case errors.Is(err, flag.ErrHelp):
		return nil
	case err != nil:
		return errUsage
	case fs.NArg() != 1 || fs.Arg(0) == "":
		fs.Usage()
		return errUsage
	}
	return themeCheck(fs.Arg(0), os.Stdout)
}

// themeCheck loads and checks the theme of dir, and writes to w its problems,
// or what it is.
func themeCheck(dir string, w io.Writer) error {
	th, err := front.LoadTheme(dir)
	if err == nil {
		err = front.Check(th)
	}
	if err != nil {
		for line := range strings.Lines(err.Error()) {
			fmt.Fprintln(w, strings.TrimSuffix(line, "\n"))
		}
		return errFailed
	}
	fmt.Fprintf(w, "theme %s %s, api %d, locales %s: ok\n", th.Manifest.Name, th.Manifest.Version, th.Manifest.API, strings.Join(th.Locales(), ", "))
	return nil
}
