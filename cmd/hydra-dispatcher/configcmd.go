package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seedfile"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// exitError ends the program with code, after the fatal line of err: config
// diff keeps 1 for the differences, and exits 2 in error.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

var configCommands = []command{
	{"dump", "dump [-section apps,flows,settings,oauth2_clients]: the configuration of the database, in the format of the seed", configDump},
	{"diff", "diff [-format text|json]: what bootstrap -force would change, reading only; exit 0 for nothing, 1 for changes, 2 in error", configDiff},
}

// configCmd compares the configuration file with the database, or writes
// what the database holds.
func configCmd(ctx context.Context, args []string) error {
	return subcommand(ctx, "config", configCommands, args)
}

// configDiff prints what bootstrap -force would change: the changes alone on
// stdout, as bootstrap prints them, or in JSON. It reads only, and a role that
// may only read runs it (store.Diff). Exit 0 when nothing would be written, 1
// when something would, 2 in error: for a job of deployment or the CI.
func configDiff(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("config diff", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	format := formatFlag(fs)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if err := checkFormat(fs, *format); err != nil {
		return err
	}
	changes, err := diff(ctx, *configPath)
	if err != nil {
		return &exitError{2, err}
	}
	if *format == "json" {
		err = writeJSON(changesJSON(changes))
	} else {
		printChanges(out(), changes)
	}
	switch {
	case err != nil:
		return &exitError{2, err}
	case writes(changes):
		return errFailed
	}
	return nil
}

func diff(ctx context.Context, configPath string) ([]store.Change, error) {
	slog.SetDefault(startLogger(os.Stderr))
	cfg, _, err := loadConfig(configPath, os.Stderr)
	if err != nil {
		return nil, err
	}
	db, err := openConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	return db.Diff(ctx, cfg.Seed)
}

// changeJSON is a change of config diff -format json; old and new are the
// values themselves, absent for a secret.
type changeJSON struct {
	Kind   string       `json:"kind"`
	ID     string       `json:"id"`
	Action store.Action `json:"action"`
	By     string       `json:"by,omitempty"`
	Fields []fieldJSON  `json:"fields,omitempty"`
}

type fieldJSON struct {
	Name   string          `json:"name"`
	Old    json.RawMessage `json:"old,omitempty"`
	New    json.RawMessage `json:"new,omitempty"`
	Secret bool            `json:"secret,omitempty"`
}

func changesJSON(changes []store.Change) []changeJSON {
	all := []changeJSON{}
	for _, c := range changes {
		j := changeJSON{Kind: c.Kind, ID: c.ID, Action: c.Action, By: c.By}
		for _, f := range c.Fields {
			fj := fieldJSON{Name: f.Name, Secret: f.Secret}
			if !f.Secret {
				fj.Old, fj.New = json.RawMessage(f.Old), json.RawMessage(f.New)
			}
			j.Fields = append(j.Fields, fj)
		}
		all = append(all, j)
	}
	return all
}

// configDump writes the configuration of the database in the format of the
// seed, under dispatcher: the settings the database holds, not those at their
// default, which a seed would write as rows and a later default would no
// longer reach; the API clients without their secret, which the database does
// not hold, a comment saying so; no admin account. bootstrap -force of the
// dump, secrets given, changes nothing.
func configDump(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("config dump", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	section := fs.String("section", strings.Join(seedfile.Sections, ","), "the sections to write, separated by commas")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	want := map[string]bool{}
	for s := range strings.SplitSeq(*section, ",") {
		s = strings.TrimSpace(s)
		if !slices.Contains(seedfile.Sections, s) {
			fmt.Fprintf(fs.Output(), "-section %q: %s\n", s, strings.Join(seedfile.Sections, ", "))
			return errUsage
		}
		want[s] = true
	}
	slog.SetDefault(startLogger(os.Stderr))
	cfg, _, err := loadConfig(*configPath, os.Stderr)
	if err != nil {
		return err
	}
	db, err := openConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	snap, err := db.Snapshot(ctx)
	if err != nil {
		return err
	}
	return seedfile.Write(out(), snap, want, seedfile.Options{},
		"The configuration of the database, in the format of the seed (hydra-dispatcher config dump).",
		"Without the settings at their default, the secrets of the API clients, which the database does not hold, or the admin accounts.")
}
