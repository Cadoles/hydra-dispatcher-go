package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// configStore is what the commands need of the configuration store.
type configStore interface {
	store.Source
	Ping(ctx context.Context) error
	Close() error
	Migrate(ctx context.Context) ([]string, error)
	Bootstrap(ctx context.Context, seed config.Seed, mode store.Mode, write bool) ([]store.Change, error)
}

// openStore opens the configuration store at dsn. The tests replace it:
// they run without Postgres.
var openStore = func(ctx context.Context, dsn string) (configStore, error) {
	p, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return p, nil
}

const configHelp = "configuration file (default: $" + configEnv + ", else DISPATCHER_* variables only)"

// migrate applies the migrations the database lacks.
func migrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	cfg, logs, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	db, err := openStore(ctx, cfg.Store.DSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return runMigrations(ctx, db, logs.app)
}

func runMigrations(ctx context.Context, db configStore, logger *slog.Logger) error {
	applied, err := db.Migrate(ctx)
	for _, m := range applied {
		logger.InfoContext(ctx, "store.migrated", "migration", m)
	}
	if err == nil && len(applied) == 0 {
		logger.InfoContext(ctx, "store.up_to_date")
	}
	return err
}

// bootstrap writes the seed of the configuration file to the database.
func bootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	force := fs.Bool("force", false, "rewrite too what the database holds of the seed, and reset the settings it sets to ~")
	dryRun := fs.Bool("dry-run", false, "print the changes and write nothing")
	yes := fs.Bool("yes", false, "with -force in a terminal, write without asking")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	cfg, _, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	db, err := openStore(ctx, cfg.Store.DSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	mode := store.Missing
	if *force {
		mode = store.Force
	}

	// -force rewrites: in a terminal, the changes are shown and confirmed.
	ask := *force && !*yes && stdinIsTerminal()
	if *dryRun || ask {
		changes, err := db.Bootstrap(ctx, cfg.Seed, mode, false)
		if err != nil {
			return err
		}
		printChanges(os.Stdout, changes)
		if *dryRun || !writes(changes) {
			return nil
		}
		if !confirm(stdin, os.Stderr, "Write these changes?") {
			fmt.Fprintln(os.Stderr, "Nothing written.")
			return nil
		}
	}
	changes, err := db.Bootstrap(ctx, cfg.Seed, mode, true)
	if err != nil {
		return err
	}
	printChanges(os.Stdout, changes)
	return nil
}

// bootstrapMode is the store.Mode of serve.bootstrap, false for off.
func bootstrapMode(setting string) (store.Mode, bool) {
	switch setting {
	case config.BootstrapMissing:
		return store.Missing, true
	case config.BootstrapForce:
		return store.Force, true
	}
	return 0, false
}

// prepareStore applies serve.migrate and serve.bootstrap: out of a terminal,
// the changes are written without question, and logged.
func prepareStore(ctx context.Context, cfg *config.Config, db configStore, logger *slog.Logger) error {
	if cfg.Serve.Migrate {
		if err := runMigrations(ctx, db, logger); err != nil {
			return err
		}
	}
	mode, ok := bootstrapMode(cfg.Serve.Bootstrap)
	if !ok {
		return nil
	}
	changes, err := db.Bootstrap(ctx, cfg.Seed, mode, true)
	if err != nil {
		return err
	}
	counts := map[store.Action]int{}
	for _, c := range changes {
		counts[c.Action]++
		if c.Action == store.Same {
			continue
		}
		var fields []string
		for _, f := range c.Fields {
			fields = append(fields, f.Name)
		}
		logger.InfoContext(ctx, "bootstrap.change", "kind", c.Kind, "id", c.ID, "action", string(c.Action), "fields", fields)
	}
	logger.InfoContext(ctx, "bootstrap.done", "mode", cfg.Serve.Bootstrap, "summary", summary(counts))
	return nil
}

// writes tells whether changes write anything.
func writes(changes []store.Change) bool {
	for _, c := range changes {
		switch c.Action {
		case store.Create, store.Update, store.Reset:
			return true
		}
	}
	return false
}

// notes explain the actions that do not speak for themselves.
var notes = map[store.Action]string{
	store.Keep:   " (left as it is: -force rewrites it)",
	store.Reset:  " (back to its default)",
	store.Absent: " (in the database only: kept)",
}

// printChanges writes one line per change, then the fields of the updates and
// keeps, then a summary. Secrets show as changed, never their value.
func printChanges(w io.Writer, changes []store.Change) {
	counts := map[store.Action]int{}
	for _, c := range changes {
		counts[c.Action]++
		fmt.Fprintf(w, "%-7s %s %s%s\n", c.Action, c.Kind, c.ID, notes[c.Action])
		for _, f := range c.Fields {
			if f.Secret {
				fmt.Fprintf(w, "          %s: changed\n", f.Name)
				continue
			}
			fmt.Fprintf(w, "          %s: %s -> %s\n", f.Name, f.Old, f.New)
		}
	}
	fmt.Fprintln(w, summary(counts))
}

// summary counts the changes, in the order of a bootstrap's effects.
func summary(counts map[store.Action]int) string {
	var parts []string
	for _, a := range []store.Action{store.Create, store.Update, store.Reset, store.Keep, store.Same, store.Absent} {
		if counts[a] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", a, counts[a]))
		}
	}
	if len(parts) == 0 {
		return "empty seed, empty database"
	}
	return strings.Join(parts, ", ")
}

// stdin and stdinIsTerminal are where bootstrap -force asks; the tests
// replace them. A character device is not enough: /dev/null is one.
var (
	stdin           io.Reader = os.Stdin
	stdinIsTerminal           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
)

// confirm asks question on w and reads the answer from r: yes or y.
func confirm(r io.Reader, w io.Writer, question string) bool {
	fmt.Fprintf(w, "%s [y/N] ", question)
	answer, _ := bufio.NewReader(r).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true
	}
	return false
}
