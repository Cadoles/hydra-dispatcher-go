// Command hydra-dispatcher is the single login app Ory Hydra talks to. It
// chains several real login apps into a flow (MFA, identity provider choice)
// by replaying Hydra's login/consent protocol towards each of them. Go rewrite
// of the Symfony dispatcher.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/config"
)

// version is injected at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// errUsage reports a command line error; usage has already been printed.
var errUsage = errors.New("usage error")

// errFailed reports a check that failed, its problems already printed: exit 1,
// without a fatal line.
var errFailed = errors.New("check failed")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = []command{
	{"serve", "run the HTTP server", serve},
	{"migrate", "apply the database migrations; migrate down rolls back the last one", migrate},
	{"bootstrap", "write the seed of the configuration file to the database", bootstrap},
	{"client", "client create|update|delete|list: the API clients of the admin API", client},
	{"admin", "admin create|update|list: the accounts of the admin UI", adminAccounts},
	{"config", "config dump|diff: the configuration of the database, against the file", configCmd},
	{"secrets", "secrets status|rekey: the settings the database holds encrypted, and their key", secretsCmd},
	{"healthcheck", "probe /health of a local server (container HEALTHCHECK)", healthcheck},
	{"theme", "theme check <dir>: render the pages of a theme as serve does, one line by problem", theme},
	{"version", "print the version", printVersion},
}

func main() {
	slog.SetDefault(startLogger(os.Stdout))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second one kills at once.
	context.AfterFunc(ctx, stop)
	err := run(ctx, os.Args[1:], os.Stderr)
	stop()
	var exit *exitError
	switch {
	case errors.Is(err, errUsage):
		os.Exit(2)
	case errors.Is(err, errFailed):
		os.Exit(1)
	case errors.As(err, &exit):
		slog.Error("fatal", "err", exit.err)
		os.Exit(exit.code)
	case err != nil:
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// startLogger writes to w the lines written before serve reads the
// configuration (its warnings, a fatal error) and those of the other
// commands: the format of the design document, at the default level.
func startLogger(w io.Writer) *slog.Logger {
	return slog.New(newLogHandler(w, "json", slog.LevelInfo)).With("log_type", "app")
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usage(stderr)
		return nil
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:])
		}
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return errUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: hydra-dispatcher <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
}

// parseFlags parses a subcommand's flags; -h prints its help and is not an
// error. No subcommand takes an argument: one is refused rather than ignored
// (serve dispatcher.yaml would run without its file).
func parseFlags(fs *flag.FlagSet, args []string) (help bool, err error) {
	if err := boolValues(fs, args); err != nil {
		return false, err
	}
	switch err := parseQuiet(fs, args); {
	case errors.Is(err, flag.ErrHelp):
		return true, nil
	case err != nil:
		return false, errUsage
	case fs.NArg() > 0:
		// Not quoted: a password given as Symfony's commands took it
		// (admin create alice S3cret!) would land in the logs (revue R37).
		fmt.Fprintln(fs.Output(), "an argument too many, not printed: values go in flags, and a password or a secret never in an argument")
		fs.Usage()
		return false, errUsage
	}
	return false, nil
}

// parseQuiet parses args into fs without letting the flag package write what
// it refuses: an unknown flag may be a password that starts with a dash
// (admin create alice -S3cret), which it quoted (revue R39). A flag that
// lacks its value is named: the command defines it. -h shows the usage.
func parseQuiet(fs *flag.FlagSet, args []string) error {
	out := fs.Output()
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	fs.SetOutput(out)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, flag.ErrHelp):
	case strings.HasPrefix(err.Error(), "flag needs an argument: "):
		fmt.Fprintln(out, err)
	default:
		fmt.Fprintln(out, "a flag or its value refused, not printed: a password or a secret never goes in an argument")
	}
	fs.Usage()
	return err
}

// boolValues refuses a value given to a boolean flag, as -password=S3cret!:
// the flag package would quote it in its error (revue R37).
func boolValues(fs *flag.FlagSet, args []string) error {
	for _, a := range args {
		if a == "--" {
			return nil
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || !hasValue {
			continue
		}
		if f := fs.Lookup(name); f != nil {
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
				fmt.Fprintf(fs.Output(), "-%s takes no value, and the one given is not printed\n", name)
				return errUsage
			}
		}
	}
	return nil
}

// healthcheck lets a distroless image (no shell, no curl) run a HEALTHCHECK.
// It probes the server.listen serve uses, as probeURL finds it. A file given
// to serve by -config alone needs -url, which serve warns of.
func healthcheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "", "health endpoint to probe (default: that of the server.listen serve uses)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if *url == "" {
		probe, err := probeURL()
		if err != nil {
			return err
		}
		*url = probe
	}

	// Under the 3 s of the image's HEALTHCHECK, so the error is printed
	// before Docker kills the probe.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	// No proxy: HTTP_PROXY would apply to a listen off the loopback.
	client := &http.Client{Transport: &http.Transport{}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: status %d", resp.StatusCode)
	}
	return nil
}

// probeURL is the /health URL healthcheck probes without -url: that of the
// server.listen of the DISPATCHER_CONFIG file and the variables, read as
// serve reads them, else of DISPATCHER_SERVER_LISTEN or the default.
func probeURL() (string, error) {
	listen := os.Getenv("DISPATCHER_SERVER_LISTEN")
	if path := os.Getenv(configEnv); path != "" {
		cfg, _, err := config.Load(path, os.Environ())
		if err != nil {
			return "", fmt.Errorf("configuration: %w", err)
		}
		listen = cfg.Server.Listen
	}
	return healthURL(listen), nil
}

// healthURL is the /health URL of a server listening on listen: an empty or
// unspecified host is reached on 127.0.0.1. For "::" too: Go listens on both
// stacks there, and a container may have no IPv6 loopback.
func healthURL(listen string) string {
	if listen == "" {
		listen = config.DefaultListen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen + "/health" // serve refuses it too
	}
	if ip, err := netip.ParseAddr(host); host == "" || err == nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/health"
}

func printVersion(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	fmt.Println(version)
	return nil
}
