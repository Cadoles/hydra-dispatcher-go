// Command dispatcher is the single login app Ory Hydra talks to. It chains
// several real login apps into a flow (MFA, identity provider choice) by
// replaying Hydra's login/consent protocol towards each of them. Go rewrite of
// the Symfony hydra-dispatcher.
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
	"syscall"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// version is injected at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// errUsage reports a command line error; usage has already been printed.
var errUsage = errors.New("usage error")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = []command{
	{"serve", "run the HTTP server", serve},
	{"healthcheck", "probe /health of a local server (container HEALTHCHECK)", healthcheck},
	{"version", "print the version", printVersion},
}

func main() {
	// The lines written before serve reads the configuration (its warnings,
	// a fatal error) and those of the other commands keep the format of the
	// design document, at the default level.
	slog.SetDefault(slog.New(newLogHandler(os.Stdout, "json", slog.LevelInfo)).With("log_type", "app"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, a second one kills at once.
	context.AfterFunc(ctx, stop)
	err := run(ctx, os.Args[1:], os.Stderr)
	stop()
	switch {
	case errors.Is(err, errUsage):
		os.Exit(2)
	case err != nil:
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
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
	fmt.Fprintln(w, "Usage: dispatcher <command> [flags]")
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
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return true, nil
	case err != nil:
		return false, errUsage
	case fs.NArg() > 0:
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return false, errUsage
	}
	return false, nil
}

// healthcheck lets a distroless image (no shell, no curl) run a HEALTHCHECK.
// It probes the server.listen serve uses: that of the DISPATCHER_CONFIG file
// and the variables, read as serve reads them, else DISPATCHER_SERVER_LISTEN
// or the default. A file given to serve by -config alone needs -url.
func healthcheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "", "health endpoint to probe (default: that of the server.listen serve uses)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if *url == "" {
		listen := os.Getenv("DISPATCHER_SERVER_LISTEN")
		if path := os.Getenv(configEnv); path != "" {
			cfg, _, err := config.Load(path, os.Environ())
			if err != nil {
				return fmt.Errorf("configuration: %w", err)
			}
			listen = cfg.Server.Listen
		}
		*url = healthURL(listen)
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
