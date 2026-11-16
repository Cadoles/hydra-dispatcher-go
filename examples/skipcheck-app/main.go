// Command skipcheck-app runs the reference app of the pre-check of a step
// (package app): a second factor that remembers a device. Its login_url is
// <origin>/login, its consent_url <origin>/consent, its skip_check_url
// <origin>/skip-check.
//
//	SKIPCHECK_APP_KEY=<the app's skip_check_key> go run ./examples/skipcheck-app \
//	  -listen :8090 -admin-url http://dispatcher:8080 -code 123456
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/examples/skipcheck-app/app"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "skipcheck-app:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("skipcheck-app", flag.ContinueOnError)
	listen := fs.String("listen", ":8090", "address to listen on")
	adminURL := fs.String("admin-url", "", "the dispatcher's emulated API, as Hydra's admin URL")
	code := fs.String("code", "", "the code the step asks")
	rememberFor := fs.Duration("remember-for", 30*24*time.Hour, "how long a device stays trusted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The key from the environment, never an argument: a process list shows
	// those.
	key, err := domain.ParseKey(os.Getenv("SKIPCHECK_APP_KEY"))
	switch {
	case err != nil:
		return fmt.Errorf("SKIPCHECK_APP_KEY: %w", err)
	case key == nil:
		return errors.New("SKIPCHECK_APP_KEY is required: the app's skip_check_key")
	case *adminURL == "" || *code == "":
		return errors.New("-admin-url and -code are required")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	h, err := app.New(app.Options{AdminURL: *adminURL, Key: key, Code: *code, RememberFor: *rememberFor, Log: log})
	if err != nil {
		return err
	}
	log.Info("listening", "address", *listen)
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}
