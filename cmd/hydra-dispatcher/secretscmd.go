package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

var secretsCommands = []command{
	{"status", "status: the settings the database holds encrypted, and the key of each; exit 1 when a key is not held", secretsStatus},
	{"rekey", "rekey: encrypt again by secrets.encryption_key what a previous key encrypted", secretsRekey},
}

// secretsCmd tells and turns the keys of the settings the database holds
// encrypted (Rotation des clés).
func secretsCmd(ctx context.Context, args []string) error {
	return subcommand(ctx, "secrets", secretsCommands, args)
}

// secretsStatus prints each encrypted setting, the kid of its key and whether
// that key is the active one, a previous one, or not held: a key is removed
// from the configuration once no setting is under it.
func secretsStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("secrets status", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	keys, err := encryptionKeys(c.cfg)
	if err != nil {
		return err
	}
	settings, err := c.db.EncryptedSettings(ctx)
	if err != nil {
		return err
	}
	if len(settings) == 0 {
		fmt.Fprintln(out(), "No setting is encrypted.")
		return nil
	}
	missing := false
	for _, s := range settings {
		state := "previous"
		switch {
		case s.KID == keys.Active():
			state = "active"
		case !keys.Holds(s.KID):
			state, missing = "not held", true
		}
		fmt.Fprintf(out(), "%s\t%s\t%s\n", s.Key, s.KID, state)
	}
	if missing {
		fmt.Fprintln(os.Stderr, "A setting is under a key neither secrets.encryption_key nor secrets.encryption_keys_previous holds.")
		return errFailed
	}
	return nil
}

// secretsRekey encrypts again by the active key what is under another, in one
// write; the audit names the settings, never their values.
func secretsRekey(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("secrets rekey", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	keys, err := encryptionKeys(c.cfg)
	if err != nil {
		return err
	}
	done, err := c.db.Rekey(ctx)
	if err != nil {
		return err
	}
	if len(done) == 0 {
		fmt.Fprintf(os.Stderr, "Every encrypted setting is under the key %s: nothing to do.\n", keys.Active())
		return nil
	}
	c.audit.CLIWrote(ctx, "settings", "", "secrets rekey", done)
	for _, k := range done {
		fmt.Fprintf(os.Stderr, "%s encrypted again by the key %s.\n", k, keys.Active())
	}
	return nil
}
