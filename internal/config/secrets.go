package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// secretFile is a secret key, and the file that may give it instead (Q87): a local
// program of the same uid reads the environment of the dispatcher in /proc/1/environ,
// which an os.Unsetenv does not change.
type secretFile struct {
	path string // the key; its file's is path + "_file"
	file string // the file, "" for none
	// given tells that the key has a value too, which the file would replace.
	given bool
	// read gives the key the content of the file.
	read func(content string) error
	// secret tells that the value of the key is a secret: a DSN is one when it holds
	// a password.
	secret func() bool
}

// secretFiles are the secret keys and their files: the keys of secrets, previous ones
// included, the DSNs that may hold a password, and the private key of the admin API.
// hydra.system_secrets_file has its own format, one secret per line.
func (c *Config) secretFiles() []secretFile {
	s := &c.Secrets
	return []secretFile{
		keyFile("secrets.cookie_key", s.CookieKeyFile, &s.CookieKey),
		keysFile("secrets.cookie_keys_previous", s.CookieKeysPreviousFile, &s.CookieKeysPrevious),
		keyFile("secrets.encryption_key", s.EncryptionKeyFile, &s.EncryptionKey),
		keysFile("secrets.encryption_keys_previous", s.EncryptionKeysPreviousFile, &s.EncryptionKeysPrevious),
		keyFile("secrets.challenge_key", s.ChallengeKeyFile, &s.ChallengeKey),
		keysFile("secrets.challenge_keys_previous", s.ChallengeKeysPreviousFile, &s.ChallengeKeysPrevious),
		keyFile("secrets.webhook_signing_key", s.WebhookSigningKeyFile, &s.WebhookSigningKey),
		keyFile("secrets.audit_key", s.AuditKeyFile, &s.AuditKey),
		dsnFile("store.dsn", c.Store.DSNFile, &c.Store.DSN),
		dsnFile("state.redis_dsn", c.State.RedisDSNFile, &c.State.RedisDSN),
		textFile("admin.api.private_key", c.Admin.API.PrivateKeyFile, &c.Admin.API.PrivateKey),
	}
}

// readSecretFiles gives each secret key given by a file the content of its file. The
// errors never quote the content.
func (c *Config) readSecretFiles() error {
	var errs []error
	for _, f := range c.secretFiles() {
		if f.file == "" {
			continue
		}
		if f.given {
			errs = append(errs, fmt.Errorf("%s and %s_file are exclusive", f.path, f.path))
			continue
		}
		data, err := os.ReadFile(f.file)
		if err == nil {
			err = f.read(string(data))
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s_file: %w", f.path, err))
		}
	}
	return errors.Join(errs...)
}

// environmentSecrets names the secret keys with a value fromEnv says the environment
// gave.
func (c *Config) environmentSecrets(fromEnv func(path string) bool) []string {
	var names []string
	for _, f := range c.secretFiles() {
		if f.secret() && fromEnv(f.path) {
			names = append(names, f.path)
		}
	}
	if len(c.Hydra.SystemSecrets) > 0 && fromEnv("hydra.system_secrets") {
		names = append(names, "hydra.system_secrets")
	}
	return names
}

func keyFile(path, file string, k *Key) secretFile {
	return secretFile{path: path, file: file, given: *k != nil,
		read: func(content string) error {
			key, err := parseKey(content)
			switch {
			case err != nil:
				return err
			case key == nil:
				return errors.New("holds no key")
			}
			*k = key
			return nil
		},
		secret: func() bool { return *k != nil }}
}

// keysFile reads one key per line; an empty file is no previous key.
func keysFile(path, file string, ks *Keys) secretFile {
	return secretFile{path: path, file: file, given: len(*ks) > 0,
		read: func(content string) error {
			keys := Keys{}
			n := 0
			for line := range strings.Lines(content) {
				n++
				key, err := parseKey(line)
				if err != nil {
					return fmt.Errorf("line %d: %w", n, err)
				}
				if key != nil {
					keys = append(keys, key)
				}
			}
			*ks = keys
			return nil
		},
		secret: func() bool { return len(*ks) > 0 }}
}

// textFile reads a value, the spaces around it trimmed: a PEM key keeps its lines.
func textFile(path, file string, v *string) secretFile {
	return secretFile{path: path, file: file, given: *v != "",
		read: func(content string) error {
			if content = strings.TrimSpace(content); content == "" {
				return errors.New("is empty")
			}
			*v = content
			return nil
		},
		secret: func() bool { return *v != "" }}
}

// dsnFile is textFile for a DSN, a secret when it holds a password.
func dsnFile(path, file string, dsn *string) secretFile {
	f := textFile(path, file, dsn)
	f.secret = func() bool { return hasPassword(*dsn) }
	return f
}

// hasPassword tells whether a DSN holds a password: in its URL, or as the keyword of a
// Postgres connection string.
func hasPassword(dsn string) bool {
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if _, ok := u.User.Password(); ok {
			return true
		}
	}
	return strings.Contains(dsn, "password=")
}
