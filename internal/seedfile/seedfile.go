// Package seedfile writes a configuration in the format of the seed of
// dispatcher.yaml (dispatcher:): config dump writes the database, and
// tools/symfonyimport the configuration of the Symfony dispatcher.
package seedfile

import (
	"fmt"
	"io"
	"slices"

	"gopkg.in/yaml.v3"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Sections are those of a seed, in their order.
var Sections = []string{"settings", "apps", "flows", "oauth2_clients"}

// Options change what Write writes.
type Options struct {
	// NoReceiveClaims leaves receive_claims out of the apps: the export of
	// Symfony, which has none. Without the key, bootstrap gives every claim to
	// a new app and keeps the list of one the Go database restricted, where
	// null would give it every claim back.
	NoReceiveClaims bool
}

// Write writes the sections want of snap under dispatcher:, after the lines
// of header, each a comment: the settings snap.StoredSettings names, each in
// the JSON of the registry, which YAML reads as it is; the apps, receive_claims
// null or [] kept apart; the flows and their steps; the API clients without
// their secret, which a database never holds, a comment saying so.
func Write(w io.Writer, snap *store.Snapshot, want map[string]bool, o Options, header ...string) error {
	doc, err := document(snap, want, o)
	if err != nil {
		return err
	}
	for _, line := range header {
		if _, err := fmt.Fprintln(w, "# "+line); err != nil {
			return err
		}
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return enc.Close()
}

type app struct {
	ID                    string    `yaml:"id"`
	LoginURL              string    `yaml:"login_url"`
	ConsentURL            string    `yaml:"consent_url"`
	LogoutURL             string    `yaml:"logout_url,omitempty"`
	Method                string    `yaml:"method"`
	AuthMode              string    `yaml:"auth_mode"`
	AllowedSources        []string  `yaml:"allowed_sources,omitempty"`
	ClientCertFingerprint string    `yaml:"client_cert_fingerprint,omitempty"`
	ReceiveClaims         *[]string `yaml:"receive_claims"` // null: every claim
}

type flow struct {
	ID          string            `yaml:"id"`
	Title       map[string]string `yaml:"title"`
	Description map[string]string `yaml:"description"`
	IconURL     map[string]string `yaml:"icon_url,omitempty"`
	Enabled     bool              `yaml:"enabled"`
	ACR         string            `yaml:"acr,omitempty"`
	Steps       []step            `yaml:"steps"`
}

type step struct {
	ID           string `yaml:"id"`
	Order        int    `yaml:"order"`
	SubjectCheck string `yaml:"subject_check"`
}

type client struct {
	ID     string   `yaml:"id"`
	Scopes []string `yaml:"scopes"`
}

// document is the YAML of the sections want of snap.
func document(snap *store.Snapshot, want map[string]bool, o Options) (*yaml.Node, error) {
	root := &yaml.Node{Kind: yaml.MappingNode}
	add := func(key string, v any) error {
		var n yaml.Node
		if node, ok := v.(*yaml.Node); ok {
			n = *node
		} else if err := n.Encode(v); err != nil {
			return err
		}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, &n)
		return nil
	}
	if want["settings"] {
		// Each value in the JSON of the registry, which YAML reads as it is.
		for _, s := range snap.Settings.Document() {
			if !slices.Contains(snap.StoredSettings, s.Key) {
				continue
			}
			var n yaml.Node
			if err := yaml.Unmarshal(s.Value, &n); err != nil {
				return nil, fmt.Errorf("setting %s: %w", s.Key, err)
			}
			if err := add(s.Key, n.Content[0]); err != nil {
				return nil, err
			}
		}
	}
	if want["apps"] {
		apps := []app{}
		for _, a := range snap.Apps {
			d := app{ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, LogoutURL: a.LogoutURL, Method: a.Method,
				AuthMode: a.AuthMode, ClientCertFingerprint: a.ClientCertFingerprint}
			for _, p := range a.AllowedSources {
				d.AllowedSources = append(d.AllowedSources, p.String())
			}
			if a.ReceiveClaims != nil {
				claims := slices.Clone(a.ReceiveClaims)
				d.ReceiveClaims = &claims
			}
			apps = append(apps, d)
		}
		if err := add("apps", apps); err != nil {
			return nil, err
		}
		if o.NoReceiveClaims {
			for _, a := range root.Content[len(root.Content)-1].Content {
				for i := 0; i+1 < len(a.Content); i += 2 {
					if a.Content[i].Value == "receive_claims" {
						a.Content = append(a.Content[:i], a.Content[i+2:]...)
						break
					}
				}
			}
		}
	}
	if want["flows"] {
		flows := []flow{}
		for _, f := range snap.Flows {
			d := flow{ID: f.ID, Title: f.Title, Description: f.Description, IconURL: f.IconURL, Enabled: f.Enabled, ACR: f.ACR}
			for _, s := range f.Steps {
				d.Steps = append(d.Steps, step{ID: s.AppID, Order: s.Position, SubjectCheck: s.SubjectCheck})
			}
			flows = append(flows, d)
		}
		if err := add("flows", flows); err != nil {
			return nil, err
		}
	}
	if want["oauth2_clients"] {
		clients := []client{}
		for _, c := range snap.APIClients {
			clients = append(clients, client{ID: c.ID, Scopes: c.Scopes})
		}
		if err := add("oauth2_clients", clients); err != nil {
			return nil, err
		}
		for _, c := range root.Content[len(root.Content)-1].Content {
			c.HeadComment = "secret: not dumped, the seed requires one"
		}
	}
	return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "dispatcher"}, root}}, nil
}
