package main

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// The walk of the exit of phase 3 (P25, Q133): an admin logs in to the
// screens of the dispatcher by the password of hydra-dev, creates an app (that
// of hydra-sql, under another id) and a flow of it by their forms; a user
// signs in by that flow; then the admin deletes the flow and the app.

const (
	journeyApp  = "e2e-journey-sql"
	journeyFlow = "e2e-journey"
)

// adminJourney plays the walk, removing first what a run stopped midway left.
func (d *driver) adminJourney() error {
	if err := d.adminLogin(); err != nil {
		return err
	}
	for _, path := range []string{"/admin/flows/" + journeyFlow, "/admin/apps/" + journeyApp} {
		if err := d.adminDelete(path, true); err != nil {
			return err
		}
	}
	values, err := d.appOf("hydra-sql")
	if err != nil {
		return err
	}
	values.Set("id", journeyApp)
	if err := d.adminCreate("/admin/apps", values, "/admin/apps/"+journeyApp+"?done=created"); err != nil {
		return fmt.Errorf("the app: %w", err)
	}
	flow := url.Values{"id": {journeyFlow}, "enabled": {"1"}, "acr": {""}, "locale": {"fr", "en"},
		"title": {"Parcours de sortie", "Exit journey"}, "description": {"Créé par l'e2e, supprimé après", ""}, "icon_url": {"", ""},
		"step_app": {journeyApp}, "step_position": {"1"}, "step_check": {"none"}, "step_claim": {""}}
	if err := d.adminCreate("/admin/flows", flow, "/admin/flows/"+journeyFlow+"?done=created"); err != nil {
		return fmt.Errorf("the flow: %w", err)
	}
	// The user, by the flow the admin made: hydra-sql's identity, under it.
	o, err := d.authorize(login{flow: journeyFlow, user: isabelle, consent: "accept"})
	if err != nil {
		return fmt.Errorf("the login by the new flow: %w", err)
	}
	if !o.saw("hydra-sql") {
		return fmt.Errorf("the login by the new flow: no form of hydra-sql: %v", o.seen)
	}
	if err := d.granted(o, identities["hydra-sql"]); err != nil {
		return fmt.Errorf("the login by the new flow: %w", err)
	}
	d.note("signed in by the flow %s, of the app %s, both made by the screens", journeyFlow, journeyApp)
	for _, path := range []string{"/admin/flows/" + journeyFlow, "/admin/apps/" + journeyApp} {
		if err := d.adminDelete(path, false); err != nil {
			return err
		}
	}
	return nil
}

// adminLogin logs in to the screens: the password from its file, never from
// the command line.
func (d *driver) adminLogin() error {
	data, err := os.ReadFile(d.adminFile)
	if err != nil {
		return fmt.Errorf("the password of the screens (-admin-password-file): %w", err)
	}
	p, err := d.b.get(d.dispatcher.JoinPath("/admin/login").String())
	if err != nil {
		return err
	}
	f, ok := p.find("password")
	if !ok {
		return fmt.Errorf("no login form: %w", errUnexpected(p))
	}
	v, err := f.values(map[string]string{"username": d.adminUser, "password": strings.TrimSpace(string(data))}, nil)
	if err != nil {
		return err
	}
	p, err = d.b.submit(p, f, v)
	if err != nil {
		return err
	}
	if p.Status != http.StatusOK || p.URL.Path != "/admin" || !strings.Contains(p.Body, "Log out") {
		return fmt.Errorf("the login to the screens: %d %s", p.Status, p.URL.Redacted())
	}
	return nil
}

var (
	inputValue = regexp.MustCompile(`<input[^>]*\bname="([a-z_]+)"[^>]*\bvalue="([^"]*)"`)
	textarea   = regexp.MustCompile(`(?s)<textarea[^>]*\bname="([a-z_]+)"[^>]*>(.*?)</textarea>`)
)

// appOf reads the form of the app id as its page shows it.
func (d *driver) appOf(id string) (url.Values, error) {
	p, err := d.b.get(d.dispatcher.JoinPath("/admin/apps/" + id).String())
	if err != nil {
		return nil, err
	}
	if p.Status != http.StatusOK {
		return nil, fmt.Errorf("the app %s: %d", id, p.Status)
	}
	v := url.Values{"auth_mode": {"network"}, "receive_all_claims": {"1"}}
	for _, m := range inputValue.FindAllStringSubmatch(p.Body, -1) {
		switch m[1] {
		case "method", "login_url", "consent_url", "logout_url":
			v.Set(m[1], html.UnescapeString(m[2]))
		}
	}
	for _, m := range textarea.FindAllStringSubmatch(p.Body, -1) {
		if m[1] == "allowed_sources" {
			v.Set(m[1], html.UnescapeString(strings.TrimSpace(m[2])))
		}
	}
	if v.Get("login_url") == "" || v.Get("allowed_sources") == "" {
		return nil, fmt.Errorf("the app %s: its form not read", id)
	}
	return v, nil
}

// formAt is the form of p whose action is path: the navigation of the screens
// has its own, the logout's.
func formAt(p page, path string) (form, bool) {
	for _, f := range parseForms(p.URL, p.Body) {
		if f.Action.Path == path {
			return f, true
		}
	}
	return form{}, false
}

// adminCreate posts values to the form of creation at path, its token that
// of its page, and wants the redirection to done.
func (d *driver) adminCreate(path string, values url.Values, done string) error {
	p, err := d.b.get(d.dispatcher.JoinPath(path + "/_new").String())
	if err != nil {
		return err
	}
	f, ok := formAt(p, path)
	if !ok {
		return fmt.Errorf("no form of %s: %w", path, errUnexpected(p))
	}
	csrf, _ := f.values(nil, nil)
	values.Set("csrf", csrf.Get("csrf"))
	p, err = d.b.submit(p, f, values)
	if err != nil {
		return err
	}
	if p.Status != http.StatusOK || p.URL.RequestURI() != done {
		return fmt.Errorf("created on %d %s, want %s: %w", p.Status, p.URL.RequestURI(), done, errUnexpected(p))
	}
	return nil
}

// adminDelete deletes the entity of the page at path by its confirmation; an
// entity absent is no error when absent is.
func (d *driver) adminDelete(path string, absent bool) error {
	p, err := d.b.get(d.dispatcher.JoinPath(path + "/delete").String())
	if err != nil {
		return err
	}
	if p.Status == http.StatusNotFound && absent {
		return nil
	}
	f, ok := formAt(p, path+"/delete")
	if p.Status != http.StatusOK || !ok {
		return fmt.Errorf("the deletion of %s: %d", path, p.Status)
	}
	v, err := f.values(nil, nil)
	if err != nil {
		return err
	}
	p, err = d.b.submit(p, f, v)
	if err != nil {
		return err
	}
	if p.Status != http.StatusOK || !strings.HasSuffix(p.URL.RequestURI(), "?done=deleted") {
		return fmt.Errorf("the deletion of %s: %d %s", path, p.Status, p.URL.RequestURI())
	}
	return nil
}
