package adminui

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The accounts of the admin UI by their screen: every role reads them, the
// role admin writes them. A creation, which gives a role, a change of role
// and a deletion are sensitive: they ask for the password again past
// admin.session.reauth_window. No account deletes itself, and the last of
// the role admin keeps it (store.ErrLastAdmin). Its own password, every
// account changes it on /admin/account.

// accountFields are the fields of the forms of an account.
var accountFields = []string{"username", "role", "password", "oidc_sub"}

type accountRow struct {
	store.AdminUser
	You bool
}

type accountsPage struct{ Accounts []accountRow }

type accountPage struct {
	Account accountRow
	// Username, Role and OIDCSub are those of the form of a new account.
	Username, Role, OIDCSub string
	Errors                  fieldErrors
	New                     bool
}

func (ui *UI) registerAccounts() {
	ui.mux.Handle("GET /admin/accounts", ui.authed(anyRole, ui.accounts))
	ui.mux.Handle("GET /admin/accounts/{name}", ui.authed(anyRole, ui.accountView))
	ui.mux.Handle("GET /admin/account", ui.authed(anyRole, ui.ownAccount))
	ui.mux.Handle("GET /admin/account/password", ui.authed(anyRole, ui.fresh(ui.passwordForm)))
	ui.mux.Handle("POST /admin/account/password", ui.authed(anyRole, ui.fresh(ui.changePassword)))
	// Any name is that of an account, but no path of the accounts: the
	// creation is beside them.
	ui.mux.Handle("GET /admin/new-account", ui.authed(adminRole, ui.fresh(ui.newAccount)))
	ui.mux.Handle("POST /admin/accounts", ui.authed(adminRole, ui.fresh(ui.createAccount)))
	ui.mux.Handle("POST /admin/accounts/{name}/role", ui.authed(adminRole, ui.fresh(ui.changeRole)))
	ui.mux.Handle("GET /admin/accounts/{name}/delete", ui.authed(adminRole, ui.fresh(ui.deleteAccountForm)))
	ui.mux.Handle("POST /admin/accounts/{name}/delete", ui.authed(adminRole, ui.fresh(ui.deleteAccount)))
}

func (ui *UI) accountPath(name string) string { return ui.base + "/accounts/" + url.PathEscape(name) }

// unreadable answers a store of the accounts that does not answer.
func (ui *UI) unreadable(w http.ResponseWriter, r *http.Request, s *current, err error) {
	if ui.o.Logger != nil {
		ui.o.Logger.ErrorContext(r.Context(), "admin.accounts_unreadable", "cause", err.Error())
	}
	ui.status(w, r, http.StatusServiceUnavailable, "Unavailable", "The admin accounts cannot be read now: try again in a moment.", s)
}

func (ui *UI) accounts(w http.ResponseWriter, r *http.Request, s *current) {
	users, err := ui.o.Accounts.Admins(r.Context())
	if err != nil {
		ui.unreadable(w, r, s, err)
		return
	}
	p := accountsPage{}
	for _, u := range users {
		p.Accounts = append(p.Accounts, accountRow{AdminUser: u, You: u.Username == s.account.Username})
	}
	ui.show(w, r, s, http.StatusOK, "accounts", "Accounts", "accounts", p)
}

// accountOf reads the account of the path, or answers why it cannot.
func (ui *UI) accountOf(w http.ResponseWriter, r *http.Request, s *current) (store.AdminUser, bool) {
	u, found, err := ui.o.Accounts.Admin(r.Context(), r.PathValue("name"))
	switch {
	case err != nil:
		ui.unreadable(w, r, s, err)
	case !found:
		ui.status(w, r, http.StatusNotFound, "Not found", "No account has this name.", s)
	}
	return u, err == nil && found
}

func (ui *UI) accountView(w http.ResponseWriter, r *http.Request, s *current) {
	u, ok := ui.accountOf(w, r, s)
	if !ok {
		return
	}
	ui.show(w, r, s, http.StatusOK, "account", "Account "+u.Username, "accounts", accountPage{Account: accountRow{AdminUser: u, You: u.Username == s.account.Username}})
}

func (ui *UI) newAccount(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "account_new", "New account", "accounts", accountPage{New: true})
}

// readPassword reads a new password and its confirmation: its hash, or what
// refuses it.
func readPassword(r *http.Request, errs fieldErrors) string {
	password, again := r.PostFormValue("password"), r.PostFormValue("password_again")
	if password == "" {
		return ""
	}
	if v := domain.Collect(func(fail domain.Fail) { domain.CheckPassword(fail, password) }); v != nil {
		for _, x := range v {
			errs["password"] = append(errs["password"], x.Message)
		}
		return ""
	}
	if password != again {
		errs["password"] = append(errs["password"], "and its confirmation differ")
		return ""
	}
	hash, err := domain.HashSecret(password)
	if err != nil {
		errs["password"] = append(errs["password"], "could not be hashed")
		return ""
	}
	return hash
}

func (ui *UI) createAccount(w http.ResponseWriter, r *http.Request, s *current) {
	p := accountPage{New: true, Username: r.PostFormValue("username"), Role: r.PostFormValue("role"), OIDCSub: strings.TrimSpace(r.PostFormValue("oidc_sub"))}
	again := func(status int, errs fieldErrors) {
		p.Errors = errs
		ui.show(w, r, s, status, "account_new", "New account", "accounts", p)
	}
	errs := fieldErrors{}
	hash := readPassword(r, errs)
	if hash == "" && p.OIDCSub == "" && len(errs) == 0 {
		errs["password"] = append(errs["password"], "is required for an account without an OIDC subject: it could not log in")
	}
	if p.Role == "" {
		errs["role"] = append(errs["role"], "is required")
	}
	if len(errs) > 0 {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	u := store.AdminUser{Username: p.Username, PasswordHash: hash, OIDCSub: p.OIDCSub, Role: p.Role}
	if err := ui.o.Accounts.CreateAdmin(r.Context(), u); err != nil {
		ui.failed(w, r, s, err, accountFields, again)
		return
	}
	fields := []string{"role"}
	if hash != "" {
		fields = append(fields, "password")
	}
	if u.OIDCSub != "" {
		fields = append(fields, "oidc_sub")
	}
	ui.wrote(r.Context(), s, "admin-users", u.Username, "create", fields)
	http.Redirect(w, r, ui.accountPath(u.Username)+"?done=created", http.StatusSeeOther)
}

func (ui *UI) changeRole(w http.ResponseWriter, r *http.Request, s *current) {
	u, ok := ui.accountOf(w, r, s)
	if !ok {
		return
	}
	role := r.PostFormValue("role")
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "account", "Account "+u.Username, "accounts", accountPage{Account: accountRow{AdminUser: u, You: u.Username == s.account.Username}, Errors: errs})
	}
	if role == u.Role {
		http.Redirect(w, r, ui.accountPath(u.Username)+"?done=saved", http.StatusSeeOther)
		return
	}
	err := ui.o.Accounts.UpdateAdmin(r.Context(), u.Username, func(a *store.AdminUser) error {
		a.Role = role
		return nil
	})
	if err != nil {
		ui.failed(w, r, s, err, accountFields, again)
		return
	}
	ui.wrote(r.Context(), s, "admin-users", u.Username, "update", []string{"role"})
	// A role changed ends the sessions of the account (Q120): its own, when
	// it changes it, among them.
	http.Redirect(w, r, ui.accountPath(u.Username)+"?done=saved", http.StatusSeeOther)
}

func (ui *UI) deleteAccountForm(w http.ResponseWriter, r *http.Request, s *current) {
	u, ok := ui.accountOf(w, r, s)
	if !ok {
		return
	}
	ui.show(w, r, s, http.StatusOK, "confirm", "Delete the account "+u.Username+"?", "accounts", ui.accountConfirm(u.Username, s, nil))
}

func (ui *UI) accountConfirm(name string, s *current, errs fieldErrors) confirmPage {
	p := confirmPage{Title: "Delete the account " + name + "?", Action: ui.accountPath(name) + "/delete", Button: "Delete the account",
		Message: "Its sessions end at once. Its deletion cannot be undone.", Back: ui.accountPath(name), Errors: errs}
	if name == s.account.Username {
		p.Action, p.Message = "", "This is your own account: another admin deletes it."
	}
	return p
}

func (ui *UI) deleteAccount(w http.ResponseWriter, r *http.Request, s *current) {
	name := r.PathValue("name")
	again := func(status int, errs fieldErrors) {
		p := ui.accountConfirm(name, s, errs)
		ui.show(w, r, s, status, "confirm", p.Title, "accounts", p)
	}
	if name == s.account.Username {
		again(http.StatusConflict, fieldErrors{"": {"No account deletes itself."}})
		return
	}
	if err := ui.o.Accounts.DeleteAdmin(r.Context(), name); err != nil {
		ui.failed(w, r, s, err, nil, again)
		return
	}
	ui.wrote(r.Context(), s, "admin-users", name, "delete", nil)
	http.Redirect(w, r, ui.base+"/accounts?done=deleted", http.StatusSeeOther)
}

func (ui *UI) ownAccount(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "account", "Your account", "account", accountPage{Account: accountRow{AdminUser: s.account, You: true}})
}

func (ui *UI) passwordForm(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "password", "Your password", "account", accountPage{Account: accountRow{AdminUser: s.account, You: true}})
}

// changePassword writes the password of the account of the session. The
// change ends its sessions (Q120): this one takes a new one, the others,
// in other browsers, end.
func (ui *UI) changePassword(w http.ResponseWriter, r *http.Request, s *current) {
	errs := fieldErrors{}
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "password", "Your password", "account", accountPage{Account: accountRow{AdminUser: s.account, You: true}, Errors: errs})
	}
	hash := readPassword(r, errs)
	if hash == "" && len(errs) == 0 {
		errs["password"] = append(errs["password"], "is required")
	}
	if len(errs) > 0 {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	name := s.account.Username
	err := ui.o.Accounts.UpdateAdmin(r.Context(), name, func(a *store.AdminUser) error {
		a.PasswordHash = hash
		return nil
	})
	if err != nil {
		ui.failed(w, r, s, err, accountFields, again)
		return
	}
	ui.wrote(r.Context(), s, "admin-users", name, "update", []string{"password"})
	// The new session opens after the end the change wrote, whatever the
	// clocks: it is read back.
	issued := ui.o.Now()
	if u, found, err := ui.o.Accounts.Admin(r.Context(), name); err == nil && found && !issued.After(u.SessionsValidAfter) {
		issued = u.SessionsValidAfter.Add(time.Microsecond)
	}
	next := ui.newSession(name, s.session.Method)
	next.Issued, next.Seen, next.Auth = issued.UnixMicro(), issued.UnixMicro(), issued.UnixMicro()
	ui.setSession(w, next)
	http.Redirect(w, r, ui.base+"/account?done=saved", http.StatusSeeOther)
}
