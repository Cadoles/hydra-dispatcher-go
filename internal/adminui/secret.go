package adminui

import (
	"encoding/json"
	"net/http"
	"time"
)

// A secret just made, of an API client or of a Hydra client, created or
// turned, is not rendered by the POST that made it: a reload would make it
// again, a second client of Hydra or another secret (revue R43). The POST
// seals it in a cookie of a minute and sends the browser to /admin/secret,
// which shows it once, to the account that made it, and forgets it.

// secretCookie carries the secret to its page.
const secretCookie = "dispatcher_admin_secret"

// secretWait is how long the secret waits for its page.
const secretWait = time.Minute

// handedSecret is what the cookie carries: the page, for whom, since when.
type handedSecret struct {
	User string     `json:"u"`
	At   int64      `json:"at"`
	Nav  string     `json:"nav"`
	Page secretPage `json:"page"`
}

// handOver sends the browser to the page of the secret of p, by a 303.
func (ui *UI) handOver(w http.ResponseWriter, r *http.Request, s *current, nav string, p secretPage) {
	data, _ := json.Marshal(handedSecret{User: s.account.Username, At: ui.o.Now().UnixMicro(), Nav: nav, Page: p}) // strings
	ui.setCookie(w, secretCookie, ui.o.Keys.Seal(secretCookie, sealVersion, data), secretWait)
	http.Redirect(w, r, ui.base+"/secret", http.StatusSeeOther)
}

// secret shows the secret the cookie carries, once: the cookie forgotten
// whatever it holds.
func (ui *UI) secret(w http.ResponseWriter, r *http.Request, s *current) {
	var h handedSecret
	c, err := r.Cookie(ui.prefix + secretCookie)
	if err == nil {
		ui.setCookie(w, secretCookie, "", 0)
		plain, ok := ui.o.Keys.Open(secretCookie, sealVersion, c.Value)
		if !ok || json.Unmarshal(plain, &h) != nil {
			h = handedSecret{}
		}
	}
	if h.Page.Secret == "" || h.User != s.account.Username || ui.o.Now().Sub(time.UnixMicro(h.At)) > secretWait {
		ui.status(w, r, http.StatusGone, "Secret already shown",
			"A secret is shown once, on the page that follows its creation or its rotation, and kept only as a hash: turn it again to get another.", s)
		return
	}
	ui.show(w, r, s, http.StatusOK, "client_secret", "The secret of "+h.Page.ID, h.Nav, h.Page)
}
