package main

import (
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// browser is a cookie jar that follows redirects itself, to keep the trail
// of what it requested and to stop at the client's redirect_uri, which the
// OAuth2 test client of hydra-dev would otherwise serve and redeem.
type browser struct {
	c *http.Client
	// stopAt is the redirect_uri: a redirect there ends a walk unfollowed.
	stopAt string
	log    *slog.Logger
}

func newBrowser(stopAt string, log *slog.Logger) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{
		c: &http.Client{
			Jar:     jar,
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		stopAt: stopAt,
		log:    log,
	}
}

// page is where a walk ends: a page, or the redirect to the redirect_uri,
// whose URL then carries the code or the error and which has no body.
type page struct {
	URL    *url.URL
	Status int
	Body   string
	// Trail lists the URLs requested on the way, URL last.
	Trail []*url.URL
}

// maxRedirects bounds a walk: hydra-oidc's login crosses the app, the IdP and
// back, then the dispatcher and Hydra.
const maxRedirects = 25

func (b *browser) get(u string) (page, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return page{}, err
	}
	return b.walk(req, nil)
}

// submit posts form from p, as filled by values, and follows the redirects.
func (b *browser) submit(p page, f form, values url.Values) (page, error) {
	if f.Method == http.MethodGet {
		u := *f.Action
		u.RawQuery = values.Encode()
		return b.get(u.String())
	}
	body := []byte(values.Encode())
	req, err := http.NewRequest(http.MethodPost, f.Action.String(), nil)
	if err != nil {
		return page{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The page that holds the form, as a browser sends it.
	req.Header.Set("Origin", p.URL.Scheme+"://"+p.URL.Host)
	return b.walk(req, body)
}

func (b *browser) walk(req *http.Request, body []byte) (page, error) {
	var trail []*url.URL
	for range maxRedirects {
		trail = append(trail, req.URL)
		resp, err := b.do(req, body)
		if err != nil {
			return page{}, err
		}
		loc, err := resp.Location()
		if err != nil || resp.StatusCode < 300 || resp.StatusCode > 399 {
			return page{URL: req.URL, Status: resp.StatusCode, Body: resp.body, Trail: trail}, nil
		}
		if strings.HasPrefix(loc.String(), b.stopAt) {
			return page{URL: loc, Status: resp.StatusCode, Trail: append(trail, loc)}, nil
		}
		method := http.MethodGet
		if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			method = req.Method
		} else {
			body = nil
		}
		// New headers: the client wrote the jar's cookies for this host into
		// req's, which a copy would send to the next one.
		next, err := http.NewRequest(method, loc.String(), nil)
		if err != nil {
			return page{}, err
		}
		if body != nil {
			for _, h := range []string{"Content-Type", "Origin"} {
				next.Header.Set(h, req.Header.Get(h))
			}
		}
		req = next
	}
	return page{}, fmt.Errorf("more than %d redirects from %s", maxRedirects, trail[0].Redacted())
}

type response struct {
	*http.Response
	body string
}

func (b *browser) do(req *http.Request, body []byte) (response, error) {
	if body != nil {
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.ContentLength = int64(len(body))
	}
	req.Header.Set("User-Agent", "hydra-dispatcher-go/examples/hydra-dev/e2e")
	req.Header.Set("Accept-Language", "fr")
	resp, err := b.c.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return response{}, err
	}
	b.log.Debug("browser", "method", req.Method, "url", req.URL.Redacted(), "status", resp.StatusCode)
	return response{resp, string(data)}, nil
}

// form is an HTML form of a page: what a browser would submit from it.
type form struct {
	// Action is resolved against the page's URL.
	Action *url.URL
	Method string
	Fields []field
}

// field is an input, or a button, of a form.
type field struct {
	Tag, Type, Name, Value string
	Checked                bool
}

func (f field) button() bool {
	return f.Tag == "button" || f.Type == "submit" || f.Type == "image"
}

var (
	formTag  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	fieldTag = regexp.MustCompile(`(?is)<(input|button)\b([^>]*)>`)
	attr     = regexp.MustCompile(`(?s)([A-Za-z_:][-A-Za-z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)
)

// parseForms reads the forms of an HTML page well enough for the pages of
// hydra-dev: neither nested forms nor inputs outside their form.
func parseForms(base *url.URL, body string) []form {
	var forms []form
	for _, m := range formTag.FindAllStringSubmatch(body, -1) {
		a := attrs(m[1])
		action, err := base.Parse(a["action"])
		if err != nil {
			continue
		}
		f := form{Action: action, Method: strings.ToUpper(a["method"])}
		if f.Method != http.MethodPost {
			f.Method = http.MethodGet
		}
		for _, t := range fieldTag.FindAllStringSubmatch(m[2], -1) {
			a := attrs(t[2])
			_, checked := a["checked"]
			f.Fields = append(f.Fields, field{
				Tag:     strings.ToLower(t[1]),
				Type:    strings.ToLower(a["type"]),
				Name:    a["name"],
				Value:   a["value"],
				Checked: checked,
			})
		}
		forms = append(forms, f)
	}
	return forms
}

// attrs returns the attributes of a tag, names in lowercase, values
// unescaped; an attribute without a value maps to "".
func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attr.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2] + m[3] + m[4])
	}
	return out
}

// has tells whether the form has a field or a button named name.
func (f form) has(name string) bool {
	return slices.ContainsFunc(f.Fields, func(x field) bool { return x.Name == name })
}

// find returns the first form of p that has a field named name.
func (p page) find(name string) (form, bool) {
	for _, f := range parseForms(p.URL, p.Body) {
		if f.has(name) {
			return f, true
		}
	}
	return form{}, false
}

// pressed names the button a submission presses: its value matters when
// several buttons share the name.
type pressed struct{ Name, Value string }

// values returns what a browser submits from f: its inputs other than
// buttons, the boxes and radios only when checked; then set, where a radio
// takes one of its own values; then the pressed button, if any.
func (f form) values(set map[string]string, press *pressed) (url.Values, error) {
	v := url.Values{}
	for _, x := range f.Fields {
		switch {
		case x.Name == "" || x.button():
		case x.Type == "checkbox" || x.Type == "radio":
			if x.Checked {
				v.Add(x.Name, x.Value)
			}
		default:
			v.Add(x.Name, x.Value)
		}
	}
	for name, value := range set {
		i := slices.IndexFunc(f.Fields, func(x field) bool {
			return x.Name == name && !x.button() && (x.Type != "radio" || x.Value == value)
		})
		if i < 0 {
			return nil, fmt.Errorf("form %s has no field %s to set to %q", f.Action.Redacted(), name, value)
		}
		v.Set(name, value)
	}
	if press != nil {
		i := slices.IndexFunc(f.Fields, func(x field) bool {
			return x.button() && x.Name == press.Name && (press.Value == "" || x.Value == press.Value)
		})
		if i < 0 {
			return nil, fmt.Errorf("form %s has no button %s=%q", f.Action.Redacted(), press.Name, press.Value)
		}
		v.Add(press.Name, f.Fields[i].Value)
	}
	return v, nil
}

// errUnexpected reports a page the walk does not know what to do with.
func errUnexpected(p page) error {
	text := strings.Join(strings.Fields(tagless.ReplaceAllString(p.Body, " ")), " ")
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	return fmt.Errorf("unexpected page %s (status %d): %s", p.URL.Redacted(), p.Status, text)
}

var tagless = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]*>`)

var errNoCallback = errors.New("the authorization did not come back to the client")
