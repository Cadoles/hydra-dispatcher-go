package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// The OAuth2 clients of Hydra, for the screens of the admin UI (P23). They go
// as JSON, whole: the SDK's model drops what it does not know, and refuses a
// client whose jwks has a key without alg, kid or use (DecodeClient). A
// client is modified by a JSON Patch of its fields alone (Q122): what a form
// does not show stays as Hydra holds it. An answer is never logged: it holds
// the secret at a creation and at a rotation.

// ClientsPage asks for a page of the clients: Size of them, from Token ("" for
// the first page), Name the exact client_name to filter by, "" for none.
type ClientsPage struct {
	Size        int
	Token, Name string
}

// ClientList is a page of the clients, Next the token of the next page, ""
// for none, Total how many clients the filter gives.
type ClientList struct {
	Clients []json.RawMessage
	Next    string
	Total   int
}

// PatchOp is an operation of a JSON Patch (RFC 6902): replace, add or remove
// a member by its JSON Pointer. A remove ignores its value.
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// Clients lists a page of the clients.
func (c *Client) Clients(ctx context.Context, p ClientsPage) (ClientList, error) {
	q := url.Values{"page_size": {strconv.Itoa(p.Size)}}
	if p.Token != "" {
		q.Set("page_token", p.Token)
	}
	if p.Name != "" {
		q.Set("client_name", p.Name)
	}
	body, header, err := c.adminCall(ctx, "list_oauth2_clients", http.MethodGet, "/admin/clients", q, nil)
	if err != nil {
		return ClientList{}, err
	}
	l := ClientList{Next: nextToken(header.Values("Link"))}
	l.Total, _ = strconv.Atoi(header.Get("X-Total-Count"))
	if err := json.Unmarshal(body, &l.Clients); err != nil {
		return ClientList{}, &UnavailableError{Op: "list_oauth2_clients", Status: http.StatusOK, err: err}
	}
	return l, nil
}

// OAuthClient reads the client id; a *RequestError of status 404 when
// Hydra has none.
func (c *Client) OAuthClient(ctx context.Context, id string) (json.RawMessage, error) {
	body, _, err := c.adminCall(ctx, "get_oauth2_client", http.MethodGet, "/admin/clients/"+url.PathEscape(id), nil, nil)
	return body, err
}

// CreateClient creates a client of the members of body; Hydra gives its id.
// The answer holds its secret, once.
func (c *Client) CreateClient(ctx context.Context, body map[string]any) (json.RawMessage, error) {
	resp, _, err := c.adminCall(ctx, "create_oauth2_client", http.MethodPost, "/admin/clients", nil, body)
	return resp, err
}

// PatchClient applies ops to the client id, and gives the client written: its
// secret, when ops replace it.
func (c *Client) PatchClient(ctx context.Context, id string, ops []PatchOp) (json.RawMessage, error) {
	resp, _, err := c.adminCall(ctx, "patch_oauth2_client", http.MethodPatch, "/admin/clients/"+url.PathEscape(id), nil, ops)
	return resp, err
}

// DeleteClient deletes the client id.
func (c *Client) DeleteClient(ctx context.Context, id string) error {
	_, _, err := c.adminCall(ctx, "delete_oauth2_client", http.MethodDelete, "/admin/clients/"+url.PathEscape(id), nil, nil)
	return err
}

// adminCall calls the admin API of Hydra by method on path, with the JSON of
// body when it is not nil, through the SDK's HTTP client as read does; an
// answer other than a 2xx is a *RequestError or an *UnavailableError
// (classify).
func (c *Client) adminCall(ctx context.Context, op, method, path string, query url.Values, body any) (json.RawMessage, http.Header, error) {
	type answer struct {
		body   json.RawMessage
		header http.Header
	}
	a, err := call(c, ctx, op, func() (answer, *http.Response, error) {
		var payload io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return answer{}, nil, err
			}
			payload = bytes.NewReader(b)
		}
		target := c.admin + path
		if len(query) > 0 {
			target += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, method, target, payload)
		if err != nil {
			return answer{}, nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return answer{}, resp, err
		}
		data, err := io.ReadAll(resp.Body)
		switch {
		case err != nil:
			return answer{}, resp, err
		case resp.StatusCode >= 300:
			return answer{}, resp, &statusError{status: resp.Status, body: data}
		}
		return answer{body: data, header: resp.Header}, resp, nil
	})
	return a.body, a.header, err
}

// linkNext finds the target of rel="next" in a Link header.
var linkNext = regexp.MustCompile(`<([^>]*)>\s*;\s*rel="?next"?`)

// nextToken is the page_token of the next page, from the Link headers of
// Hydra; "" for the last page.
func nextToken(links []string) string {
	for _, l := range links {
		if m := linkNext.FindStringSubmatch(l); m != nil {
			if u, err := url.Parse(m[1]); err == nil {
				return u.Query().Get("page_token")
			}
		}
	}
	return ""
}
