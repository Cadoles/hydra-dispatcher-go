// Package webhook calls the login and consent accept webhooks with Symfony's
// payloads: over HTTP, signed, or a local program, JSON on stdin and stdout. A
// webhook can rewrite the subject and the claims, and the skip calls it again on
// what it already returned: it must be idempotent (doc, Mémoire du skip).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/loglevel"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

const (
	// httpTimeout bounds an HTTP call, from the connection to the last byte of
	// the answer (doc: webhooks HTTP 5 s).
	httpTimeout = 5 * time.Second
	// maxAnswer bounds an answer, over HTTP or on a program's stdout.
	maxAnswer = 1 << 20
	// idleConns is how many idle connections stay open, by host: two webhooks,
	// usually on one host.
	idleConns = 32
	// waitDelay is how long a program's pipes may outlive it, killed or exited: a
	// child that keeps its stdout would otherwise hold the request.
	waitDelay = time.Second
	userAgent = "hydra-dispatcher-go"

	// HeaderTimestamp and HeaderSignature sign an HTTP call: the time in Unix
	// seconds, and hex(HMAC-SHA256(key, timestamp + "." + body)).
	HeaderTimestamp = "X-Dispatcher-Timestamp"
	HeaderSignature = "X-Dispatcher-Signature"
)

// Client calls the webhooks, one shared transport over HTTP, at most
// webhooks.max_processes programs at a time.
type Client struct {
	// Log, nil for none, gets webhook.request at the level debug for each call
	// (Q132): set before the first call.
	Log     *slog.Logger
	http    *http.Client
	key     []byte
	timeout time.Duration
	slots   chan struct{}
	now     func() time.Time
}

// New builds the client. The transport takes no proxy from the environment and
// follows no redirect: a webhook's URL is the one the configuration names, and a
// signed payload of subjects and claims goes nowhere else. It trusts
// webhooks.ca_file instead of the system's authorities when it is set (Q71).
func New(w config.Webhooks, minVersion string, key []byte) (*Client, error) {
	tlsConfig, err := httpx.ClientTLS(minVersion, w.CAFile)
	if err != nil {
		return nil, fmt.Errorf("webhooks.ca_file: %w", err)
	}
	return &Client{
		http:    newHTTPClient(tlsConfig, httpTimeout, httpx.PingTimeout),
		key:     key,
		timeout: w.ProcessTimeout.Std(),
		slots:   make(chan struct{}, w.MaxProcesses),
		now:     time.Now,
	}, nil
}

// newHTTPClient is the client of the calls over HTTP, bounded by timeout. An idle
// connection is closed after 30 s (httpx.IdleConnTimeout, Q84). Over HTTP/2, a
// connection silent for timeout gets a ping, and is closed if it stays
// unanswered for ping, 2 s, as Hydra's (R28): a receiver gone without a reset
// would otherwise keep its connection in the pool, and every call on it would
// fail in E1006 after timeout. The call that waits on it when it closes goes
// again on a new one, its Idempotency-Key letting Go replay it.
func newHTTPClient(tlsConfig *tls.Config, timeout, ping time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 2 * time.Second,
			TLSClientConfig:     tlsConfig,
			ForceAttemptHTTP2:   true,
			HTTP2:               &http.HTTP2Config{SendPingTimeout: timeout, PingTimeout: ping},
			MaxIdleConns:        idleConns,
			MaxIdleConnsPerHost: idleConns,
			IdleConnTimeout:     httpx.IdleConnTimeout,
		},
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Check refuses what a webhook of the settings cannot be called with: a URL in
// http:// without tls.allow_http, whatever its network (it carries subjects and
// claims, Q70), or a URL in http(s) without a key to sign it. A snapshot it
// refuses stops serve at startup, and leaves the previous one in place later on.
func Check(s store.Settings, allowHTTP, signed bool) error {
	var errs []error
	for _, hook := range []struct{ key, location string }{
		{"login_accept_webhook_url", s.LoginAcceptWebhookURL},
		{"consent_accept_webhook_url", s.ConsentAcceptWebhookURL},
	} {
		scheme := store.WebhookScheme(hook.location)
		if scheme == "http" && !allowHTTP {
			errs = append(errs, fmt.Errorf("setting %s: is in http://, which needs tls.allow_http", hook.key))
		}
		if (scheme == "http" || scheme == "https") && !signed {
			errs = append(errs, fmt.Errorf("setting %s: needs secrets.webhook_signing_key, to sign its calls", hook.key))
		}
	}
	return errors.Join(errs...)
}

// ProgramWarnings warns of a webhook run as a local program while secret keys come
// from the environment, which it names (Q87): a program of the same uid reads them in
// /proc/1/environ, which no os.Unsetenv changes, whatever the reduced environment it
// is given. Nothing sends them to it: it must go and read them.
func ProgramWarnings(s store.Settings, fromEnv []string) []string {
	if len(fromEnv) == 0 {
		return nil
	}
	var programs []string
	for _, hook := range []struct{ key, location string }{
		{"login_accept_webhook_url", s.LoginAcceptWebhookURL},
		{"consent_accept_webhook_url", s.ConsentAcceptWebhookURL},
	} {
		if scheme := store.WebhookScheme(hook.location); hook.location != "" && (scheme == "" || scheme == "file") {
			programs = append(programs, hook.key)
		}
	}
	what := ""
	switch len(programs) {
	case 0:
		return nil
	case 1:
		what = "setting " + programs[0] + " runs a local program"
	default:
		what = "settings " + strings.Join(programs, " and ") + " run local programs"
	}
	return []string{fmt.Sprintf("%s, which can read the environment of the dispatcher in /proc/1/environ: "+
		"give %s by a file (the key followed by _file) rather than by the environment", what, strings.Join(fromEnv, ", "))}
}

// browser is what a webhook is told of the browser: null for what is unknown.
type browser struct {
	IP        *string `json:"ip"`
	UserAgent *string `json:"user-agent"`
}

func browserOf(ctx context.Context) browser {
	var b browser
	if ip := httpx.ClientIP(ctx); ip.IsValid() {
		s := ip.String()
		b.IP = &s
	}
	if ua := httpx.UserAgent(ctx); ua != "" {
		b.UserAgent = &ua
	}
	return b
}

// client is what a webhook is told of the OAuth2 client: null for what Hydra does
// not serve.
type client struct {
	ClientID   *string `json:"client_id"`
	ClientName *string `json:"client_name"`
	LogoURI    *string `json:"logo_uri"`
	TosURI     *string `json:"tos_uri"`
	PolicyURI  *string `json:"policy_uri"`
}

func clientOf(raw json.RawMessage) client {
	var c client
	_ = json.Unmarshal(raw, &c) // a client that cannot be read names nothing
	return c
}

// loginPayload is Symfony's, member for member, in its order; challenge is L.
type loginPayload struct {
	Challenge   string   `json:"challenge"`
	Subject     string   `json:"subject"`
	ACR         *string  `json:"acr"`
	AMR         []string `json:"amr"`
	Context     any      `json:"context"`
	Remember    *bool    `json:"remember"`
	RememberFor *int64   `json:"remember_for"`
	Browser     browser  `json:"browser"`
	Client      client   `json:"client"`
}

// consentPayload is Symfony's, plus context: the login's (Q38).
type consentPayload struct {
	Challenge     string      `json:"challenge"`
	Subject       string      `json:"subject"`
	ACR           string      `json:"acr"`
	AMR           []string    `json:"amr"`
	Context       flow.Object `json:"context"`
	GrantScope    []string    `json:"grant_scope"`
	GrantAudience []string    `json:"grant_access_token_audience"`
	AccessToken   any         `json:"access_token"`
	IDToken       any         `json:"id_token"`
	Browser       browser     `json:"browser"`
	Client        client      `json:"client"`
}

// Login calls the login webhook of the call.
func (c *Client) Login(ctx context.Context, call flow.Call) flow.LoginHookAnswer {
	b, start := call.AcceptLogin, time.Now()
	data, err := c.invoke(ctx, call.Hook.Location, loginPayload{
		Challenge:   call.Challenge,
		Subject:     b.Subject,
		ACR:         b.Acr,
		AMR:         orEmpty(b.Amr),
		Context:     b.Context,
		Remember:    b.Remember,
		RememberFor: b.RememberFor,
		Browser:     browserOf(ctx),
		Client:      clientOf(call.Hook.Client),
	})
	if err != nil {
		c.traced(ctx, "login", call.Hook.Location, start, err)
		return flow.LoginHookAnswer{Err: err}
	}
	answer, err := parseLogin(data)
	if err != nil {
		err = refused(call.Hook.Location, start, err)
		answer = flow.LoginHookAnswer{Err: err}
	}
	c.traced(ctx, "login", call.Hook.Location, start, err)
	return answer
}

// Consent calls the consent webhook of the call.
func (c *Client) Consent(ctx context.Context, call flow.Call) flow.ConsentHookAnswer {
	b, h, start := call.AcceptConsent, call.Hook, time.Now()
	payload := consentPayload{
		Challenge:     call.Challenge,
		Subject:       h.Subject,
		ACR:           h.ACR,
		AMR:           orEmpty(h.AMR),
		Context:       h.Context,
		GrantScope:    orEmpty(b.GrantScope),
		GrantAudience: orEmpty(b.GrantAccessTokenAudience),
		AccessToken:   flow.Object{},
		IDToken:       flow.Object{},
		Browser:       browserOf(ctx),
		Client:        clientOf(h.Client),
	}
	if payload.Context == nil {
		payload.Context = flow.Object{}
	}
	if s := b.Session; s != nil {
		payload.AccessToken, payload.IDToken = s.AccessToken, s.IdToken
	}
	data, err := c.invoke(ctx, h.Location, payload)
	if err != nil {
		c.traced(ctx, "consent", h.Location, start, err)
		return flow.ConsentHookAnswer{Err: err}
	}
	answer, err := parseConsent(data)
	if err != nil {
		err = refused(h.Location, start, err)
		c.traced(ctx, "consent", h.Location, start, err)
		return flow.ConsentHookAnswer{Err: err}
	}
	c.traced(ctx, "consent", h.Location, start, nil, "id_token", answer.IDToken, "access_token", answer.AccessToken)
	return answer
}

// traced writes webhook.request at the level debug (Q132): the kind of the
// webhook, its host, the status of its answer (that of an error; 200 for an
// answer of a URL, 0 of a program), its duration, and the names of the claims
// of each member it returned, never their values; the flow and the app of its
// request.
func (c *Client) traced(ctx context.Context, kind, location string, start time.Time, err error, members ...any) {
	if c.Log == nil || !c.Log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	status := 0
	var failed *flow.HookError
	switch {
	case errors.As(err, &failed):
		status = failed.Status
	case err == nil && strings.HasPrefix(store.WebhookScheme(location), "http"):
		status = http.StatusOK
	}
	args := []any{"kind", kind, "host", target(location), "status", status, "duration_ms", time.Since(start).Milliseconds()}
	for i := 0; i+1 < len(members); i += 2 {
		if raw, _ := members[i+1].(json.RawMessage); raw != nil {
			o, _ := flow.ObjectOf(raw)
			args = append(args, members[i], append([]string{}, slices.Sorted(maps.Keys(o))...))
		}
	}
	c.Log.DebugContext(ctx, "webhook.request", append(args, loglevel.ScopeAttrs(ctx)...)...)
}

func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// refused is the error of an answer that does not hold what it should.
func refused(location string, start time.Time, err error) *flow.HookError {
	return &flow.HookError{Host: target(location), Status: http.StatusOK, Cause: err.Error(), Elapsed: time.Since(start), Err: err}
}

// target names a location in the logs: the host of a URL, whatever its path, its
// query or its user may hold, or the name of a program, without its arguments.
func target(location string) string {
	switch store.WebhookScheme(location) {
	case "http", "https":
		if u, err := url.Parse(location); err == nil {
			return u.Host
		}
		return ""
	case "file":
		if u, err := url.Parse(location); err == nil {
			return filepath.Base(u.Path)
		}
		return ""
	}
	if args := splitCommand(location); len(args) > 0 {
		return filepath.Base(args[0])
	}
	return ""
}

// invoke sends payload where location says and returns the answer.
func (c *Client) invoke(ctx context.Context, location string, payload any) ([]byte, error) {
	host := target(location)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &flow.HookError{Host: host, Cause: "the payload does not encode", Err: err}
	}
	switch store.WebhookScheme(location) {
	case "http", "https":
		return c.post(ctx, location, host, body)
	case "file":
		u, err := url.Parse(location)
		if err != nil {
			return nil, &flow.HookError{Host: host, Cause: "the location does not parse", Err: err}
		}
		return c.run(ctx, []string{u.Path}, host, body)
	}
	return c.run(ctx, splitCommand(location), host, body)
}

// sign gives the signature of body at the time ts.
func sign(key []byte, ts string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// post makes the HTTP call: 200 and application/json expected, as Symfony. An
// Idempotency-Key makes the call one Go may replay on a connection the server was
// closing, where it would otherwise fail the login on a keep-alive shorter than ours: a
// webhook is idempotent, the skip already calling it again (Q72).
func (c *Client) post(ctx context.Context, location, host string, body []byte) ([]byte, error) {
	start := time.Now()
	fail := func(status int, cause string, err error) ([]byte, error) {
		return nil, &flow.HookError{Host: host, Status: status, Cause: cause, Elapsed: time.Since(start), Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, location, bytes.NewReader(body))
	if err != nil {
		return fail(0, "the location does not parse", err)
	}
	ts := strconv.FormatInt(c.now().Unix(), 10)
	signature := sign(c.key, ts, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, signature)
	req.Header.Set("Idempotency-Key", signature)
	if id := httpx.TraceID(ctx); id != "" {
		req.Header.Set("X-Trace-ID", id)
	}
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	resp, err := c.http.Do(req)
	if err != nil {
		return fail(0, transportCause(err), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// An answer read in part would leave nothing to reuse of the connection,
		// and costs nothing kept short.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return fail(resp.StatusCode, fmt.Sprintf("status %d", resp.StatusCode), errors.New("unexpected status"))
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return fail(resp.StatusCode, "the answer is not application/json", errors.New("unexpected content type"))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	switch {
	case err != nil:
		return fail(resp.StatusCode, transportCause(err), err)
	case len(data) > maxAnswer:
		return fail(resp.StatusCode, "the answer is over 1 MiB", errors.New("answer too long"))
	case len(bytes.TrimSpace(data)) == 0:
		return fail(resp.StatusCode, "the answer is empty", errors.New("empty answer"))
	}
	return data, nil
}

// transportCause says why a call failed without the URL *url.Error quotes, whose query
// or path may hold a token.
func transportCause(err error) string {
	var u *url.Error
	if errors.As(err, &u) {
		err = u.Err
	}
	return httpx.BoundedCause(httpx.Uncited(err.Error()))
}

// bounded is a Writer that keeps the first maxAnswer bytes, and tells the program
// off past them.
type bounded struct {
	buf  bytes.Buffer
	over func()
	full bool
}

func (b *bounded) Write(p []byte) (int, error) {
	if left := maxAnswer - b.buf.Len(); left < len(p) {
		if !b.full {
			b.full = true
			b.over()
		}
		b.buf.Write(p[:max(left, 0)])
		return len(p), nil
	}
	return b.buf.Write(p)
}

// run lets the program argv answer: the payload on stdin, a line of JSON in the end,
// the answer on stdout, exit code 0. It waits for one of webhooks.max_processes at most
// webhooks.process_timeout, then runs at most as long, under a process group of its own:
// a timeout or a client gone kills what it started too, and so does its end (Q86). Its
// environment is reduced, no
// secret of the dispatcher reaching it, and what it says on stderr goes nowhere, a free
// text that may quote a subject (Q64). Empty stdout changes nothing, as Symfony.
func (c *Client) run(ctx context.Context, argv []string, host string, body []byte) ([]byte, error) {
	start := time.Now()
	fail := func(status int, cause string, err error) ([]byte, error) {
		return nil, &flow.HookError{Host: host, Status: status, Cause: cause, Elapsed: time.Since(start), Err: err}
	}
	if len(argv) == 0 {
		return fail(0, "the command is blank", errors.New("blank command"))
	}
	wait := time.NewTimer(c.timeout)
	defer wait.Stop()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return fail(0, "waiting for a process slot", ctx.Err())
	case <-wait.C:
		return fail(0, "too many processes", errors.New("no process slot"))
	}
	runCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Env = reducedEnv()
	cmd.Stdin = bytes.NewReader(append(body, '\n'))
	out := &bounded{over: cancel}
	cmd.Stdout = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	err := runToEnd(cmd)
	var exit *exec.ExitError
	switch {
	case out.full:
		return fail(0, "the answer is over 1 MiB", errors.New("answer too long"))
	case ctx.Err() != nil:
		return fail(0, "the client left", ctx.Err())
	case runCtx.Err() != nil:
		return fail(0, "timeout", runCtx.Err())
	case errors.As(err, &exit):
		return fail(exit.ExitCode(), fmt.Sprintf("exit code %d", exit.ExitCode()), err)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		return fail(0, "the program does not exist", err)
	case err != nil && !errors.Is(err, exec.ErrWaitDelay):
		// A program that exited 0 and left a child on its stdout keeps its answer, the
		// child killed with its group.
		return fail(0, "the program did not start", err)
	}
	return out.buf.Bytes(), nil
}

// reducedEnv is what a program gets of the dispatcher's environment: where to find
// programs and how to read the time and the text, no DISPATCHER_* variable, which hold
// the keys.
func reducedEnv() []string {
	var env []string
	for _, name := range []string{"PATH", "HOME", "LANG", "LC_ALL", "TZ"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// splitCommand cuts a command line as Symfony's str_getcsv($command, ' ', '"', '\\')
// does, without a shell: on spaces, a field that opens with a double quote holding
// spaces until the closing one, "" within it a quote, a backslash and what follows kept
// as they are. A quote elsewhere in a field is an ordinary character: --name="a b" gives
// two arguments, there as here. Empty fields are dropped.
func splitCommand(line string) []string {
	var args []string
	for i := 0; i < len(line); {
		if line[i] == ' ' {
			i++
			continue
		}
		var arg strings.Builder
		if line[i] == '"' {
			i++
		quoted:
			for i < len(line) {
				switch ch := line[i]; {
				case ch == '\\' && i+1 < len(line):
					arg.WriteString(line[i : i+2])
					i += 2
				case ch == '"' && i+1 < len(line) && line[i+1] == '"':
					arg.WriteByte('"')
					i += 2
				case ch == '"':
					i++
					break quoted
				default:
					arg.WriteByte(ch)
					i++
				}
			}
		}
		for i < len(line) && line[i] != ' ' {
			arg.WriteByte(line[i])
			i++
		}
		if arg.Len() > 0 {
			args = append(args, arg.String())
		}
	}
	return args
}

// members reads an answer's top level. Empty (a program's stdout, Symfony's "nothing to
// change"), or the [] of a PHP json_encode of an empty array, change nothing (Q69): any
// other list, a scalar or null is no answer.
func members(data []byte) (map[string]json.RawMessage, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || isEmptyList(data) {
		return nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		return nil, errors.New("the answer is not a JSON object")
	}
	return m, nil
}

func isEmptyList(data []byte) bool {
	var list []json.RawMessage
	return json.Unmarshal(data, &list) == nil && list != nil && len(list) == 0
}

func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// member decodes a member present into v, whose type is the member's schema. Members it
// does not name are ignored, as Symfony: a receiver may send back what it was given
// (Q68). Causes name the member, never its value.
func member[T any](m map[string]json.RawMessage, name string, v *T, want string) error {
	raw, ok := m[name]
	if !ok {
		return nil
	}
	if isNull(raw) || json.Unmarshal(raw, v) != nil {
		return fmt.Errorf("member %s is not %s", name, want)
	}
	return nil
}

// nullable is member for a member that may also be null: null reports true.
func nullable[T any](m map[string]json.RawMessage, name string, v **T, want string) (null bool, err error) {
	raw, ok := m[name]
	if !ok {
		return false, nil
	}
	if isNull(raw) {
		return true, nil
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("member %s is not %s or null", name, want)
	}
	*v = &value
	return false, nil
}

// object reads a member that holds an object: an empty list is the empty object PHP
// writes (Q69).
func object(raw json.RawMessage) json.RawMessage {
	if isEmptyList(raw) {
		return json.RawMessage(`{}`)
	}
	return raw
}

func parseLogin(data []byte) (flow.LoginHookAnswer, error) {
	var a flow.LoginHookAnswer
	m, err := members(data)
	if err != nil {
		return a, err
	}
	var subject string
	if err := member(m, "subject", &subject, "a string"); err != nil {
		return a, err
	}
	if _, ok := m["subject"]; ok {
		if subject == "" {
			// Hydra would refuse it (400, E1007), a skip take it for another subject
			// (SKP-7): the fault is the webhook's, and says so.
			return a, errors.New("member subject is empty")
		}
		a.Subject = &subject
	}
	if a.NullACR, err = nullable(m, "acr", &a.ACR, "a string"); err != nil {
		return a, err
	}
	if err := member(m, "amr", &a.AMR, "a list of strings"); err != nil {
		return a, err
	}
	if raw, ok := m["context"]; ok {
		a.Context = object(raw)
		if !isNull(a.Context) && !isObject(a.Context) {
			return a, errors.New("member context is neither an object nor null")
		}
	}
	if a.NullRemember, err = nullable(m, "remember", &a.Remember, "a boolean"); err != nil {
		return a, err
	}
	if a.NullRememberFor, err = nullable(m, "remember_for", &a.RememberFor, "an integer"); err != nil {
		return a, err
	}
	return a, nil
}

func parseConsent(data []byte) (flow.ConsentHookAnswer, error) {
	var a flow.ConsentHookAnswer
	m, err := members(data)
	if err != nil {
		return a, err
	}
	if err := member(m, "grant_scope", &a.GrantScope, "a list of strings"); err != nil {
		return a, err
	}
	if err := member(m, "grant_access_token_audience", &a.GrantAudience, "a list of strings"); err != nil {
		return a, err
	}
	for name, claims := range map[string]*json.RawMessage{"id_token": &a.IDToken, "access_token": &a.AccessToken} {
		if raw, ok := m[name]; ok {
			*claims = object(raw)
			if !isObject(*claims) {
				return a, fmt.Errorf("member %s is not an object", name)
			}
		}
	}
	return a, nil
}

func isObject(raw json.RawMessage) bool {
	var o map[string]json.RawMessage
	return json.Unmarshal(raw, &o) == nil && o != nil
}
