package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Writer writes the configuration: store.Postgres (P14).
type Writer interface {
	CreateApp(ctx context.Context, by string, a store.App) error
	UpdateApp(ctx context.Context, by, id string, change func(*store.App) error) error
	DeleteApp(ctx context.Context, id string) error
	CreateFlow(ctx context.Context, by string, f store.Flow) error
	UpdateFlow(ctx context.Context, by, id string, change func(*store.Flow) error) error
	DeleteFlow(ctx context.Context, id string) error
	CreateAPIClient(ctx context.Context, by string, c store.APIClient) error
	UpdateAPIClient(ctx context.Context, by, id string, change func(*store.APIClient) error) error
	DeleteAPIClient(ctx context.Context, id string) error
	UpdateSettings(ctx context.Context, by string, values map[string]json.RawMessage) error
}

// problem is an error of the resources, the form of API Platform without the
// code of a constraint nor a trace.
type problem struct {
	Type       string      `json:"type"`
	Title      string      `json:"title"`
	Status     int         `json:"status"`
	Detail     string      `json:"detail"`
	Violations []violation `json:"violations,omitempty"`
}

type violation struct {
	PropertyPath string `json:"propertyPath"`
	Message      string `json:"message"`
}

func writeProblem(w http.ResponseWriter, status int, detail string) {
	writeProblemBody(w, problem{Type: fmt.Sprintf("/errors/%d", status), Title: "An error occurred", Status: status, Detail: detail})
}

func writeProblemBody(w http.ResponseWriter, p problem) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// writeViolations answers 422, each violation under the path of its field in
// camelCase (Q94).
func writeViolations(w http.ResponseWriter, v domain.Violations) {
	p := problem{Type: "/validation_errors", Title: "An error occurred", Status: http.StatusUnprocessableEntity}
	var lines []string
	for _, x := range v {
		path := camel(x.Field)
		p.Violations = append(p.Violations, violation{PropertyPath: path, Message: x.Message})
		if path == "" {
			lines = append(lines, x.Message)
		} else {
			lines = append(lines, path+": "+x.Message)
		}
	}
	p.Detail = strings.Join(lines, "\n")
	writeProblemBody(w, p)
}

// camel writes a path of the domain (steps[1].subject_check, login_url) in
// the camelCase of the API (steps[1].subjectCheck, loginUrl).
func camel(path string) string {
	segments := strings.Split(path, ".")
	for i, seg := range segments {
		name, index, _ := strings.Cut(seg, "[")
		parts := strings.Split(name, "_")
		for j := 1; j < len(parts); j++ {
			if parts[j] != "" {
				parts[j] = strings.ToUpper(parts[j][:1]) + parts[j][1:]
			}
		}
		segments[i] = strings.Join(parts, "")
		if index != "" {
			segments[i] += "[" + index
		}
	}
	return strings.Join(segments, ".")
}

// refusedViolations gives a configuration serve would refuse as violations:
// the lines that name a setting under its key, the others under none.
func refusedViolations(err error) domain.Violations {
	var v domain.Violations
	for line := range strings.Lines(err.Error()) {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "setting "); ok {
			if key, message, ok := strings.Cut(rest, ": "); ok && !strings.Contains(key, " ") {
				v = append(v, domain.Violation{Field: key, Message: message})
				continue
			}
		}
		v = append(v, domain.Violation{Message: "the configuration it leaves would be refused: " + line})
	}
	return v
}

// fail answers the error of a request or of a write: its status, and for a
// failure of the dispatcher a 500 that says nothing of its cause, which goes to
// the log with the trace id.
func (a *API) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	var he *httpError
	var v domain.Violations
	var ref *store.ReferencedError
	var refused *store.RefusedError
	switch {
	case errors.As(err, &he):
		writeProblem(w, he.status, he.detail)
	case errors.As(err, &v):
		writeViolations(w, v)
	case errors.As(err, &refused):
		writeViolations(w, refusedViolations(refused.Err))
	case errors.Is(err, store.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "Not Found")
	case errors.Is(err, store.ErrExists):
		writeProblem(w, http.StatusConflict, what+" already exists.")
	case errors.As(err, &ref):
		writeProblem(w, http.StatusConflict, fmt.Sprintf("App %s is a step of the flows %s: remove it from them first.", ref.App, strings.Join(ref.Flows, ", ")))
	default:
		if a.o.Logger != nil {
			a.o.Logger.ErrorContext(r.Context(), "admin.write_failed", "cause", err.Error())
		}
		writeProblem(w, http.StatusInternalServerError, "An internal error occurred, trace "+httpx.TraceID(r.Context())+".")
	}
}
