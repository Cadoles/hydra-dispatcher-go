package admin

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

type stepJSON struct {
	AppID        string `json:"appId"`
	StepOrder    int    `json:"stepOrder"`
	SubjectCheck string `json:"subjectCheck"`
	// SkipCheck asks the app of the step whether it may be skipped (phase 4).
	SkipCheck bool `json:"skipCheck"`
}

// flowJSON is the representation of a flow: its steps by stepOrder, without
// the internal id Symfony gave them (Q109).
type flowJSON struct {
	ID          string            `json:"id"`
	Title       map[string]string `json:"title"`
	Description map[string]string `json:"description"`
	// IconURL is null for no icon.
	IconURL map[string]string `json:"iconUrl"`
	Enabled bool              `json:"enabled"`
	ACR     *string           `json:"acr"`
	// SkipCheckAllowedACR are the acr_values under which a step may be
	// skipped by its pre-check, [] for none.
	SkipCheckAllowedACR []string   `json:"skipCheckAllowedAcr"`
	Steps               []stepJSON `json:"steps"`
}

func flowOf(f store.Flow) flowJSON {
	j := flowJSON{ID: f.ID, Title: orEmpty(f.Title), Description: orEmpty(f.Description), IconURL: f.IconURL, Enabled: f.Enabled,
		SkipCheckAllowedACR: append([]string{}, f.SkipCheckAllowedACR...), Steps: []stepJSON{}}
	if len(j.IconURL) == 0 {
		j.IconURL = nil
	}
	if f.ACR != "" {
		j.ACR = &f.ACR
	}
	steps := slices.SortedFunc(slices.Values(f.Steps), func(a, b store.Step) int { return cmp.Compare(a.Position, b.Position) })
	for _, s := range steps {
		j.Steps = append(j.Steps, stepJSON{AppID: s.AppID, StepOrder: s.Position, SubjectCheck: s.SubjectCheck, SkipCheck: s.SkipCheck})
	}
	return j
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// The fields of a flow: those of Symfony, which a PUT replaces, steps apart,
// which a PUT without them keeps as Symfony does; acr and
// skipCheckAllowedAcr, which the Go adds, kept too (Q107).
var (
	flowFields = []string{"id", "title", "description", "iconUrl", "enabled", "acr", "skipCheckAllowedAcr", "steps"}
	stepKeys   = []string{"appId", "id", "stepOrder", "order", "subjectCheck", "skipCheck"}
)

// applyFlow writes the fields of b into f, as mode says.
func applyFlow(b body, f *store.Flow, mode writeMode) error {
	if err := b.unknown(flowFields); err != nil {
		return err
	}
	if mode == replace {
		f.Title, f.Description, f.IconURL, f.Enabled = map[string]string{}, map[string]string{}, nil, true
	}
	for _, t := range []struct {
		name string
		into *map[string]string
	}{{"title", &f.Title}, {"description", &f.Description}, {"iconUrl", &f.IconURL}} {
		if b.has(t.name) {
			m, err := b.texts(t.name)
			if err != nil {
				return err
			}
			*t.into = m // replaced whole (Q104)
		}
	}
	if len(f.IconURL) == 0 {
		f.IconURL = nil
	}
	if b.has("enabled") {
		enabled, err := b.boolean("enabled", true)
		if err != nil {
			return err
		}
		f.Enabled = enabled
	}
	if b.has("acr") {
		acr, err := b.str("acr")
		if err != nil {
			return err
		}
		f.ACR = acr
	}
	if b.has("skipCheckAllowedAcr") {
		acr, err := b.strs("skipCheckAllowedAcr")
		if err != nil {
			return err
		}
		f.SkipCheckAllowedACR = nil
		if len(acr) > 0 {
			f.SkipCheckAllowedACR = acr
		}
	}
	if b.has("steps") {
		steps, err := readSteps(b["steps"], f.Steps)
		if err != nil {
			return err
		}
		f.Steps = steps
	}
	return nil
}

// readSteps reads the steps of a write, under both forms of Symfony: the app by
// appId or id, appId winning as with Symfony, whose reads gave id the internal
// id of the step; the position by stepOrder or order, an integer or a numeric
// string. subjectCheck absent keeps the one the app had in the flow, none for a
// new app (Q107); skipCheck likewise, false for a new app. null is no step.
func readSteps(raw json.RawMessage, previous []store.Step) ([]store.Step, error) {
	if kind(raw) == "null" {
		return nil, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, typeError("steps", "array", raw)
	}
	had, skipped := map[string]string{}, map[string]bool{}
	for _, s := range previous {
		had[s.AppID], skipped[s.AppID] = s.SubjectCheck, s.SkipCheck
	}
	var steps []store.Step
	var v requestViolations
	for i, entry := range entries {
		path := fmt.Sprintf("steps[%d]", i)
		var e body
		if kind(entry) != "object" || json.Unmarshal(entry, &e) != nil || e == nil {
			v = append(v, domain.Violation{Field: path, Message: "is not an object"})
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(e)) {
			if !slices.Contains(stepKeys, k) {
				v = append(v, domain.Violation{Field: path + "." + k, Message: "is not a field of a step"})
			}
		}
		step := store.Step{}
		switch {
		case e.has("appId") && !e.null("appId"):
			app, err := e.str("appId")
			if err != nil {
				return nil, typeError(path+".appId", "string", e["appId"])
			}
			step.AppID = app
		case e.has("id") && !e.null("id"):
			app, err := e.str("id")
			if err != nil {
				return nil, typeError(path+".id", "string", e["id"])
			}
			step.AppID = app
		default:
			v = append(v, domain.Violation{Field: path + ".appId", Message: "is required"})
		}
		orderKey := "stepOrder"
		if !e.has(orderKey) || e.null(orderKey) {
			orderKey = "order"
		}
		switch position, ok, err := stepOrder(e[orderKey]); {
		case !e.has(orderKey) || e.null(orderKey):
			v = append(v, domain.Violation{Field: path + ".stepOrder", Message: "is required"})
		case err != nil:
			return nil, err
		case !ok:
			v = append(v, domain.Violation{Field: path + "." + orderKey, Message: "is not an integer"})
		default:
			step.Position = position
		}
		step.SubjectCheck = cmp.Or(had[step.AppID], "none")
		if e.has("subjectCheck") && !e.null("subjectCheck") {
			check, err := e.str("subjectCheck")
			if err != nil {
				return nil, typeError(path+".subjectCheck", "string", e["subjectCheck"])
			}
			step.SubjectCheck = check
		}
		step.SkipCheck = skipped[step.AppID]
		if e.has("skipCheck") {
			skip, err := e.boolean("skipCheck", false)
			if err != nil {
				return nil, typeError(path+".skipCheck", "boolean", e["skipCheck"])
			}
			step.SkipCheck = skip
		}
		steps = append(steps, step)
	}
	if v != nil {
		return nil, v
	}
	return steps, nil
}

// stepOrder reads a position as Symfony casts it: a number, or a string that
// holds an integer.
func stepOrder(raw json.RawMessage) (int, bool, error) {
	switch kind(raw) {
	case "int":
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			return 0, false, nil
		}
		return int(n), true, nil
	case "string":
		var s string
		_ = json.Unmarshal(raw, &s)
		n, err := strconv.Atoi(strings.TrimSpace(s))
		return n, err == nil, nil
	}
	return 0, false, nil
}

func (a *API) registerFlows() {
	a.Handle("GET "+Prefix+"/flows", Flows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := page(r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		items := []flowJSON{}
		for _, f := range paginate(a.o.Config.Snapshot().Flows, n) {
			items = append(items, flowOf(f))
		}
		writeResource(w, http.StatusOK, items)
	}))
	a.Handle("GET "+Prefix+"/flows/{id}", Flows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One snapshot read: a refresh between two reads would give another
		// flow, or an index past the end (revue R35).
		id, flows := r.PathValue("id"), a.o.Config.Snapshot().Flows
		i := slices.IndexFunc(flows, func(f store.Flow) bool { return f.ID == id })
		if i < 0 {
			a.fail(w, r, "", store.ErrNotFound)
			return
		}
		writeResource(w, http.StatusOK, flowOf(flows[i]))
	}))
	a.Handle("POST "+Prefix+"/flows", Flows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(w, r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		f := store.Flow{Enabled: true}
		if b.has("id") {
			if f.ID, err = b.str("id"); err != nil {
				a.fail(w, r, "", err)
				return
			}
		}
		if err := applyFlow(b, &f, create); err != nil {
			a.fail(w, r, "", err)
			return
		}
		if err := a.o.Writer.CreateFlow(r.Context(), author(r), f); err != nil {
			a.fail(w, r, "Flow "+f.ID, err)
			return
		}
		a.wrote(r, Flows, f.ID, b.fieldsOf(flowFields))
		w.Header().Set("Location", Prefix+"/flows/"+f.ID)
		writeResource(w, http.StatusCreated, flowOf(f))
	}))
	update := func(mode writeMode) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			b, err := readBody(w, r)
			if err == nil {
				err = checkPathID(b, id)
			}
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			var written store.Flow
			err = a.o.Writer.UpdateFlow(r.Context(), author(r), id, func(f *store.Flow) error {
				if err := applyFlow(b, f, mode); err != nil {
					return err
				}
				written = *f
				return nil
			})
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			a.wrote(r, Flows, id, b.fieldsOf(flowFields))
			writeResource(w, http.StatusOK, flowOf(written))
		}
	}
	a.Handle("PUT "+Prefix+"/flows/{id}", Flows, update(replace))
	a.Handle("PATCH "+Prefix+"/flows/{id}", Flows, update(patch))
	a.Handle("DELETE "+Prefix+"/flows/{id}", Flows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := a.o.Writer.DeleteFlow(r.Context(), id); err != nil {
			a.fail(w, r, "", err)
			return
		}
		a.wrote(r, Flows, id, nil)
		w.WriteHeader(http.StatusNoContent)
	}))
}
