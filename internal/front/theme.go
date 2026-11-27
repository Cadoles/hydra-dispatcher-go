package front

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Cadoles/hydra-dispatcher-go/internal/i18n"
	"github.com/Cadoles/hydra-dispatcher-go/web"
)

// API is the version of the contract of the pages (Thèmes) this binary
// supports, which a theme names in its theme.yaml: additions keep it, a
// breaking change increments it.
const API = 1

// pageNames are the pages, each parsed with the layout and the partials.
var pageNames = []string{"select", "consent", "error", "logout"}

// Manifest is the theme.yaml of a theme.
type Manifest struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	API     int    `yaml:"api"`
}

// Theme is what the pages are made of: the embedded theme, and over it, file
// by file, the directory of ui.theme_dir (Thèmes). Everything is read at load:
// a static file served is the one hashed, and nothing reads the directory
// afterwards.
type Theme struct {
	// Dir is ui.theme_dir, "" for the embedded theme alone; Manifest its
	// theme.yaml, the zero value without it.
	Dir      string
	Manifest Manifest

	templates map[string]*template.Template
	// statics are the static files by their path under static/.
	statics  map[string]staticFile
	catalogs i18n.Catalogs
}

type staticFile struct {
	data []byte
	hash string
}

// Locales are the locales the theme has a catalog for, sorted: those the pages
// may offer (Q92).
func (t *Theme) Locales() []string { return t.catalogs.Locales() }

// LoadTheme reads the theme of dir over the embedded one; "" gives the embedded
// one alone. A directory that cannot be read, a theme.yaml absent or of
// another api, a file the pages would not read, a template that does not parse
// are errors; Check, and New, then render each page of it.
func LoadTheme(dir string) (*Theme, error) {
	t := &Theme{Dir: dir, statics: map[string]staticFile{}}
	fsys := fs.FS(web.FS)
	embedded, err := i18n.Embedded()
	if err != nil {
		return nil, err
	}
	t.catalogs = embedded
	if dir != "" {
		// A link does not take a file of the theme out of its directory.
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		disk := root.FS()
		if t.Manifest, err = readManifest(disk); err != nil {
			return nil, err
		}
		if err := checkTemplates(disk); err != nil {
			return nil, err
		}
		translations, err := readTranslations(disk)
		if err != nil {
			return nil, err
		}
		t.catalogs = embedded.Merge(translations)
		fsys = overlay{theme: disk, embedded: web.FS}
	}
	if t.templates, err = parseTemplates(fsys); err != nil {
		return nil, err
	}
	err = fs.WalkDir(fsys, "static", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		t.statics[strings.TrimPrefix(name, "static/")] = staticFile{data: data, hash: hex.EncodeToString(sum[:])[:12]}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// parseTemplates parses each page with the layout and the partials.
func parseTemplates(fsys fs.FS) (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.ParseFS(fsys, "templates/layout.html.tmpl", "templates/partials/*.html.tmpl", "templates/"+name+".html.tmpl")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}

// readManifest reads theme.yaml: a theme names itself, its version, and the
// version of the contract of the pages it follows.
func readManifest(fsys fs.FS) (Manifest, error) {
	data, err := fs.ReadFile(fsys, "theme.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, fmt.Errorf("no theme.yaml: a theme gives its name, its version and the api of the pages it follows (api: %d)", API)
	}
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("theme.yaml: %w", err)
	}
	var errs []error
	if m.Name == "" {
		errs = append(errs, errors.New("theme.yaml: no name"))
	}
	if m.Version == "" {
		errs = append(errs, errors.New("theme.yaml: no version"))
	}
	switch {
	case m.API == 0:
		errs = append(errs, fmt.Errorf("theme.yaml: no api; this binary supports api %d", API))
	case m.API != API:
		errs = append(errs, fmt.Errorf("theme.yaml: api %d is not supported; this binary supports api %d", m.API, API))
	}
	return m, errors.Join(errs...)
}

// checkTemplates refuses a file of templates/ that no page reads: a mistyped
// name would leave the embedded template in place without a word. A new
// partial is read, by every page.
func checkTemplates(fsys fs.FS) error {
	known := []string{"layout.html.tmpl"}
	for _, name := range pageNames {
		known = append(known, name+".html.tmpl")
	}
	var errs []error
	err := fs.WalkDir(fsys, "templates", func(name string, d fs.DirEntry, err error) error {
		if name == "templates" && errors.Is(err, fs.ErrNotExist) {
			return fs.SkipAll
		}
		if err != nil || d.IsDir() {
			return err
		}
		dir, file := path.Split(name)
		if !(dir == "templates/" && slices.Contains(known, file) || dir == "templates/partials/" && strings.HasSuffix(file, ".html.tmpl")) {
			errs = append(errs, fmt.Errorf("%s: not a template of the pages (templates/%s, templates/partials/*.html.tmpl)", name, strings.Join(known, ", templates/")))
			return nil
		}
		// Read here, a link out of the theme says so: the pattern of the
		// partials would only find no file.
		_, err = fs.ReadFile(fsys, name)
		errs = append(errs, err)
		return nil
	})
	return errors.Join(err, errors.Join(errs...))
}

// readTranslations reads the catalogs of translations/, none without it.
func readTranslations(fsys fs.FS) (i18n.Catalogs, error) {
	switch info, err := fs.Stat(fsys, "translations"); {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case !info.IsDir():
		return nil, errors.New("translations: not a directory")
	}
	sub, err := fs.Sub(fsys, "translations")
	if err != nil {
		return nil, err
	}
	c, err := i18n.Read(sub)
	if err != nil {
		return nil, fmt.Errorf("translations/%w", err)
	}
	return c, nil
}

// overlay serves the file of the theme when it has one, else the embedded
// one; a directory lists the files of both, for the partials' pattern and
// static/. A file of the theme that cannot be read, a link out of its
// directory say, is an error rather than the embedded file.
type overlay struct{ theme, embedded fs.FS }

func (o overlay) Open(name string) (fs.File, error) {
	f, err := o.theme.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return o.embedded.Open(name)
	}
	return f, err
}

func (o overlay) ReadDir(name string) ([]fs.DirEntry, error) {
	entries := map[string]fs.DirEntry{}
	embedded, embeddedErr := fs.ReadDir(o.embedded, name)
	for _, e := range embedded {
		entries[e.Name()] = e
	}
	theme, themeErr := fs.ReadDir(o.theme, name)
	switch {
	case themeErr != nil && !errors.Is(themeErr, fs.ErrNotExist):
		return nil, themeErr
	case themeErr != nil && embeddedErr != nil:
		return nil, embeddedErr
	}
	for _, e := range theme {
		entries[e.Name()] = e
	}
	return slices.SortedFunc(maps.Values(entries), func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) }), nil
}
