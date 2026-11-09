# theme-demo

A whole theme of the dispatcher's pages in Tailwind, for a fictitious
establishment, Val Fictif: every template rewritten in Tailwind classes, a
logo, flags, a German locale the binary does not have, and two texts changed
in French and English. The guide of the themes is `docs/themes.md`.

```
theme.yaml          name, version, api: 1
input.css           the source of static/theme.css: the charter's colours, buttons, links
build.sh            builds static/theme.css with the standalone Tailwind CLI, pinned
templates/          the layout, the four pages and the partials
static/             theme.css (built, committed), images/logo.svg, flags/
translations/       de.json, a whole locale; fr.json and en.json, two keys each
```

Its layout loads `theme.css` alone, not the base CSS of the dispatcher:
Tailwind's preflight takes its place. A lighter theme keeps the layout and
only redefines the variables of the base CSS in its `theme.css`.

## Build and check

```sh
examples/theme-demo/build.sh                                   # static/theme.css, after a change of a template
go run ./cmd/hydra-dispatcher theme check examples/theme-demo  # the check of serve
```

`build.sh` downloads the CLI once to `~/.cache/hydra-dispatcher`, and checks its
sum at each run. The CI runs both, and fails when the committed `theme.css`
differs from the one built.

## Run it

With hydra-dev, `ui.reload` on: a template edited shows at the next page,
`theme.css` once `build.sh` has run. German shows once the setting
`supported_locales` names `de`:

```sh
HYDRA_DEV_THEME=../hydra-dispatcher-go/examples/theme-demo HYDRA_DEV_LOCALES=fr,en,de make up-go
```

In an image of its own (the sources of the build stay unread at the root):

```dockerfile
FROM reg.cadoles.com/cadoles/hydra-dispatcher-go:<version>
COPY examples/theme-demo /etc/dispatcher/theme
ENV DISPATCHER_UI_THEME_DIR=/etc/dispatcher/theme
```
