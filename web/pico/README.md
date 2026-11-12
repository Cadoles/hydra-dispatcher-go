# Pico CSS, the sheet of the admin UI

`pico.classless.min.css` is `css/pico.classless.min.css` of the npm package
`@picocss/pico`, unchanged, at the version `fetch.sh` names, checked by the
integrity of its npm tarball and by its own sha256 (Q119). MIT license,
`LICENSE.md`; the notice is also at the head of the sheet, served with it.

A sheet without classes and without JavaScript: the pages of `web/admin`
style their HTML elements, nothing else. It asks the CSP of the admin for
`style-src 'self'` and `img-src data:` (its few images are SVG in `data:`),
nothing more: no font, no `@import`, no address outside.

A new version: Renovate opens its pull request on `fetch.sh`; run
`web/pico/fetch.sh` with the integrity and the sha256 of the new version (the
script says them when they differ), then open the admin UI in a browser and
read the Issues panel of the developer tools for a violation of its CSP before
merging.
