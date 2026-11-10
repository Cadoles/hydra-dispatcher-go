# Scalar, the page of /admin/v1/docs

`standalone.js` is `dist/browser/standalone.js` of the npm package
`@scalar/api-reference`, unchanged, at the version `fetch.sh` names, checked by
the integrity of its npm tarball and by its own sha256. MIT license, `LICENSE`:
Scalar's notice is not in `standalone.js`, nor yet in the image (a point of the
switchover); the licenses of what it bundles are in its comments.

`init.js` starts it on `docs.json`; the page itself is written by
`internal/admin` (docs.go), under a CSP of its own.

A new version: Renovate opens its pull request on `fetch.sh`; run
`web/scalar/fetch.sh` with the integrity and the sha256 of the new version (the
script says them when they differ), then open `/admin/v1/docs` in a browser
before merging:

- the Issues panel of the developer tools, not the console alone: a violation
  of the CSP by an eval caught in a try/catch shows there only. One is
  expected, zod's detection `Function('')`, refused; any other is to read
  (revue R36);
- no button of Scalar's services back (Open API Client, Ask AI, Deploy,
  Generate SDK): `init.js` hides them by its options, which a version may
  rename.
