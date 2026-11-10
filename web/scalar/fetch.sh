#!/bin/sh
# Writes standalone.js, the bundle of Scalar's API reference that /admin/v1/docs
# serves, from the npm tarball of the pinned version: its integrity checked as
# npm does, then the sha256 of the file. The CI runs it and fails when the
# committed standalone.js differs.
#
# A new version (Renovate opens its pull request): the integrity is that of the
# registry (npm view @scalar/api-reference@<version> dist.integrity), the sha256
# the one this script says when it differs; then open /admin/v1/docs and read
# the console for a violation of the CSP before merging.
set -eu

SCALAR_VERSION=1.76.0 # renovate: datasource=npm depName=@scalar/api-reference
INTEGRITY=sha512-pjqwnzmA9YK3ZX+IZSICMsywm4qI6HLSngR2py9H6TvFApHHuJjkTAd+gFJfnqJDzJuro8k7ji6JCtJ2U+Byng==
SHA256=dcb027152bf20bf2f6dcd66e8f9fb073c1a9e274cf0b94b939a7d99ab8947060

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/package.tgz" "https://registry.npmjs.org/@scalar/api-reference/-/api-reference-$SCALAR_VERSION.tgz"
got="sha512-$(openssl dgst -sha512 -binary "$tmp/package.tgz" | base64 | tr -d '\n')"
if [ "$got" != "$INTEGRITY" ]; then
	echo "fetch.sh: the tarball has the integrity $got, not $INTEGRITY" >&2
	exit 1
fi
tar -xzf "$tmp/package.tgz" -C "$tmp" package/dist/browser/standalone.js
file=$tmp/package/dist/browser/standalone.js
if command -v sha256sum >/dev/null; then
	sum=$(sha256sum "$file" | cut -d' ' -f1)
else
	sum=$(shasum -a 256 "$file" | cut -d' ' -f1)
fi
if [ "$sum" != "$SHA256" ]; then
	echo "fetch.sh: standalone.js has the sha256 $sum, not $SHA256" >&2
	exit 1
fi
cp "$file" "$dir/standalone.js"
