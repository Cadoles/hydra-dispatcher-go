#!/bin/sh
# Writes pico.classless.min.css, the sheet of the admin UI (Q119), from the npm
# tarball of the pinned version of Pico CSS: its integrity checked as npm does,
# then the sha256 of the file. The CI runs it and fails when the committed
# sheet differs.
#
# A new version (Renovate opens its pull request): the integrity is that of the
# registry (npm view @picocss/pico@<version> dist.integrity), the sha256 the
# one this script says when it differs; then open the admin UI and read the
# Issues panel for a violation of its CSP before merging (README.md).
set -eu

PICO_VERSION=2.1.1 # renovate: datasource=npm depName=@picocss/pico
INTEGRITY=sha512-kIDugA7Ps4U+2BHxiNHmvgPIQDWPDU4IeU6TNRdvXQM1uZX+FibqDQT2xUOnnO2yq/LUHcwnGlu1hvf4KfXnMg==
SHA256=61207a40ffc02a42d1e50143651c121beab70ed413c934c1ff84fa263ba436b0

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/package.tgz" "https://registry.npmjs.org/@picocss/pico/-/pico-$PICO_VERSION.tgz"
got="sha512-$(openssl dgst -sha512 -binary "$tmp/package.tgz" | base64 | tr -d '\n')"
if [ "$got" != "$INTEGRITY" ]; then
	echo "fetch.sh: the tarball has the integrity $got, not $INTEGRITY" >&2
	exit 1
fi
tar -xzf "$tmp/package.tgz" -C "$tmp" package/css/pico.classless.min.css package/LICENSE.md
file=$tmp/package/css/pico.classless.min.css
if command -v sha256sum >/dev/null; then
	sum=$(sha256sum "$file" | cut -d' ' -f1)
else
	sum=$(shasum -a 256 "$file" | cut -d' ' -f1)
fi
if [ "$sum" != "$SHA256" ]; then
	echo "fetch.sh: pico.classless.min.css has the sha256 $sum, not $SHA256" >&2
	exit 1
fi
cp "$file" "$dir/pico.classless.min.css"
cp "$tmp/package/LICENSE.md" "$dir/LICENSE.md"
