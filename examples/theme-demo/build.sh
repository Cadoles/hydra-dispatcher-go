#!/bin/sh
# Builds static/theme.css from input.css and the templates, by the standalone
# Tailwind CLI pinned by version and checksums (Q91). The CI runs it and fails
# when the committed theme.css differs: run it after a change of a template.
#
# A new version of the CLI (Renovate opens its pull request): the four sums
# come from the sha256sums.txt of its release, then build.sh, then commit
# theme.css with them.
set -eu

TAILWIND_VERSION=v4.3.3 # renovate: datasource=github-releases depName=tailwindlabs/tailwindcss
case "$(uname -s)-$(uname -m)" in
Linux-x86_64) asset=tailwindcss-linux-x64 sum=dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a ;;
Linux-aarch64) asset=tailwindcss-linux-arm64 sum=55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195 ;;
Darwin-arm64) asset=tailwindcss-macos-arm64 sum=cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d ;;
Darwin-x86_64) asset=tailwindcss-macos-x64 sum=7922e0953f2110c05976e3bf58f14e643d90427575e766b7d433f5f80cbee7e1 ;;
*)
	echo "build.sh: no Tailwind CLI pinned for $(uname -s)-$(uname -m)" >&2
	exit 1
	;;
esac

dir=$(cd "$(dirname "$0")" && pwd)
cache=${XDG_CACHE_HOME:-$HOME/.cache}/hydra-dispatcher/tailwindcss-$TAILWIND_VERSION
cli=$cache/$asset
if [ ! -f "$cli" ]; then
	mkdir -p "$cache"
	curl -sSfL -o "$cli.part" "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAILWIND_VERSION/$asset"
	mv "$cli.part" "$cli"
fi
# Checked at each run, not only at the download: the cache is outside the
# repository.
if command -v sha256sum >/dev/null; then
	echo "$sum  $cli" | sha256sum -c --quiet -
else
	echo "$sum  $cli" | shasum -a 256 -c --quiet -
fi
chmod +x "$cli"
"$cli" --input "$dir/input.css" --output "$dir/static/theme.css" --minify
