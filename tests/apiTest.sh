#!/usr/bin/env bash
# The contract the admin API of the Go dispatcher keeps with that of the
# Symfony one, played against either: a token (form and JSON), the lists and
# their pages, an app and a flow created, read, patched (merge-patch+json),
# replaced and deleted, the settings read, the errors of a token, a page and an
# unknown resource. The deviations the design document lists (Contrat de
# l'admin API) are left out: a POST on an id taken (500 in Symfony, 409), a
# PATCH in application/json (415, 200), what a DELETE leaves, the scopes. Each
# status is checked; the first difference stops it, exit 1.
#
#   BASE_URL=http://dispatcher.hydra.test CLIENT_ID=test CLIENT_SECRET=test tests/apiTest.sh
#
# HOST sets the Host header, for a dispatcher reached by its address (the
# Symfony one in hydra-dev, which Caddy no longer serves). The ids it creates
# are zz-apitest-<time>-*: a run leaves nothing behind in the Go dispatcher; in
# Symfony, whose DELETE of a flow deletes nothing, the flow stays.
set -euo pipefail

BASE_URL=${BASE_URL:-http://dispatcher.hydra.test}
CLIENT_ID=${CLIENT_ID:-test}
CLIENT_SECRET=${CLIENT_SECRET:-test}
HOST=${HOST:-}
command -v jq >/dev/null || { echo "apiTest: jq is required" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
STATUS='' BODY='' TOKEN='' STEP=0

# call METHOD PATH [CONTENT-TYPE BODY] [noauth]: STATUS and BODY of the answer.
call() {
  local method=$1 path=$2 ctype=${3:-} body=${4:-} auth=${5:-auth}
  local args=(-sS -o "$tmp/body" -w '%{http_code}' -X "$method")
  [ -n "$HOST" ] && args+=(-H "Host: $HOST")
  [ "$auth" = auth ] && [ -n "$TOKEN" ] && args+=(-H "Authorization: Bearer $TOKEN")
  [ -n "$ctype" ] && args+=(-H "Content-Type: $ctype" --data-binary "$body")
  STATUS=$(curl "${args[@]}" "$BASE_URL$path")
  BODY=$(cat "$tmp/body")
}

# check WHAT STATUS [JQ-FILTER]: the status, and the filter true on the body.
check() {
  local what=$1 want=$2 filter=${3:-}
  STEP=$((STEP + 1))
  if [ "$STATUS" != "$want" ]; then
    echo "apiTest: step $STEP, $what: $STATUS, want $want: $BODY" >&2
    exit 1
  fi
  if [ -n "$filter" ] && [ "$(jq -r "$filter" <<<"$BODY")" != true ]; then
    echo "apiTest: step $STEP, $what: $filter is not true of $BODY" >&2
    exit 1
  fi
  echo "ok $STEP - $what"
}

J=application/json
M=application/merge-patch+json
F=application/x-www-form-urlencoded
id=zz-apitest-$(date +%s)
app=$id-app
flow=$id-flow

# The token, by a form then in JSON; a wrong secret.
call POST /admin/v1/token "$F" "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
check "token, form" 200 '.token_type == "Bearer" and (.access_token | length > 0) and (.expires_in | type == "number")'
TOKEN=$(jq -r .access_token <<<"$BODY")
call POST /admin/v1/token "$J" "{\"grant_type\":\"client_credentials\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\"}"
check "token, JSON" 200 '.access_token | length > 0'
call POST /admin/v1/token "$F" "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=not-$CLIENT_SECRET"
check "token, a wrong secret" 401 '.error == "invalid_client"'
call POST /admin/v1/token "$F" "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
check "token, no grant_type" 400 '.error == "unsupported_grant_type"'

# Without a token, with one; the pages.
call GET /admin/v1/flows "" "" noauth
check "flows without a token" 401 '.error == "invalid_token"'
call GET /admin/v1/flows
check "flows" 200 'type == "array"'
call GET '/admin/v1/apps?page=1'
check "apps, page 1" 200 'type == "array" and length <= 30'
call GET '/admin/v1/apps?page=1000'
check "apps, a page past the end" 200 '. == []'
call GET '/admin/v1/apps?page=0'
check "apps, page 0" 400

# An app.
call POST /admin/v1/apps "$J" "{\"id\":\"$app\",\"loginUrl\":\"http://apitest/login\",\"consentUrl\":\"http://apitest/consent\",\"logoutUrl\":\"http://apitest/logout\",\"method\":\"pwd\"}"
check "app created" 201 ".id == \"$app\" and .method == \"pwd\""
call GET "/admin/v1/apps/$app"
check "app read" 200 '.loginUrl == "http://apitest/login" and .logoutUrl == "http://apitest/logout"'
call PATCH "/admin/v1/apps/$app" "$M" '{"method":"otp"}'
check "app patched" 200 '.method == "otp" and .loginUrl == "http://apitest/login"'
# Read back after each write: an answer right over a write left undone
# passed (revue R38).
call GET "/admin/v1/apps/$app"
check "app patched, read back" 200 '.method == "otp" and .loginUrl == "http://apitest/login"'
call PUT "/admin/v1/apps/$app" "$J" "{\"id\":\"$app\",\"loginUrl\":\"http://apitest/login2\",\"consentUrl\":\"http://apitest/consent2\",\"logoutUrl\":\"http://apitest/logout\",\"method\":\"pwd\"}"
check "app replaced" 200 '.loginUrl == "http://apitest/login2" and .method == "pwd"'
call GET "/admin/v1/apps/$app"
check "app replaced, read back" 200 '.loginUrl == "http://apitest/login2" and .consentUrl == "http://apitest/consent2" and .method == "pwd"'
call POST /admin/v1/apps text/plain "{\"id\":\"$id-other\"}"
check "app, a body not JSON" 415
call GET /admin/v1/apps/zz-apitest-none
check "app unknown" 404 '.status == 404'

# A flow.
call POST /admin/v1/flows "$J" "{\"id\":\"$flow\",\"title\":{\"fr\":\"A\"},\"description\":{\"fr\":\"D\"},\"enabled\":true,\"steps\":[{\"appId\":\"$app\",\"stepOrder\":0}]}"
check "flow created" 201 ".id == \"$flow\" and (.steps | length == 1) and .steps[0].appId == \"$app\""
call GET "/admin/v1/flows/$flow"
check "flow read" 200 '.title.fr == "A" and .enabled == true'
call PATCH "/admin/v1/flows/$flow" "$M" '{"enabled":false,"title":{"en":"E"}}'
check "flow patched" 200 '.enabled == false and .title == {"en":"E"} and .description.fr == "D"'
call GET "/admin/v1/flows/$flow"
check "flow patched, read back" 200 '.enabled == false and .title == {"en":"E"} and .description.fr == "D"'
call PUT "/admin/v1/flows/$flow" "$J" "{\"id\":\"$flow\",\"title\":{\"fr\":\"B\"},\"description\":{\"fr\":\"D2\"},\"enabled\":true,\"steps\":[{\"appId\":\"$app\",\"stepOrder\":0}]}"
check "flow replaced" 200 '.title == {"fr":"B"} and .enabled == true'
call GET "/admin/v1/flows/$flow"
check "flow replaced, read back" 200 '.title == {"fr":"B"} and .description == {"fr":"D2"} and .enabled == true and .steps[0].appId == "'"$app"'"'

# The settings, read.
call GET /admin/v1/settings
check "settings" 200 '(.appAutoSelect | type == "boolean") and (.supportedLocales | type == "array")'

# Deleted: the flow, then its app.
call DELETE "/admin/v1/flows/$flow"
check "flow deleted" 204
call DELETE "/admin/v1/apps/$app"
check "app deleted" 204

echo "apiTest: $STEP steps, all passed"
