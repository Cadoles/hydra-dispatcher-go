B=http://10.0.6.136
H="Host: dispatcher.hydra.test"
T=$(curl -s -H "$H" -X POST $B/admin/v1/token -d grant_type=client_credentials -d client_id=test -d client_secret=test | jq -r .access_token)
req() {
  method=$1; path=$2; ctype=$3; body=$4; auth=${5:-yes}
  echo "=== $method $path ${ctype:+[$ctype]} ${body}"
  set -- -s -i -H "$H" -X "$method"
  [ "$auth" = yes ] && set -- "$@" -H "Authorization: Bearer $T"
  [ -n "$ctype" ] && set -- "$@" -H "Content-Type: $ctype"
  [ -n "$body" ] && set -- "$@" --data "$body"
  curl "$@" "$B$path" | tr -d '\r' | grep -v -i '^\(date\|x-debug\|x-powered\|link\|vary\|server\|alt-svc\|content-length\|permissions-policy\|x-frame\|x-content\|referrer\|cache-control\|x-robots\|expires\|pragma\|etag\|last-modified\)' | cut -c1-700 | head -25
  echo
}
J=application/json
M=application/merge-patch+json
req GET /admin/v1/flows "" "" no
req GET /admin/v1/flows
req GET /admin/v1/flows/hydra-sql-2fa
req GET /admin/v1/apps/hydra-sql
req GET /admin/v1/oauth2-clients
req GET /admin/v1/settings
req GET '/admin/v1/apps?page=2'
req GET '/admin/v1/apps?page=0'
req GET /admin/v1/apps/unknown
req POST /admin/v1/apps $J '{"id":"zz-app","loginUrl":"http://x/login","consentUrl":"http://x/consent","logoutUrl":"","method":"pwd"}'
req POST /admin/v1/apps $J '{"id":"zz-app","loginUrl":"http://x/login","consentUrl":"http://x/consent","logoutUrl":"","method":"pwd"}'
req POST /admin/v1/apps $J '{"id":"bad/id","loginUrl":"not a url","consentUrl":"","method":""}'
req POST /admin/v1/apps $J '{"id":"zz-app2","loginUrl":42}'
req POST /admin/v1/apps $J 'not json'
req POST /admin/v1/apps text/plain '{"id":"zz-app3"}'
req POST /admin/v1/flows $J '{"id":"zz-flow","title":{"fr":"Z"},"description":{"fr":"Z"},"enabled":true,"steps":[{"appId":"zz-app","stepOrder":0}]}'
req PUT /admin/v1/flows/zz-flow $J '{"id":"zz-flow","title":{"fr":"Z2"},"description":{"fr":"Z2"},"enabled":true,"steps":[{"appId":"zz-app","stepOrder":0}]}'
req PUT /admin/v1/flows/zz-flow $J '{"title":{"fr":"Z3"}}'
req PATCH /admin/v1/flows/zz-flow $J '{"enabled":false}'
req PATCH /admin/v1/flows/zz-flow $M '{"enabled":false,"title":{"en":"E"}}'
req PATCH /admin/v1/flows/zz-flow $M '{"steps":[{"id":"zz-app","order":"3"},"junk"]}'
req PATCH /admin/v1/flows/zz-flow $M '{"steps":[{"appId":"nope","stepOrder":0}]}'
req GET /admin/v1/flows/zz-flow
req PUT /admin/v1/apps/zz-app $J '{"id":"zz-app","loginUrl":"http://y/login","consentUrl":"http://y/consent","logoutUrl":"","method":"otp"}'
req PUT /admin/v1/apps/zz-app $J '{"method":"otp2"}'
req GET /admin/v1/apps/zz-app
req PATCH /admin/v1/apps/zz-app $M '{"id":"zz-renamed"}'
req GET /admin/v1/apps/zz-renamed
req POST /admin/v1/oauth2-clients $J '{"id":"zz-client","secret":"x"}'
req PUT /admin/v1/oauth2-clients/zz-client $J '{"id":"zz-client","secret":"y"}'
req PATCH /admin/v1/oauth2-clients/zz-client $M '{"secret":"z"}'
req DELETE /admin/v1/oauth2-clients/zz-client
req GET /admin/v1/oauth2-clients/zz-client
req DELETE /admin/v1/flows/zz-flow
req GET /admin/v1/flows/zz-flow
req DELETE /admin/v1/apps/zz-app
req DELETE /admin/v1/apps/zz-renamed
req GET /admin/v1/apps/zz-renamed
req PATCH /admin/v1/settings $M '{"appAutoSelect":false}'
req PUT /admin/v1/settings $J '{"challengeTtl":3600}'
req PUT /admin/v1/settings $J '{"challengeTtl":"abc"}'
req PATCH /admin/v1/settings $M '{"supportedLocales":"fr"}'
req GET /admin/v1/docs.json
