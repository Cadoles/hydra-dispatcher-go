# The admin API of the Symfony dispatcher, replayed

`replay.txt` holds the answers of the Symfony dispatcher's `/admin/v1` to the
requests of `probe.sh`, played on 10 November 2026 against hydra-dev's Symfony
dispatcher (`hydra-dispatcher` at `d66639e`, image built after it, `APP_ENV=dev`),
started alone with the profile `symfony`, from its own container on the network
`backend`, with a token of the client `test` of the seed. The objects `zz-*` were
created for the replay; the bootstrap of Symfony rewrites its database at its next
start.

Cleaned of what `APP_ENV=dev` adds: the `trace` of each error, the debug token and
cookie, the trace id. The bodies are otherwise as Symfony sent them, null fields
left out by API Platform included.

It is the reference of the contract of P16 (`Conception Dispatcher Go.md`,
Contrat de l'admin API) and of its deviations from Symfony.
