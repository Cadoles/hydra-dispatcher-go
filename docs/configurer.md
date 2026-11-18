# Configurer le dispatcher

La configuration tient dans un fichier YAML, `dispatcher.yaml` : d'abord l'**infrastructure** (où écouter, où est Hydra, la base, les clés…), puis, sous `dispatcher:`, la **graine** : les apps, les flows, les réglages et les clients de l'API, que `bootstrap` écrit en base. L'infrastructure est relue à chaque démarrage ; la graine ne compte qu'à `bootstrap`, l'admin modifiant ensuite la base. Ce document en est la référence ; `livrer.md` dit quand jouer quoi.

## Comment elle se lit

- **Le fichier** : `-config <fichier>`, ou la variable `DISPATCHER_CONFIG`. Sans fichier, les seules variables `DISPATCHER_*`.
- **`${VAR}`** dans une valeur est remplacée par la variable d'environnement, vide si elle n'existe pas ; `${VAR:-défaut}` prend le défaut quand elle est absente ou vide. `$${` écrit un `${` littéral ; toute autre forme est une erreur. Une variable oubliée laisse donc la clé vide : refusée si la clé est requise, acceptée sinon.
- **`DISPATCHER_<SECTION>_<CLÉ>`** remplace une clé de l'infrastructure, prioritaire sur le fichier : `DISPATCHER_SERVER_BASE_URL`, `DISPATCHER_OBSERVABILITY_METRICS_LISTEN`. Une liste s'y écrit séparée par des virgules, comme elle peut l'être dans le fichier. Ni la graine ni `ui.csp_extra` ne sont concernées.
- **Les durées** s'écrivent comme en Go (`30m`, `1h30m`, `90s`) ou en secondes entières (`900`).
- **Les secrets** peuvent se donner par un fichier : la clé suivie de `_file` (`cookie_key_file: /run/secrets/cookie_key`), jamais les deux. C'est préférable à une variable d'environnement, que tout programme du même utilisateur lit dans `/proc`. Le dispatcher le signale au démarrage quand un webhook est un programme local, en nommant les secrets venus de l'environnement.
- **Au démarrage**, une erreur arrête le dispatcher avec le chemin de la clé fautive ; ce qui est accepté mais douteux est écrit au journal (`config.warning`).

## Ce qui n'a pas de défaut

| Clé | Ce qu'elle dit |
| --- | --- |
| `server.base_url` | l'URL publique du dispatcher, son chemin compris (`https://exemple.fr/auth/dispatcher`) ; le dispatcher sert à la racine, le reverse proxy retire ce chemin |
| `server.trusted_proxies` | les adresses des reverse proxies devant lui, `[]` si les navigateurs arrivent directement |
| `hydra.admin_url` | l'admin API de Hydra (`http://hydra:4445`) |
| `security.emulated_api_authorized_hosts` | les réseaux d'où les login apps appellent l'API émulée |
| `store.dsn` | la base Postgres (`postgres://user:mot-de-passe@hôte:5432/base`) |
| `secrets.cookie_key`, `secrets.challenge_key` | deux clés de 32 octets |
| `state.redis_dsn` | le Redis des connexions en cours ; requis dès que `server.replicas_hint` dépasse 1 |

Un exemple minimal :

```yaml
server:
  base_url: https://exemple.fr/auth/dispatcher   # l'Ingress retire /auth/dispatcher
  cookie_path: /auth/dispatcher
  trusted_proxies: [10.0.0.10/32]   # l'Ingress seul, pas tout le réseau des pods
  replicas_hint: 2                  # plus d'une instance : Redis exigé
  drain_delay: 5s                   # sous Kubernetes
hydra:
  admin_url: http://hydra:4445
  version: "2.1"
security:
  emulated_api_authorized_hosts: [10.0.1.0/24]   # le réseau des login apps
secrets:
  cookie_key: "${DISPATCHER_COOKIE_KEY}"
  challenge_key: "${DISPATCHER_CHALLENGE_KEY}"
  encryption_key: "${DISPATCHER_ENCRYPTION_KEY}"
state:
  redis_dsn: redis://redis:6379/0
  key_prefix: "dispatcher-go:"
store:
  dsn: "${DATABASE_URL}"

dispatcher:
  apps:
    - id: sql
      login_url: https://exemple.fr/auth/sql/login
      consent_url: https://exemple.fr/auth/sql/consent
      logout_url: https://exemple.fr/auth/sql/logout
      method: pwd
      allowed_sources: [10.0.1.20/32]   # l'adresse de cette app
  flows:
    - id: mot-de-passe
      title: { fr: Mot de passe, en: Password }
      description: { fr: Connexion par mot de passe, en: Sign in with a password }
      steps:
        - { id: sql, order: 0 }
```

## L'infrastructure

### `server`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `listen` | `:8080` | l'adresse d'écoute |
| `base_url` | requis | l'URL publique ; les liens et les redirections en partent. Son chemin est un préfixe que le reverse proxy retire avant le dispatcher, qui sert à la racine : un proxy qui le laisse fait répondre 404 à toutes les pages (`livrer.md`, l'Ingress de l'exemple) |
| `trusted_proxies` | requis | les mandataires dont le dispatcher croit le `X-Forwarded-For` ; l'adresse d'un navigateur sert à l'audit, aux allowlists et à la limite des échecs |
| `cookie_path` | `/` | le chemin des cookies du dispatcher ; sous `/`, en HTTPS, ils prennent le préfixe `__Host-` |
| `replicas_hint` | | au-dessus de 1, le store en mémoire est refusé |
| `drain_delay` | | à l'arrêt, le temps pendant lequel `/ready` répond 503 tout en servant encore, pour que l'orchestrateur retire l'instance (quelques secondes) |

### `hydra`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `admin_url` | requis | l'admin API ; en `http://`, un avertissement (voir `tls.allow_http`) |
| `version` | `2.2` | `2.1`, `2.2` ou `2.3` : la forme des challenges à déchiffrer. **À fixer à la version réelle** |
| `system_secrets`, `system_secrets_file` | | les `secrets.system` de Hydra, dans son ordre : le dispatcher déchiffre les challenges lui-même (Hydra 2.2 et plus) ; sans eux, il les valide par l'admin. Le fichier : un secret par ligne |
| `timeout` | `5s` | la durée d'un appel à Hydra |
| `login_consent_ttl` | `30m` | la durée de vie d'une demande de Hydra (son `ttl.login_consent_request`) |
| `max_in_flight` | `512` | les appels simultanés à Hydra, au-delà une page « réessayez » |

### `security`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `admin_authorized_hosts` | les réseaux privés | d'où l'admin (écrans et API) est joignable |
| `emulated_api_authorized_hosts` | requis | d'où les login apps appellent l'API émulée ; chaque app peut le restreindre (`allowed_sources`) |
| `metrics_authorized_hosts` | celles de l'admin | d'où `/metrics` est joignable |
| `failure_rate_limit` | `max: 20`, `per: 1m`, `block: 5m` | les échecs (challenge invalide, CSRF…) par adresse avant un blocage |

Une allowlist qui couvre tout Internet (`0.0.0.0/0`) est signalée au démarrage.

### `secrets`

Toutes des clés de 32 octets (64 caractères hexadécimaux, ou base64), chacune donnable par un fichier (`_file`). Les clés qui déchiffrent ou vérifient ont des **précédentes**, pour les tourner sans coupure : l'active signe ou chiffre, les précédentes ne font que lire (`rotation.md`).

| Clé | Sert à |
| --- | --- |
| `cookie_key`, `cookie_keys_previous` | sceller les cookies : la mémoire du skip, l'appareil, la session de l'admin |
| `challenge_key`, `challenge_keys_previous` | signer les challenges que le dispatcher émet aux apps et le marqueur du skip |
| `encryption_key`, `encryption_keys_previous` | chiffrer en base les valeurs secrètes de la configuration (le secret du SSO de l'admin, les clés de la vérification préalable) ; `secrets status` et `secrets rekey` les gèrent |
| `webhook_signing_key` | signer les appels aux webhooks ; requise avec un webhook |
| `audit_key` | pseudonymiser les subjects au journal d'audit ; sans elle, une clé dérivée de `challenge_key`, dont la rotation change alors les pseudonymes |

### `tls`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `min_version` | `1.2` | `1.2` ou `1.3`, vers Hydra et les webhooks |
| `ca_file` | | les autorités pour Hydra, à la place de celles du système |
| `allow_http` | faux | accepter des cibles en `http://` : sans lui, un webhook ou une vérification préalable en `http://` est refusé, une admin de Hydra en `http://` signalée au démarrage, et une adresse de retour en `http://` d'un client de Hydra signalée dans l'écran des clients. À réserver au développement, ou à un réseau interne assumé |
| `pinned_spki_sha256` | | pas encore pris en charge : toute valeur arrête le démarrage |
| `hsts_include_subdomains` | faux | `includeSubDomains` dans l'en-tête HSTS |

### `state`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `redis_dsn`, `redis_dsn_file` | | `redis://`, `rediss://` ou `unix://` ; vide, la mémoire (une instance seule). Des paramètres de l'URL règlent les délais (`dial_timeout`, `read_timeout`, `write_timeout`, `max_retries`) ; sinon 1 s et deux tentatives |
| `key_prefix` | | le préfixe des clés : à fixer quand le Redis est partagé |
| `redis_pool_size` | 10 par CPU | la taille du pool |

### `store`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `backend` | `postgres` | le seul possible |
| `dsn`, `dsn_file` | requis | la base ; les paramètres propres à Doctrine (un `DATABASE_URL` de Symfony) sont retirés, avec un avertissement |

### `admin`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `ui.enabled` | vrai | les écrans, sous `/admin` |
| `ui.password_login` | vrai | la connexion par mot de passe ; faux, le fournisseur d'identité seul (les réglages `admin_oidc.*`) |
| `api.enabled` | vrai | l'API, sous `/admin/v1` ; servie seulement avec `api.private_key` |
| `api.private_key`, `api.private_key_file` | | la clé qui signe les jetons : un PEM, ou son base64 comme le `OAUTH2_PRIVATE_KEY` du Symfony ; EC P-256, ou RSA de 2048 bits au moins |
| `api.public_key`, `api.public_keys_previous` | | la clé publique, et celles d'avant une rotation, qui vérifient les jetons encore valides |
| `api.token_ttl` | `15m` | la durée d'un jeton, en secondes entières |
| `api.rate_limit_per_minute` | `100` | par adresse |
| `session.idle_timeout`, `session.max_age` | `30m`, `8h` | la session des écrans |
| `session.reauth_window` | `5m` | au-delà, une action sensible (un compte, un rôle, un mot de passe, un secret, une suppression) redemande le mot de passe |
| `hydra_clients.enabled` | vrai | l'écran et l'API des clients de Hydra |
| `client_secret_max_age` | `8760h` | l'âge au-delà duquel le secret d'un client de Hydra est signalé dans l'écran des clients |

### `ui`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `theme_dir` | | un thème, qui surcharge fichier par fichier les gabarits, le CSS, les images et les traductions (`themes.md`) |
| `reload` | faux | relire le thème quand un fichier change ; pour écrire un thème |
| `remember_last_flow` | vrai | présélectionner le dernier flow choisi dans ce navigateur |
| `csp_extra` | | des sources de plus par directive de la CSP des pages (`script-src`, `connect-src`, `img-src`…), pour un thème qui charge un service externe |

### `emulated_api`, `consent`, `logout`, `webhooks`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `emulated_api.legacy_v1_paths` | vrai | servir les chemins v1 du Symfony, jusqu'à la version 2.0 |
| `consent.claims_filter` | `permissive` | `strict` : un client ne reçoit que les claims des scopes qu'il obtient, d'après le catalogue des scopes |
| `consent.show_values` | faux | montrer les valeurs des claims sur l'écran de consentement |
| `logout.propagate_without_record` | `all` | sans trace des apps qu'une session a utilisées, déconnecter toutes celles qui ont un `logout_url` (`all`), ou aucune (`none`) |
| `webhooks.process_timeout` | `5s` | la durée d'un appel |
| `webhooks.max_processes` | `32` | les appels simultanés |
| `webhooks.ca_file` | | les autorités des webhooks et des apps de vérification |

### `observability`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `log_level` | `info` | `debug`, `info`, `warn`, `error` ; le debug se règle aussi pour un temps, à chaud (`exploiter.md`) |
| `log_format` | `json` | `json` ou `text` |
| `access_log_sample` | `1` | la part des requêtes au journal d'accès |
| `log_ip` | `truncated` | les adresses aux journaux : `truncated`, `full` ou `none` |
| `debug_max_duration` | `1h` | la plus longue fenêtre de debug à chaud |
| `metrics.listen` | | un port à part pour `/metrics` (`:9142`) ; vide, sur le port du service |
| `metrics.max_label_values` | `200` | les valeurs distinctes d'un label avant `other` |
| `audit.output` | `stdout` | `stdout`, `syslog` ou `file:<chemin>` |
| `audit.pseudonymize_subject` | vrai | les subjects pseudonymisés au journal d'audit |
| `sentry.dsn`, `.environment`, `.release` | | Sentry ; la version du binaire par défaut |
| `sentry.sample_rate`, `.traces_sample_rate`, `.max_events_per_minute` | `1`, `0`, `60` | |
| `tracing.enabled`, `.endpoint`, `.protocol`, `.sampler_ratio` | faux, , `grpc`, `0.01` | OpenTelemetry ; `grpc` ou `http/protobuf` |

### `serve`, `remember`

| Clé | Défaut | Sens |
| --- | --- | --- |
| `serve.migrate` | faux | migrer au démarrage, pour le développement |
| `serve.bootstrap` | `off` | `missing` (`bootstrap`) ou `force` (`bootstrap -force`) au démarrage, pour le développement |
| `remember.backend` | `cookie` | la mémoire du skip ; le seul possible |

## La graine

Sous `dispatcher:`. `bootstrap` l'écrit en base :

- **sans `-force`**, il crée ce qui manque et laisse ce qui existe ;
- **avec `-force`**, il réécrit aussi ce qui existe pour le rendre conforme à la graine.

`bootstrap` ne supprime jamais : une app, un flow ou un client présent en base et absent de la graine reste. Sous `-force`, une app dont la graine ne nomme pas `receive_claims`, ou pas `skip_check_url`, garde ce que la base tient pour cette clé (la clé de vérification comprise) ; `~` la remet à vide. En terminal, `-force` montre ce qu'il va changer et demande confirmation, sauf `-yes`.

`bootstrap -dry-run` dit ce qu'il ferait. `config dump` rend la base dans ce format, sans les secrets ; `config diff` dit ce que `bootstrap -force` changerait.

### Les apps (`apps`)

| Clé | Sens |
| --- | --- |
| `id` | l'identifiant |
| `login_url`, `consent_url` | où le dispatcher envoie le navigateur pour le login et le consent de l'étape |
| `logout_url` | où il l'envoie à la déconnexion ; sans elle, l'app n'est pas prévenue |
| `method` | la valeur d'`amr` que l'app apporte (`pwd`, `otp`, `oidc`…) |
| `auth_mode` | comment l'app est reconnue sur l'API émulée : `network`, par ses adresses (par défaut). `mtls`, par son certificat client, est accepté mais pas encore servi : le dispatcher ne sert pas de TLS, et refuse tous les appels d'une telle app (un avertissement le dit au démarrage) |
| `allowed_sources` | en `network`, les adresses de l'app ; vides, celles de `security.emulated_api_authorized_hosts` |
| `client_cert_fingerprint` | en `mtls`, l'empreinte SHA-256 de son certificat |
| `receive_claims` | les claims des étapes précédentes que l'app reçoit ; sans la clé, tous pour une app nouvelle ; `[]`, aucun ; `~`, tous |
| `skip_check_url`, `skip_check_key` (ou `skip_check_key_file`), `skip_check_signals` | la vérification préalable : l'URL de l'app, sa clé de 32 octets (chiffrée en base, absente de `config dump`), les signaux du navigateur qu'elle reçoit (`ip` ou `full_ip`, `user_agent`, `client_hints`, `accept_language`, `device_age`) |

### Les flows (`flows`)

| Clé | Sens |
| --- | --- |
| `id` | l'identifiant |
| `enabled` | vrai par défaut ; faux, le flow n'est pas offert |
| `title`, `description`, `icon_url` | par langue (`{ fr: …, en: … }`) ; l'icône relative se cherche dans le thème |
| `acr` | l'acr envoyé à Hydra à la fin ; un client qui envoie des `acr_values` ne se voit offrir que les flows dont l'acr y figure, s'il y en a (aucun : tous restent offerts, ou le login est rejeté sous `acr_values_mode: require`). Pour imposer un flow, le client met `urn:hydra-dispatcher:preferred-app:<id du flow>` dans ses `acr_values` |
| `steps` | les étapes, chacune `{ id: <app>, order: <position> }`, et éventuellement `subject_check` (`none` par défaut, `equal`, ou `claim:<nom>`) et `skip_check: true` (jamais sur la première étape) |
| `skip_check_allowed_acr` | les `acr_values` sous lesquelles une étape peut être sautée |

### Les réglages

À la racine de `dispatcher:`.

| Clé | Défaut | Sens |
| --- | --- | --- |
| `app_auto_select` | faux | un seul flow possible : choisi d'office, sans page |
| `consent_auto_accept` | faux | accepter le consent sans écran |
| `aggregate_amr_from_login_request` | faux | l'amr fait des `amr` que les apps renvoient, plutôt que de leurs méthodes |
| `challenge_ttl` | `1h` | la durée d'une connexion en cours |
| `remember`, `login_remember_for` (ou `session_ttl`) | vrai, `24h` | la session que Hydra garde après une connexion |
| `consent_remember_for` | un mois | la mémoire d'un consentement chez Hydra |
| `login_accept_webhook_url`, `consent_accept_webhook_url` | | les webhooks ; une URL, ou un programme local |
| `supported_locales`, `default_locale`, `fallback_locale` | `[fr, en]`, `fr`, `en` | les langues des pages |
| `acr_values_mode` | `prefer` | ce que font des `acr_values` qu'aucun flow ne déclare : `prefer`, tous les flows restent offerts ; `require`, le login est rejeté. Le préfixe du flow préféré n'en fait pas partie |
| `admin_oidc.*` | | la connexion aux écrans par un fournisseur OpenID Connect : `enabled`, `issuer`, `client_id`, `client_secret`, `scopes`, `username_claim`, `required_acr`, `auto_create`, et, pour un fournisseur sans découverte, `authorization_endpoint`, `token_endpoint`, `jwks_uri`. Ce sont des clés à point, à la racine de `dispatcher:` (`admin_oidc.enabled: true`), pas un bloc `admin_oidc:` imbriqué, refusé comme clé inconnue |

Un réglage retiré de la graine garde sa valeur en base ; `~` le remet à son défaut.

### Les clients de l'API (`oauth2_clients`) et les scopes (`scopes`)

- `oauth2_clients` : `{ id, secret (ou secret_file), scopes }`, les clients de `/admin/v1` ; leurs scopes parmi `admin:apps`, `admin:flows`, `admin:settings`, `admin:clients`, `admin:scopes`, `admin:read`, `admin:debug` ; sans la clé, `admin:flows` seul, comme dans le Symfony.
- `scopes` : le catalogue des scopes métier, `{ name, label, claims: [{ claim, label }] }`, qui dit quels claims chaque scope couvre et comment l'écran de consentement les nomme.

## Les variables du dispatcher Symfony

Une variable du Symfony restée dans l'environnement est lue en repli, avec un avertissement, quand ni le fichier ni une variable `DISPATCHER_*` ne fixe la clé :

| Variable du Symfony | Clé |
| --- | --- |
| `BASE_URL` (ou `BASE_PATH` et `SERVER_NAME`) | `server.base_url` |
| `COOKIE_PATH` | `server.cookie_path` |
| `TRUSTED_PROXIES` | `server.trusted_proxies` |
| `HYDRA_ADMIN_BASE_URL` | `hydra.admin_url` |
| `HYDRA_HTTP_MAX_DURATION` | `hydra.timeout` |
| `HYDRA_ADMIN_AUTHORIZED_HOSTS` | `security.admin_authorized_hosts` (pas l'API émulée, à déclarer à part) |
| `REDIS_DSN` | `state.redis_dsn` (ses options propres à Symfony sont refusées) |
| `DATABASE_URL` | `store.dsn` |
| `OAUTH2_PRIVATE_KEY`, `OAUTH2_PUBLIC_KEY`, `OAUTH2_TOKEN_TTL` | `admin.api.private_key`, `.public_key`, `.token_ttl` |
| `ADMIN_UI_ENABLED` | `admin.ui.enabled` |
| `WEBHOOK_PROCESS_TIMEOUT` | `webhooks.process_timeout` |
| `SENTRY_DSN`, `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE` | `observability.sentry.*` |

Sans équivalent : `OAUTH2_ADMIN_CLIENT_ID` et `OAUTH2_ADMIN_CLIENT_SECRET` (il n'y a plus de client implicite de l'API : le déclarer dans `oauth2_clients`), `DEFAULT_LOCALE` et `APP_LOCALES` (les réglages `default_locale` et `supported_locales`). Les variables de PHP, de FrankenPHP ou de Caddy ne veulent rien dire ici, et sont signalées une fois.
