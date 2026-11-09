# Thèmes des pages

Un thème habille les pages que le dispatcher montre aux utilisateurs : le choix du mode de connexion, l'écran de consent, la page d'erreur et la confirmation de logout. L'administration n'est pas thématisable. Ce guide décrit le contrat des pages, version `api: 1`. Un prompt pour faire générer un thème est dans `docs/theme-prompt.md` ; un thème complet en Tailwind, dans `examples/theme-demo`.

## Ce qu'est un thème

Un répertoire, que `ui.theme_dir` désigne, posé fichier par fichier sur le thème embarqué dans le binaire : ce que le thème fournit remplace le fichier de même chemin, le reste est celui par défaut.

```
theme.yaml                          obligatoire : name, version, api: 1
templates/
  layout.html.tmpl                  squelette : blocs title, head, header, content, footer
  select.html.tmpl                  choix du mode de connexion
  consent.html.tmpl                 écran de consent
  error.html.tmpl                   page d'erreur
  logout.html.tmpl                  confirmation, refus et suites du logout
  partials/client_header.html.tmpl  logo et nom du client OAuth2
  partials/flow_card.html.tmpl      une carte de mode de connexion
  partials/locale_switcher.html.tmpl
  partials/csrf.html.tmpl           le jeton CSRF des formulaires
  partials/<autre>.html.tmpl        un partiel ajouté, que vos gabarits appellent
static/
  theme.css                         chargé après le CSS de base ; vide par défaut
  theme.js                          facultatif, chargé en defer s'il existe
  images/, fonts/, flags/<locale>.svg
translations/
  <locale>.json                     textes changés, ou une locale entière
```

`theme.yaml` :

```yaml
name: mon-theme
version: 1.0.0
api: 1
```

Le dispatcher lit le thème au démarrage, une fois, et le refuse, ce qui arrête le démarrage, quand :

- `theme.yaml` manque, porte une autre clé que `name`, `version` et `api`, ou une `api` qu'il ne prend pas en charge (aujourd'hui, toute autre que 1) ;
- un fichier de `templates/` n'est ni le layout, ni une page, ni un partiel `templates/partials/*.html.tmpl` : une faute dans un nom laisserait sinon le gabarit embarqué en place sans un mot ;
- un fichier de `translations/` n'est pas un `<locale>.json` d'une locale en minuscules (`fr`, `de`, `pt-br`), objet plat de textes ;
- un lien symbolique sort du répertoire (un lien qui y reste est suivi : un volume Kubernetes en est fait) ;
- le contrôle des pages échoue (plus bas).

À la racine, seul `theme.yaml` est lu : les sources d'un build (`input.css`, un `build.sh`) peuvent y rester. Sous `/static/`, seuls les fichiers de `static/` sont servis, depuis la mémoire, avec leur empreinte dans l'URL et un cache d'un an.

## Commencer petit

Le CSS de base expose des variables ; un habillage aux couleurs d'un établissement tient dans `static/theme.css` :

```css
:root {
  --color-accent: #6d28d9;
  --color-accent-text: #ffffff;
  --color-background: #f5f3ff;
  --radius: 0.75rem;
  --font: "Inter", system-ui, sans-serif;
}
```

et le logo dans un partiel, `templates/partials/client_header.html.tmpl` :

```html
{{define "client_header"}}<div class="client"><img class="logo" src="{{.Asset "images/logo.svg"}}" alt="">{{if .Client.Name}}<span>{{.Client.Name}}</span>{{end}}</div>{{end}}
```

avec `static/images/logo.svg` et le `theme.yaml`. Une police hébergée va dans `static/fonts/`, déclarée par `@font-face` dans `theme.css` avec une URL relative (`url(fonts/inter.woff2)`).

## Développer et vérifier

```sh
hydra-dispatcher theme check <répertoire>
```

rend chaque page du thème dans chaque locale, comme `serve` au démarrage, sans configuration ni base : une ligne par problème et le code de retour 1, ou une ligne qui nomme le thème. L'image du dispatcher le fait aussi : `docker run --rm -v "$PWD/mon-theme:/theme:ro" <image> theme check /theme`.

Avec `ui.reload: true`, les pages relisent le thème quand l'un de ses fichiers change, et refont le contrôle : un gabarit, un texte ou une image modifiés s'affichent à la page suivante ; un thème qui échoue donne une 500 dont le texte dit pourquoi. C'est un mode de développement : la configuration le rappelle au démarrage. Dans hydra-dev :

```sh
HYDRA_DEV_THEME=../mon-theme HYDRA_DEV_LOCALES=fr,en make up-go
```

## Déployer

Dans une image dérivée :

```dockerfile
FROM reg.cadoles.com/cadoles/hydra-dispatcher-go:<version>
COPY mon-theme /etc/dispatcher/theme
ENV DISPATCHER_UI_THEME_DIR=/etc/dispatcher/theme
```

ou monté en volume, en lecture seule, avec `ui.theme_dir` (ou `DISPATCHER_UI_THEME_DIR`) qui le désigne. Un `ConfigMap` Kubernetes n'a pas de sous-répertoires : ses clés passent par `items[].path` (`templates/select.html.tmpl`). Au démarrage, le journal écrit `theme.loaded`, avec le répertoire, le nom, la version, l'`api` et les locales du thème.

## Gabarits

Les gabarits sont des `html/template` de Go. Chaque page est analysée avec `layout.html.tmpl`, tous les partiels (`partials/*.html.tmpl`) et son propre fichier. La page définit les blocs `title` et `content` ; le layout offre aussi `head`, `header` et `footer`, qu'une page peut redéfinir. Le layout embarqué rend `header` par le partiel `client_header` et `footer` par `locale_switcher`.

Un partiel commence par `{{define "nom"}}`. `client_header`, `locale_switcher` et `csrf` reçoivent les données de la page ; le layout embarqué appelle les deux premiers sur toutes les pages, page d'erreur comprise, où `.Client` est vide. `flow_card` reçoit un élément de `.Flows`. Le titre et le texte d'introduction sont dans chaque page, pas dans un partiel.

Tout est échappé : un texte n'est jamais du HTML, et une URL en `javascript:` ou `data:` devient `#ZgotmplZ`. Aucune fonction n'est ajoutée à celles de `html/template` (`if`, `range`, `with`, `eq`, `len`, `index`, `printf`…) : celles du contrat sont des méthodes des données.

### Données

| Donnée | Pages | Contenu |
| --- | --- | --- |
| `.Locale` | toutes | la locale de la page |
| `.Locales` | toutes | les locales proposées, chacune avec `.Code`, `.Label` (le nom de la locale dans sa langue), `.Action` (l'URL du changement de langue), `.Flag` (l'URL du drapeau, vide sans lui), `.Current` ; vide hors de la confirmation sur la page de logout |
| `.Return` | toutes | la page à laquelle revient le changement de langue, vide là où il n'y revient pas |
| `.Client` | choix, consent, logout d'un client | `.Name`, `.LogoURI`, `.ClientURI`, `.PolicyURI`, `.TosURI` du client OAuth2 ; vide sur la page d'erreur |
| `.Flows` | choix | chaque mode proposé : `.ID`, `.Title`, `.Description`, `.IconURL`, et `.Selected`, vrai pour le dernier mode employé, à cocher |
| `.Scopes` | consent | chaque groupe de données : `.Label`, et `.Claims`, chacune avec `.Label` et `.Value` (vide sans `consent.show_values`) |
| `.Audience` | consent | les destinataires demandés, une liste de textes |
| `.Error` | erreur ; choix | `.Code` (`E1000` à `E1008`), `.MessageKey`, `.TraceID`, `.Link` (le site du client, vide sans lui), `.SignOut` (le lien de déconnexion d'Hydra, sur E1003 et sur l'E1006 d'un skip, vide sinon). Sur la page de choix, `.MessageKey` seul, quand le mode posté n'est pas proposé ; `nil` sinon |
| `.Form` | choix, consent, confirmation de logout | `.Action`, `.LoginChallenge`, `.ConsentChallenge`, `.LogoutChallenge`, `.CSRF`, et `.Print` sur l'écran de consent sans flow |
| `.Logout` | logout | `.State` (`confirm`, `declined`, `in_progress`, `already_out`), `.OtherSession` (la demande vise une autre session que celle du navigateur), `.Next` (le lien qui reprend une déconnexion commencée) |

### Méthodes

- `{{.T "clé" args…}}` : le texte de la clé dans la locale de la page, ses `%s` remplis dans l'ordre.
- `{{.Asset "fichier"}}` : l'URL, empreinte comprise, d'un fichier de `static/` (`"theme.css"`, `"images/logo.svg"`) ; vide s'il n'existe pas, ce qui permet `{{with .Asset "theme.js"}}…{{end}}`. Le contrôle ne le signale pas : une faute de nom donne une URL vide.
- `{{.Flag "fr"}}` : l'URL du drapeau d'une locale, `static/flags/<locale>.svg`, vide sans lui. Aucun drapeau n'est embarqué.
- `{{.LocaleURL "en"}}` : l'URL du changement de langue vers une locale.

N'écrivez jamais une URL du dispatcher en dur (`/static/…`, `/locale/…`, `/`) : `server.base_url` peut porter un chemin. Passez par `.Asset`, `.LocaleURL`, `.Form.Action` et l'`.Action` de chaque locale.

### Ce que les gestionnaires lisent

Les formulaires postent des champs que le dispatcher lit ; le contrôle les relit dans le HTML rendu, avec leurs valeurs.

- Choix : `<form method="post" action="{{.Form.Action}}">`, un `<input type="radio" name="flow" value="{{.ID}}" required>` par mode, coché si `.Selected`, un champ caché `login_challenge` valant `{{.Form.LoginChallenge}}`, et le partiel `csrf`. Un bouton de validation, qui peut porter `autofocus` : le dernier mode est présélectionné, l'utilisateur confirme d'Entrée.
- Consent : `<form method="post" action="{{.Form.Action}}">`, un champ caché `consent_challenge` valant `{{.Form.ConsentChallenge}}`, le partiel `csrf`, `{{if .Form.Print}}<input type="hidden" name="claims_print" value="{{.Form.Print}}">{{end}}`, un bouton `name="action" value="accept"` et un bouton `name="action" value="reject"` ; toute autre valeur refuse. Aucun des deux n'a `autofocus` : une touche gardée appuyée depuis la page précédente n'accepte rien.
- Confirmation de logout (`.Logout.State` vaut `confirm`) : `<form method="post" action="{{.Form.Action}}">`, un champ caché `logout_challenge` valant `{{.Form.LogoutChallenge}}`, le partiel `csrf`, un bouton `name="action" value="accept"` et un bouton `name="action" value="reject"`. Dans les autres états, ni formulaire ni sélecteur de langue ; `in_progress` donne le lien `{{.Logout.Next}}`.
- Langue : `<form method="post">`, `{{with .Return}}<input type="hidden" name="return" value="{{.}}">{{end}}`, puis un bouton par locale avec `formaction="{{.Action}}"`. Gardez `aria-current` sur la locale courante.
- Erreur : `{{.T .Error.MessageKey}}`, `.Error.TraceID` et `.Error.Code`, le lien `.Error.Link` s'il existe (texte `error.back`), le lien `.Error.SignOut` s'il existe (texte `error.sign_out`).
- Le partiel `csrf` : `<input type="hidden" name="csrf_token" value="{{.Form.CSRF}}">`.

## CSS de base

Le CSS de base est écrit à la main et chargé avant `theme.css` par le layout embarqué. Ses variables :

| Variable | Rôle |
| --- | --- |
| `--color-text`, `--color-muted` | texte, texte secondaire |
| `--color-background`, `--color-surface`, `--color-border` | fond de la page, du cadre principal, bordures |
| `--color-accent`, `--color-accent-text` | boutons, mode coché, liens de langue ; texte sur l'accent |
| `--color-alert` | messages d'erreur (`.message`, `[role="alert"]`) |
| `--radius`, `--space` | rayons, espacement de base |
| `--font` | police |

Il n'a ni mode sombre ni style de focus propre (celui du navigateur). Ses classes, celles des gabarits embarqués : `.client`, `.logo`, `.lead`, `fieldset.flows`, `label.flow`, `.icon`, `.title`, `.description`, `.message`, `.scopes`, `.scope`, `.value`, `.audience`, `.trace`, `.locales`, `.flag`, `button.secondary`. Un gabarit réécrit avec d'autres classes apporte leur CSS dans `theme.css`, le CSS de base ne les connaissant pas.

Un thème qui réécrit tout, en Tailwind par exemple, peut ne plus charger le CSS de base : son layout ne lie que `{{.Asset "theme.css"}}`. `examples/theme-demo` le fait, et compile son `theme.css` par le CLI Tailwind standalone (`build.sh`) en ne scannant que ses gabarits.

## Ce que la CSP interdit

Les pages sont servies avec une politique de sécurité du contenu que le thème ne peut pas lever :

- ni `<script>` sans `src`, ni attribut `on…` (`onclick`) : le JavaScript va dans `static/theme.js`, chargé en `defer` par le layout. Les pages doivent marcher sans JavaScript ;
- ni `<style>`, ni attribut `style="…"` : le style va dans `static/theme.css` ;
- ni URL `javascript:` ;
- scripts, feuilles de style et polices viennent de `static/` ; les images peuvent venir d'une URL `https`, comme le logo d'un client ;
- les pages ne s'affichent jamais dans une iframe.

Le contrôle refuse les trois premiers points, que la CSP bloquerait sans bruit. Une origine externe, une police d'un CDN par exemple, s'ajoute au déploiement par `ui.csp_extra` (`font-src: ["https://fonts.gstatic.com"]`) ; le contrôle ne le voit pas, la console du navigateur oui.

## Traductions

`translations/<locale>.json` est un objet plat, clé vers texte, fusionné clé par clé avec les catalogues embarqués `fr` et `en` : un thème ne donne que les textes qu'il change. Les textes sont du texte, pas du HTML ; gardez chaque `%s`.

Clés des pages : `choice.title`, `choice.client` (`%s` : nom du client), `choice.submit`, `choice.invalid`, `choice.none`, `consent.title`, `consent.intro` (`%s` : nom du client), `consent.other`, `consent.nothing`, `consent.audience`, `consent.accept`, `consent.reject`, `error.title`, `error.trace` (`%s` : référence), `error.back`, `error.sign_out`, `error.E1000` à `error.E1008`, `logout.title`, `logout.intro`, `logout.accept`, `logout.reject`, `logout.declined`, `logout.other_session`, `logout.in_progress`, `logout.continue`, `logout.already_out`, `locale.label`, `locale.<code>` (le nom de la locale dans sa propre langue), `scope.openid`, `scope.profile`, `scope.email`, `scope.address`, `scope.phone`, `scope.generic` (`%s` : nom du scope), `claim.sub`, `claim.name`, `claim.family_name`, `claim.given_name`, `claim.preferred_username`, `claim.locale`, `claim.email`, `claim.email_verified`, `claim.address`, `claim.phone_number`, `claim.phone_number_verified`.

Codes d'erreur, un message distinct pour chacun : `E1000`, erreur inattendue ; `E1001`, lien de connexion invalide ; `E1002`, connexion expirée ou déjà terminée ; `E1003`, connexion qui ne correspond pas à la session en cours ; `E1004`, service d'authentification indisponible ; `E1005`, mode de connexion mal configuré ; `E1006`, connexion non finalisée, un service consulté l'ayant refusée ; `E1007`, connexion qui n'a pas pu aboutir ; `E1008`, demande non vérifiée, venue d'un autre site. `locale.<code>` n'est lu que dans le catalogue de sa locale.

Un thème peut :

- ajouter ses propres clés, appelées par ses gabarits (`{{.T "monetab.nom"}}`) : chaque catalogue doit alors les avoir ;
- nommer une donnée métier sur l'écran de consent par `claim.<nom>` (`claim.groups`) ;
- ajouter une locale : `translations/de.json` avec toutes les clés que les pages emploient, et `locale.de`. Elle n'est proposée que si le setting `supported_locales` la nomme ; une locale de `supported_locales` sans catalogue n'est pas proposée, et le journal le dit (`config.warning`).

## Le contrôle

Au démarrage, à chaque relecture de `ui.reload`, et par `theme check`, chaque page est rendue avec des données fictives dans chaque locale du thème, par chacune de ses branches : modes proposés dont un refusé, le dernier mode présélectionné, aucun mode ; consent avec données et destinataires, avec leurs valeurs, sans rien, sans flow ; chaque état du logout ; chaque code d'erreur avec et sans lien, et le lien de déconnexion. Il refuse :

- un gabarit qui ne s'analyse pas ou qui échoue au rendu ;
- une clé de traduction qu'un catalogue n'a pas, même quand `fallback_locale` la fournirait ;
- un formulaire sans les champs que les gestionnaires lisent, ou avec d'autres valeurs ;
- le code que la CSP bloque (plus haut), dit une fois par page.

## Accessibilité

Contraste AA, focus visible sur chaque contrôle, un libellé pour chaque contrôle, `aria-current` sur la locale courante, `role="alert"` sur les messages, des pages lisibles à 360 px de large comme sur un grand écran, sans JavaScript. Une image décorative a `alt=""`.

## Versions du contrat

`api: 1` est le contrat que ce guide décrit. Les ajouts (une donnée, une méthode, une clé) le gardent ; un changement qui casserait un thème existant incrémente la version, et le binaire refuse un thème d'une version qu'il ne prend pas en charge, plutôt que de le servir à moitié.

Une exception : un nouveau texte des pages est un ajout, mais un thème qui apporte une locale entière doit le traduire, et le contrôle refuse ce thème au démarrage tant qu'il ne l'a pas fait. Avant de monter de version, passez `theme check` avec la nouvelle image :

```sh
docker run --rm -v "$PWD/mon-theme:/theme:ro" reg.cadoles.com/cadoles/hydra-dispatcher-go:<nouvelle version> theme check /theme
```
