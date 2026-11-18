# Faire tourner les clés

Ce document dit comment changer chaque clé et chaque certificat du dispatcher sans coupure, et quoi faire en cas de fuite. Il suppose lu `configurer.md` (la section `secrets`).

## Le principe

Une clé que le dispatcher relit est un **trousseau** : une clé active, qui chiffre ou signe, et des **précédentes**, qui ne font que déchiffrer ou vérifier. Avec plusieurs instances, une rotation se fait donc en trois déploiements, pour qu'aucune instance ne reçoive ce qu'elle ne sait pas lire :

1. **Distribuer** : ajouter la nouvelle clé aux précédentes, partout. Toutes les instances savent la lire ; aucune ne s'en sert encore.
2. **Promouvoir** : la nouvelle clé devient l'active, l'ancienne passe dans les précédentes. Une instance pas encore redéployée lit quand même ce que les autres écrivent, grâce à l'étape 1.
3. **Retirer** l'ancienne clé, une fois que plus rien de ce qu'elle a scellé ne sert.

Une clé se génère par `openssl rand -hex 32`. Chacune peut se donner par un fichier (`_file`), les précédentes une par ligne.

| Clé | Protège | Précédentes | Retirer l'ancienne après |
| --- | --- | --- | --- |
| `secrets.cookie_key` | les cookies : la mémoire du skip, la session de l'admin, l'appareil de la vérification préalable | `secrets.cookie_keys_previous` | `login_remember_for` (24 h par défaut) ; voir plus bas pour l'appareil |
| `secrets.challenge_key` | les challenges émis aux apps, le marqueur du skip, les challenges de déconnexion | `secrets.challenge_keys_previous` | `challenge_ttl` (1 h) et `hydra.login_consent_ttl` (30 min), le plus long |
| `secrets.encryption_key` | les valeurs secrètes de la configuration en base | `secrets.encryption_keys_previous` | `secrets rekey`, puis `secrets status` sans valeur sous l'ancienne |
| `admin.api.private_key` | les jetons de l'API d'administration | `admin.api.public_keys_previous` (les clés publiques) | `admin.api.token_ttl` (15 min) |
| `secrets.webhook_signing_key` | la signature des webhooks | aucune : les récepteurs acceptent les deux | quand les récepteurs n'acceptent plus que la nouvelle |
| `secrets.audit_key` | les pseudonymes des subjects dans l'audit | aucune | sans objet : les pseudonymes changent |
| `skip_check_key` (par app) | la vérification préalable d'une app | aucune | dans le même mouvement que l'app |
| `hydra.system_secrets` | le déchiffrement des challenges de Hydra | la liste elle-même | avec Hydra, `hydra.login_consent_ttl` après |

## `secrets.cookie_key`

Les trois étapes du principe, avec `secrets.cookie_keys_previous`.

Un cookie scellé par une clé retirée devient illisible ; il n'est pas rescellé par la nouvelle clé quand il est lu. Selon le cookie :

- **la mémoire du skip** : le skip est ignoré, l'usager se reconnecte une fois ;
- **la session de l'admin** : il faut se reconnecter aux écrans ;
- **l'appareil de la vérification préalable**, qui vit 400 jours : le navigateur reçoit un nouvel appareil, et l'app redemande son facteur une fois, puis s'en souvient de nouveau.

Garder l'ancienne clé `login_remember_for` suffit pour la mémoire du skip. Pour ne pas redemander le facteur sur les appareils de confiance, il faudrait la garder aussi longtemps qu'ils durent chez l'app : c'est un choix. Une rotation pour fuite, elle, retire l'ancienne clé tout de suite.

## `secrets.challenge_key`

Les trois étapes, avec `secrets.challenge_keys_previous`. Retirer l'ancienne clé une fois passés `challenge_ttl` et `hydra.login_consent_ttl` : une connexion commencée avant la rotation ne vit pas plus longtemps. Une connexion encore en cours, dont le challenge d'étape a été signé par une clé retirée, échoue, et l'usager recommence.

**Sans `secrets.audit_key`**, les pseudonymes de l'audit sont dérivés de `challenge_key` : sa rotation les change. Poser une `audit_key` avant la première rotation garde les pseudonymes stables.

## `secrets.encryption_key`

Elle chiffre en base les valeurs secrètes de la configuration : le `client_secret` du SSO de l'admin, les `skip_check_key` des apps. Ces valeurs ne vivent pas : il faut les rechiffrer avant de retirer l'ancienne clé. On le fait en quatre étapes :

1. **Distribuer** : la nouvelle clé dans `secrets.encryption_keys_previous`, partout.
2. **Promouvoir** : la nouvelle devient `secrets.encryption_key`, l'ancienne passe dans les précédentes. Les écritures suivantes utilisent la nouvelle.
3. **Rechiffrer** : `hydra-dispatcher secrets rekey` rechiffre par la nouvelle clé, en une transaction, tout ce qu'une précédente avait chiffré. La commande peut se rejouer sans risque.
4. **Vérifier, puis retirer** : `hydra-dispatcher secrets status` liste chaque valeur chiffrée et sa clé. Il finit en code 1 si l'une d'elles n'est tenue par aucune clé de la configuration. Quand plus aucune valeur n'est sous l'ancienne clé, la retirer.

**Ne jamais retirer une clé sous laquelle une valeur est encore chiffrée** : la configuration devient illisible, et une instance qui démarre s'arrête sur l'erreur.

## `admin.api.private_key`

La paire qui signe les jetons de l'API d'administration. Chaque jeton porte le `kid` de sa clé : les 16 premiers caractères hexadécimaux du SHA-256 de la clé publique.

1. **Générer** une paire : EC P-256, ou RSA de 2048 bits au moins.
2. **Distribuer** la nouvelle clé publique dans `admin.api.public_keys_previous`, partout : toutes les instances accepteront les jetons qu'elle signera.
3. **Promouvoir** : la nouvelle paire dans `admin.api.private_key` et `admin.api.public_key`, l'ancienne clé publique dans `public_keys_previous`.
4. **Retirer** l'ancienne clé publique après `admin.api.token_ttl` : les jetons qu'elle a signés ont expiré.

Les clients de l'API redemandent un jeton comme d'habitude : rien ne change pour eux.

## `secrets.webhook_signing_key`

Le dispatcher ne fait que signer : c'est le récepteur qui vérifie (`X-Dispatcher-Signature`, voir le README). Il n'y a pas de clés précédentes. La rotation se fait donc côté récepteurs :

1. **Le récepteur** accepte l'ancienne et la nouvelle clé.
2. **Le dispatcher** passe à la nouvelle clé.
3. **Le récepteur** n'accepte plus que la nouvelle.

Un récepteur qui ne vérifie pas la signature n'a rien à faire : seul le dispatcher change.

## `skip_check_key`, la clé de la vérification préalable

Une clé par app, partagée avec elle : le dispatcher signe sa question, l'app signe sa réponse. Elle est chiffrée en base, et se change :

- côté dispatcher, par l'écran de l'app, par l'API (`PUT /admin/v1/apps/{id}`), ou par la graine (`skip_check_key`, puis `bootstrap -force`) ;
- côté app : `SKIP_CHECK_KEY` pour hydra-passwordless.

Il n'y a pas de clés précédentes. Changer les deux côtés au plus près l'un de l'autre. Entre les deux changements, les signatures ne correspondent plus : la vérification échoue, l'étape se joue normalement, et le facteur est demandé. Rien n'est accordé à tort. `step_skips_total{result}` montre ces échecs.

## `secrets.audit_key`

Elle pseudonymise les subjects du journal d'audit, sans clés précédentes. La changer change tous les pseudonymes à partir de ce moment : un SIEM ne relie plus les lignes d'avant à celles d'après. À planifier avec ses utilisateurs.

## `hydra.system_secrets`, les secrets de Hydra

Avec Hydra 2.2 et plus, le dispatcher déchiffre les challenges avec les `secrets.system` de Hydra : la même liste, dans le même ordre. Elle suit la rotation de Hydra.

1. **Hydra** : la nouvelle clé en tête de `secrets.system`, l'ancienne en second. **Le dispatcher** : la même liste, déployée au même moment.
2. Après `hydra.login_consent_ttl`, retirer l'ancienne clé des deux côtés.

Rien ne casse si le dispatcher n'a pas encore la bonne liste : un challenge qu'il ne sait pas déchiffrer passe par l'admin de Hydra, au prix d'un appel. L'alerte `HydraDispatcherDecryptErrors` le signale. En revanche, Hydra lui-même refuse (404) un challenge scellé par un secret qu'il a retiré de sa liste : l'usager reçoit E1001. D'où l'ancienne clé gardée en second, le temps d'une demande.

## Les certificats

- **L'autorité de Hydra** (`tls.ca_file`) et **celle des webhooks et des apps de vérification** (`webhooks.ca_file`) remplacent les autorités du système pour ces cibles. Pour changer d'autorité, mettre l'ancienne et la nouvelle dans le fichier (plusieurs certificats PEM à la suite), redéployer, changer les certificats des cibles, puis retirer l'ancienne. Un certificat renouvelé par la même autorité ne demande rien.
- **L'épinglage** (`tls.pinned_spki_sha256`) n'est pas encore pris en charge.

## Les autres secrets

- **La base et Redis** : leur mot de passe est dans `store.dsn` et `state.redis_dsn` (ou leurs `_file`), lus au démarrage. Changer le mot de passe côté serveur en gardant l'ancien valide, redéployer le dispatcher, puis retirer l'ancien.
- **Les comptes de l'admin** : `hydra-dispatcher admin update <nom> -password-stdin`, ou l'écran du compte.
- **Les clients de l'API d'administration** : `hydra-dispatcher client update <id> -new-secret`, ou l'écran. Le nouveau secret n'est affiché qu'une fois.
- **Les clients de Hydra** : leur secret se change dans l'écran des clients de Hydra. L'écran signale ceux qui ont dépassé `admin.client_secret_max_age`.

## En cas de fuite

Aller vite plutôt que sans accroc :

- **`cookie_key`, `challenge_key`** : promouvoir la nouvelle clé et retirer l'ancienne dans le même déploiement. Les usagers en pleine connexion recommencent, ceux qui avaient un skip se reconnectent une fois.
- **`encryption_key`** : fusionner les étapes 1 et 2 (quelques erreurs de lecture sur les instances pas encore redéployées), lancer `secrets rekey` aussitôt, vérifier par `secrets status`, retirer l'ancienne clé. Changer aussi les secrets qu'elle protégeait : le `client_secret` du SSO de l'admin chez le fournisseur, les `skip_check_key` avec leurs apps.
- **`admin.api.private_key`** : nouvelle paire, sans garder l'ancienne clé publique. Les jetons en cours sont refusés, et les clients en redemandent.
- **`webhook_signing_key`, `skip_check_key`** : changer les deux côtés tout de suite. Pendant l'écart, les webhooks échouent (E1006) ou les étapes se jouent.
