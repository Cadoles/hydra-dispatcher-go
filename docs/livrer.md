# Livrer le dispatcher

Ce document s'adresse à qui déploie le dispatcher : il dit quoi déployer, ce qu'il faut avant, et comment l'installer, le vérifier, le mettre à jour et revenir en arrière. Il suppose lu `comprendre.md` ; la configuration est détaillée dans `configurer.md`, l'exploitation dans `exploiter.md` (à venir). Il ne dit rien de propre à un déploiement donné : chacun documente le sien à côté de ses manifestes.

## Ce qu'on déploie

**Une image**, `reg.cadoles.com/cadoles/hydra-dispatcher-go`, publiée par version (`1.0.0`, et `1.0`, `latest`). Elle contient le binaire `hydra-dispatcher`, sans shell (distroless, utilisateur non root) ; elle écoute sur le port 8080 et se sonde elle-même (`HEALTHCHECK`). Épinglez-la par son digest, et vérifiez sa signature avec la clé publique du dépôt, `cosign.pub` :

```sh
cosign verify --key cosign.pub --insecure-ignore-tlog=true \
  reg.cadoles.com/cadoles/hydra-dispatcher-go@sha256:<digest>
```

(`--insecure-ignore-tlog` : la signature n'est pas inscrite au journal public de transparence, seule la clé fait foi.)

Le même binaire fait tout, par ses sous-commandes : `serve` (le service), `migrate`, `bootstrap`, `admin`, `client`, `config`, `secrets`, `healthcheck`, `theme check`, `version`.

**Les objets**, sur Kubernetes :

- un **Deployment** qui lance `serve`, avec ses sondes : `/health` pour la vie (le processus répond), `/ready` pour la disponibilité. `/ready` répond 200 dès que l'instance sert, et 503 seulement pendant son arrêt. L'état de Hydra, de la base et de Redis figure dans sa réponse, dans le journal et dans la métrique `hydra_dispatcher_ready_check_up`, sans changer le code : une dépendance commune à toutes les instances les retirerait toutes à la fois, alors qu'une instance qui reste sert à l'usager une page d'erreur claire. La sonde doit attendre plus de 2 s, le temps de ces vérifications ;
- un **Job** d'initialisation, joué avant chaque déploiement : `migrate`, puis `bootstrap`. L'image n'ayant pas de shell, ce sont deux conteneurs, `migrate` en init container ;
- un **Service** vers le port 8080 ;
- une **ConfigMap** qui porte `dispatcher.yaml`, montée en lecture seule ;
- un **Secret** pour les clés et le mot de passe de la base, passés en variables d'environnement ou, mieux, en fichiers (`configurer.md`, « Les secrets »).

À l'arrêt (SIGTERM), l'instance répond 503 sur `/ready` pendant `server.drain_delay` tout en servant encore, le temps que Kubernetes la retire du Service ; puis elle laisse 6 s aux requêtes en cours. Sous Kubernetes, poser `drain_delay: 5s`, et un `terminationGracePeriodSeconds` d'au moins `drain_delay` + 10 s.

Le système de fichiers peut être en lecture seule (`readOnlyRootFilesystem`) : le dispatcher n'écrit rien sur disque, sauf un journal d'audit qu'on dirigerait vers un fichier.

Un exemple, à adapter :

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hydra-dispatcher
spec:
  replicas: 2
  template:
    spec:
      # au moins server.drain_delay (5s) + 10 s
      terminationGracePeriodSeconds: 20
      containers:
      - name: hydra-dispatcher
        image: reg.cadoles.com/cadoles/hydra-dispatcher-go@sha256:<digest>
        args: ["serve"]
        ports:
        - { name: http, containerPort: 8080 }
        - { name: metrics, containerPort: 9142 }   # avec observability.metrics.listen: ":9142"
        env:
        - { name: DISPATCHER_CONFIG, value: /etc/hydra-dispatcher/dispatcher.yaml }
        envFrom:
        - secretRef: { name: hydra-dispatcher }
        livenessProbe: { httpGet: { path: /health, port: 8080 }, periodSeconds: 15 }
        readinessProbe: { httpGet: { path: /ready, port: 8080 }, periodSeconds: 5, timeoutSeconds: 3 }
        securityContext: { readOnlyRootFilesystem: true }
        volumeMounts:
        - { name: config, mountPath: /etc/hydra-dispatcher, readOnly: true }
      volumes:
      - name: config
        configMap: { name: hydra-dispatcher }
---
apiVersion: batch/v1
kind: Job
metadata:
  name: hydra-dispatcher-migrate
spec:
  template:
    spec:
      restartPolicy: OnFailure
      initContainers:
      - name: migrate
        image: reg.cadoles.com/cadoles/hydra-dispatcher-go@sha256:<digest>
        args: ["migrate"]
        # les mêmes env, envFrom et volumeMounts que le Deployment
      containers:
      - name: bootstrap
        image: reg.cadoles.com/cadoles/hydra-dispatcher-go@sha256:<digest>
        args: ["bootstrap"]
        # les mêmes env, envFrom et volumeMounts que le Deployment
```

Hors Kubernetes, le principe est le même : `migrate` et `bootstrap` avant chaque démarrage, puis `serve`.

## Ce qu'il faut avant

- **Ory Hydra**, en 2.1 ou en 2.2 :
  - ses URL `urls.login`, `urls.consent` et `urls.logout` pointent vers le dispatcher (sa racine, `/consent`, `/logout`, sous son URL publique) ;
  - son admin API (le port 4445) est joignable depuis le dispatcher, et de préférence de lui seul et des appelants connus (une `NetworkPolicy`) ;
  - en 2.2, donner au dispatcher les `secrets.system` de Hydra lui permet de déchiffrer les challenges lui-même, sans appeler l'admin à chaque requête (`hydra.system_secrets`) ; sans eux, il valide les challenges par l'admin, comme en 2.1.
- **Une base Postgres** : une base et un rôle qui en est propriétaire, que `migrate` remplit. La CI joue Postgres 17.
- **Redis**, ou Dragonfly, dès que le dispatcher tourne en plus d'un exemplaire : les connexions en cours y vivent, partagées. Une instance seule peut garder les siennes en mémoire, perdues à son redémarrage. La CI joue Redis 7 ; hydra-dev, Dragonfly.
- **Les clés**, à générer une fois et à garder secrètes (`configurer.md`, « Les secrets ») : `secrets.cookie_key`, `secrets.challenge_key`, `secrets.encryption_key`, et `secrets.webhook_signing_key` si des webhooks sont configurés. Chacune fait 32 octets :

  ```sh
  openssl rand -hex 32
  ```

  L'admin API signe ses jetons avec une paire de clés (EC P-256, ou RSA) : `admin.api.private_key`.
- **Le réseau** :
  - les adresses des reverse proxies devant le dispatcher (`server.trusted_proxies`), pour qu'il lise l'adresse réelle des navigateurs ;
  - les réseaux d'où les login apps appellent l'API émulée (`security.emulated_api_authorized_hosts`), et les adresses de chaque app (`allowed_sources`).
- **Les login apps**, configurées avec l'URL du dispatcher comme si c'était celle de l'admin de Hydra.

## Installer

1. Créer la base, le rôle et le Secret des clés.
2. Écrire `dispatcher.yaml` : l'infrastructure, puis la graine, les apps et les flows (`configurer.md`).
3. Jouer `migrate`, puis `bootstrap -dry-run`, qui dit ce qu'il écrirait sans rien écrire : relire. Puis `bootstrap`.
4. Créer le premier compte de l'admin, au choix :
   - `hydra-dispatcher bootstrap -create-admin admin -password-file <fichier>`, dans le Job : le compte créé s'il n'existe pas, laissé tel quel sinon ;
   - `hydra-dispatcher admin create <nom> -role admin -password-file <fichier>`.

   Le mot de passe se lit d'un fichier ou de l'entrée standard, jamais d'un argument : la liste des processus montre ceux-là.
5. Créer les clients de l'API d'administration, s'il en faut : `hydra-dispatcher client create <id> -scopes admin:apps,admin:flows`, dont le secret, généré s'il n'est pas donné, n'est affiché qu'une fois. Ou les déclarer dans la graine.
6. Déployer `serve`.

`serve` peut migrer et amorcer lui-même au démarrage (`serve.migrate`, `serve.bootstrap`) : c'est fait pour le développement. En production, le Job le fait, explicitement.

## Vérifier

- `/health` et `/ready` répondent 200.
- Au démarrage, le journal dit le mode de Hydra : `hydra.mode`, `decrypt` (les challenges déchiffrés) ou `fallback` (validés par l'admin de Hydra). Il signale aussi ce qui est accepté mais douteux (`config.warning`), par exemple une allowlist ouverte à tous.
- Une connexion de bout en bout par chaque flow, puis une seconde connexion dans le même navigateur (le skip), puis une déconnexion.
- L'admin : une connexion aux écrans, et `hydra-dispatcher config dump` qui rend la configuration de la base au format de la graine.
- Les métriques (`/metrics`) et les trois journaux (service, accès, audit) ; la latence et la charge de Hydra, face à la mesure de référence.

## Reprendre depuis le dispatcher Symfony

L'outil `symfonyimport` n'est pas dans l'image : il se lance depuis les sources du dépôt, avec Go.

- **La configuration** : `symfonyimport export` lit l'API d'administration du Symfony en marche et écrit les apps, les flows et les réglages au format de la graine, sur la sortie standard ; à relire, puis à donner à `bootstrap`. Un `dispatcher.yaml` du Symfony s'importe aussi directement, une fois ses `%env(VAR)%` réécrits `${VAR}`.

  ```sh
  go run ./tools/symfonyimport export -url https://ancien-dispatcher -client-id <client> -client-secret-file <fichier> > graine.yaml
  ```

- **Les comptes de l'admin et les clients de l'API** : `symfonyimport accounts` les copie de la base du Symfony dans celle du Go, chaque refus nommé avant toute écriture ; un compte ou un client déjà présent est laissé tel quel. `-dry-run` dit ce qu'il écrirait.

  ```sh
  go run ./tools/symfonyimport accounts -config dispatcher.yaml -symfony-dsn-file <fichier> -dry-run
  ```

- **Les variables d'environnement du Symfony** restées dans le conteneur sont lues en repli, avec un avertissement, quand le fichier ne fixe pas la clé correspondante (`configurer.md`, « Les variables du Symfony »).

## Basculer, et revenir en arrière

Le passage du Symfony au Go se fait en place, sans faire tourner les deux à la fois :

1. **Avant** : la nouvelle base, les clés et la configuration du Go prêtes ; le Go prend le même Redis que le Symfony, sous un autre préfixe (`state.key_prefix`), pour que les clés du Symfony restent. Relever aussi une mesure de référence du Symfony (la latence à l'ingress, le volume de connexions, la charge de Hydra) : c'est à elle que se compare le Go ensuite.
2. **Le Job** avec l'image du Go : `migrate`, `bootstrap -dry-run` relu, `bootstrap`, la reprise des comptes et des clients.
3. **Le déploiement** : les mêmes Deployment, Service et Ingress, sans les renommer (un objet renommé est un objet supprimé et recréé, ce qui complique le retour). L'image, le port (8080), les sondes, la configuration et les secrets changent. Avec `strategy: Recreate` pour cette fois : quelques secondes de coupure, et jamais les deux versions sur le trafic en même temps. Hors des heures de pointe.
4. **Une fenêtre de quelques semaines** : les login apps restent sur les chemins v1 de l'API émulée, Hydra reste dans sa version ; la base, l'image, la configuration et les secrets du Symfony sont gardés.
5. **En cas de problème** : redéployer la version d'avant (le revert du changement). Ce qui a été modifié dans l'admin du Go pendant la fenêtre n'est pas reporté au Symfony.

Ce que voient les usagers : ceux qui étaient en pleine connexion recommencent ; ceux qui avaient une session se reconnectent une fois (le Go n'a pas encore sa mémoire du skip). Au retour arrière, de même.

## Mettre à jour

- **Le Job avant le Deployment**, à chaque version : les migrations d'une version ne font qu'ajouter (une colonne, une table) ; ce qu'elles retirent ne l'est qu'à la version suivante. Une instance de la version d'avant tourne donc sans faute sur la base migrée, le temps du déploiement.
- **Revenir à la version d'avant** : `hydra-dispatcher migrate down` avec l'image qu'on retire (elle seule connaît sa dernière migration ; en terminal, elle la nomme et demande confirmation, sauf `-yes`), puis l'image d'avant.
- **Vérifier une graine avant de l'appliquer** : `hydra-dispatcher config diff` dit ce que `bootstrap -force` changerait, en lecture seule (code de sortie 0 rien, 1 des changements, 2 une erreur).

## Après la bascule

- Passer les login apps aux chemins v2 de l'API émulée. Le dispatcher sert l'API émulée sous deux jeux de chemins, sur la même URL de base :
  - v1, ceux de Hydra 1 que le Symfony servait, et qu'appellent les apps configurées pour lui : `/oauth2/auth/requests/login?login_challenge=…`, `/oauth2/auth/requests/login/accept`, de même pour `consent` et `logout` ;
  - v2, ceux de l'admin de Hydra 2, les mêmes sous `/admin` : `/admin/oauth2/auth/requests/login?login_challenge=…`, etc.

  Le passage ne change que la configuration de chaque app, pas son URL de base. Pour les apps qui ont le réglage (hydra-sql-go, hydra-oidc-go, hydra-charter), `HYDRA_API_PATH_PREFIX` passe de `""` à `/admin`, son défaut. hydra-passwordless a ses chemins v1 en dur : il reste en v1 tant qu'il n'a pas ce réglage. On le fait après la fenêtre et pas à la bascule, parce que le Symfony ne sert que les chemins v1 : une app passée en v2 casserait le retour arrière. Les chemins v1 restent servis jusqu'à la version 2.0 du dispatcher (`emulated_api.legacy_v1_paths`) ; le journal signale le premier appel v1 de chaque adresse (`emulated.legacy_path`), ce qui dit quelles apps restent à passer.
- Monter Hydra en 2.2. C'est le point de non-retour : le Symfony refuse les challenges de Hydra 2.2. Poser d'abord `hydra.version: "2.2"` et `hydra.system_secrets` dans la configuration du dispatcher : les challenges de 2.1 passent alors en repli, sans erreur, et le déchiffrement s'enclenche seul avec les premiers challenges de 2.2. Plus généralement, tant que `hydra.version` ne suit pas la version de Hydra, les challenges passent en repli : plus d'appels à Hydra, mais rien ne casse.
- Supprimer la base, l'image, la configuration et les secrets du Symfony ; rendre au Deployment sa stratégie habituelle.

## Prévenir

- **Les usagers** : la coupure, et une reconnexion pour ceux qui avaient une session.
- **Les intégrateurs de l'API d'administration** : leurs jetons sont à redemander après la bascule ; l'API et ses scopes ne changent pas.
- **Les équipes des login apps** : rien à changer à la bascule ; après la fenêtre, le passage aux chemins v2 (`HYDRA_API_PATH_PREFIX=/admin`, voir « Après la bascule »).
