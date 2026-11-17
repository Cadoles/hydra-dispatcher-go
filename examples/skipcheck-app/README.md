# skipcheck-app

The reference app of the pre-check of a step (phase 4): a second factor that
remembers a device, so that the dispatcher can skip its step at the next
login, server to server, without sending the browser to it. Its package `app`
is what the exit test of the extension runs
(`cmd/hydra-dispatcher/skipcheck_test.go`); this command serves it.

```
app/app.go     the step, the devices, the pre-check
app/app_test.go
main.go        the flags; the key from SKIPCHECK_APP_KEY, never an argument
```

## Its configuration in the dispatcher

```yaml
apps:
  - id: otp
    login_url: http://otp.example/login
    consent_url: http://otp.example/consent
    method: otp
    skip_check_url: http://otp.example/skip-check
    skip_check_key: ${OTP_SKIP_CHECK_KEY}   # 32 bytes, hex or base64
    skip_check_signals: [user_agent]
flows:
  - id: password-otp
    steps:
      - { id: sql, order: 0 }
      - { id: otp, order: 1, subject_check: equal, skip_check: true }
```

Never on a first step: the device alone would authenticate. `http://` needs
`tls.allow_http`.

```sh
SKIPCHECK_APP_KEY=<the same key> go run ./examples/skipcheck-app \
  -listen :8090 -admin-url http://dispatcher:8080 -code 123456
```

`-admin-url` is the dispatcher's emulated API, as Hydra's admin URL is to an
app; the app's address must be in its `allowed_sources`. Served over HTTPS, behind a proxy that ends TLS too,
`-secure-cookies` marks the cookie of its forms' token `Secure`.

## What it does

**The step.** `GET /login?login_challenge=` reads the login request, which
carries `x_dispatcher_device`, the browser's device for this app (an HMAC of
the device cookie by the app's id: another app sees another value). The page
asks the code and offers "Remember this device" when the request has a device.
`POST /login` reads the request again (the form only says which), checks the
code, accepts; remembered, the device is recorded for the subject until a date
the accept declares, `context.x_dispatcher_remember_until`, which the
dispatcher logs (`device.remembered`).

**The devices.** The step's page lists the subject's trusted devices, each with
a button that revokes it (`POST /revoke`, the form's token required). Clearing
the device cookie in the browser revokes them all at once: the dispatcher draws
another device.

**The pre-check.** `POST /skip-check`, which the dispatcher signs as its
webhooks: `X-Dispatcher-Timestamp`, and `X-Dispatcher-Signature`, the hex of
HMAC-SHA256 by the app's key of `timestamp + "." + body`. The app refuses a
request out of 5 minutes, or not signed by its key, with a 4xx, and the
dispatcher runs the step. The body:

```json
{"version": 1, "nonce": "…", "subject": "alice", "device": "…", "client_id": "…",
 "flow": "password-otp", "step": "otp", "claims": {}, "signals": {"user_agent": "…"},
 "attestation": null}
```

It answers skip for a device recorded for the subject, not expired, and, with
the `user_agent` signal, of the browser that enrolled it. The answer is JSON,
the nonce back, signed by the same key over `"response." + timestamp + "." +
body`, so that a request sent back as it came never passes for an answer:

```json
{"nonce": "…", "skip": true}
```

It may carry `subject`, `context`, `id_token` and `access_token`, as the step's
login and consent accepts would; the `amr` stays the app's `method`.

The dispatcher calls the app only for a step after the first, with a device,
without `prompt=login`, without `max_age`, and under `acr_values` the flow's
`skip_check_allowed_acr` admits; it waits 300 ms at most, and any failure runs
the step. The accept of a login whose step was skipped names it in its context,
`x_dispatcher_skipped_steps`, to tell a factor remembered from a factor typed:
the webhooks receive it; the client sees it only if the consent webhook makes a
claim of it, Hydra keeping a login's context out of the tokens.

## Before production

The devices live in memory: an app of production keeps them with the user's
account, lists them on the user's own pages, and revokes them all when the
factor changes (a new OTP secret, a password reset). It applies its own risk
rules with the signals it declares (`ip` truncated, `client_hints`,
`accept_language`, `device_age`), keeps them only for this use, and decides how
long a device stays trusted: the dispatcher does not cap it.
