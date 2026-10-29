-- The schema of the design document: configuration only, the flows in
-- progress live in the state store.

-- +goose Up
CREATE TABLE app (
  id          VARCHAR(128) PRIMARY KEY,
  login_url   TEXT NOT NULL,
  consent_url TEXT NOT NULL,
  logout_url  TEXT,
  method      VARCHAR(64) NOT NULL,
  auth_mode   VARCHAR(16) NOT NULL DEFAULT 'network',  -- network | mtls
  allowed_sources CIDR[] NOT NULL DEFAULT '{}',
  client_cert_fingerprint TEXT,
  options     JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE flow (
  id          VARCHAR(128) PRIMARY KEY,
  title       JSONB NOT NULL DEFAULT '{}',
  description JSONB NOT NULL DEFAULT '{}',
  icon_url    JSONB,
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  acr         VARCHAR(255)
);
CREATE TABLE flow_step (
  flow_id  VARCHAR(128) NOT NULL REFERENCES flow(id) ON DELETE CASCADE,
  app_id   VARCHAR(128) NOT NULL REFERENCES app(id) ON DELETE RESTRICT,
  position INTEGER NOT NULL,
  subject_check VARCHAR(128) NOT NULL DEFAULT 'none',
  PRIMARY KEY (flow_id, position),
  UNIQUE (flow_id, app_id)
);
CREATE TABLE setting (
  key        VARCHAR(128) PRIMARY KEY,      -- ex. consent_auto_accept, admin_oidc.issuer
  value      JSONB NOT NULL,                 -- typed value; secrets encrypted
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by VARCHAR(180)                    -- admin, API client or bootstrap
);
CREATE TABLE scope (
  name    VARCHAR(128) PRIMARY KEY,
  label   JSONB NOT NULL DEFAULT '{}',   -- locale -> label of the scope
  claims  JSONB NOT NULL DEFAULT '[]',   -- [{claim, label: {locale: text}}]
  builtin BOOLEAN NOT NULL DEFAULT FALSE -- standard OIDC scopes, given by default
);
CREATE TABLE admin_user (
  id SERIAL PRIMARY KEY, username VARCHAR(180) UNIQUE NOT NULL,
  password_hash TEXT, oidc_sub VARCHAR(255) UNIQUE, role VARCHAR(16) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE api_client (
  id VARCHAR(256) PRIMARY KEY, secret_hash TEXT NOT NULL,
  scopes TEXT[] NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE api_client;
DROP TABLE admin_user;
DROP TABLE scope;
DROP TABLE setting;
DROP TABLE flow_step;
DROP TABLE flow;
DROP TABLE app;
