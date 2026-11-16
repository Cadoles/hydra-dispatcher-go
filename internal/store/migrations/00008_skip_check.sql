-- The pre-check of a step (phase 4, P26): an app answers it at its
-- skip_check_url, its requests signed by its skip_check_key, which the column
-- holds encrypted by secrets.encryption_key as an encrypted setting; a step
-- asks for it, a flow names the acr_values it tolerates. Off by default: a
-- database migrated behaves as before. The shape the reader takes only, the
-- rules stay in the code (00002).

-- +goose Up
ALTER TABLE app
  ADD COLUMN skip_check_url TEXT,
  ADD COLUMN skip_check_key TEXT,
  ADD COLUMN skip_check_signals TEXT[] NOT NULL DEFAULT '{}',
  -- One dimension, no NULL item: the reader takes nothing else.
  ADD CONSTRAINT app_skip_check_signals CHECK (CASE
    WHEN array_ndims(skip_check_signals) IS NULL THEN TRUE
    WHEN array_ndims(skip_check_signals) > 1 THEN FALSE
    ELSE array_position(skip_check_signals, NULL) IS NULL
  END);
ALTER TABLE flow
  ADD COLUMN skip_check_allowed_acr TEXT[] NOT NULL DEFAULT '{}',
  ADD CONSTRAINT flow_skip_check_allowed_acr CHECK (CASE
    WHEN array_ndims(skip_check_allowed_acr) IS NULL THEN TRUE
    WHEN array_ndims(skip_check_allowed_acr) > 1 THEN FALSE
    ELSE array_position(skip_check_allowed_acr, NULL) IS NULL
  END);
ALTER TABLE flow_step ADD COLUMN skip_check BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE flow_step DROP COLUMN skip_check;
ALTER TABLE flow
  DROP CONSTRAINT flow_skip_check_allowed_acr,
  DROP COLUMN skip_check_allowed_acr;
ALTER TABLE app
  DROP CONSTRAINT app_skip_check_signals,
  DROP COLUMN skip_check_signals,
  DROP COLUMN skip_check_key,
  DROP COLUMN skip_check_url;
