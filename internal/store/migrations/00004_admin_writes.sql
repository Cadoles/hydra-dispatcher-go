-- What the writes of the admin record, and the shape of the rows it writes.
-- Additions only: the version before reads the tables after it (rule of the
-- migrations).

-- +goose Up
-- Who wrote a row last: an admin, an API client or bootstrap, as the setting
-- table has it. Bootstrap was the only writer before.
ALTER TABLE app
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN updated_by VARCHAR(180);
ALTER TABLE flow
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN updated_by VARCHAR(180);
ALTER TABLE api_client
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN updated_by VARCHAR(180);
UPDATE app SET updated_by = 'bootstrap';
UPDATE flow SET updated_by = 'bootstrap';
UPDATE api_client SET updated_by = 'bootstrap';

-- An id is a path segment of the admin API, 128 characters at most as for the
-- apps and the flows; the seed never took more.
ALTER TABLE api_client
  ALTER COLUMN id TYPE VARCHAR(128),
  -- One dimension, no NULL: the reader takes nothing else.
  ADD CONSTRAINT api_client_scopes CHECK (CASE
    WHEN array_ndims(scopes) IS NULL THEN TRUE
    WHEN array_ndims(scopes) > 1 THEN FALSE
    ELSE array_position(scopes, NULL) IS NULL
  END);
ALTER TABLE admin_user
  ADD CONSTRAINT admin_user_role CHECK (role IN ('admin', 'viewer'));

-- +goose Down
ALTER TABLE admin_user
  DROP CONSTRAINT admin_user_role;
ALTER TABLE api_client
  DROP CONSTRAINT api_client_scopes,
  ALTER COLUMN id TYPE VARCHAR(256),
  DROP COLUMN updated_by,
  DROP COLUMN updated_at;
ALTER TABLE flow
  DROP COLUMN updated_by,
  DROP COLUMN updated_at;
ALTER TABLE app
  DROP COLUMN updated_by,
  DROP COLUMN updated_at;
