-- The catalogue of the scopes (P24): who wrote a row last, as the other
-- tables of the configuration, and the shape of its rows. The column builtin
-- of 00001 stays, unread: a standard scope is the code's (Q125). Additions
-- only (rule of the migrations).

-- +goose Up
ALTER TABLE scope
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN updated_by VARCHAR(180),
  ADD CONSTRAINT scope_name CHECK (name <> '' AND name !~ '[[:space:][:cntrl:]]'),
  ADD CONSTRAINT scope_label CHECK (jsonb_typeof(label) = 'object'),
  ADD CONSTRAINT scope_claims CHECK (jsonb_typeof(claims) = 'array');

-- +goose Down
ALTER TABLE scope
  DROP CONSTRAINT scope_claims,
  DROP CONSTRAINT scope_label,
  DROP CONSTRAINT scope_name,
  DROP COLUMN updated_by,
  DROP COLUMN updated_at;
