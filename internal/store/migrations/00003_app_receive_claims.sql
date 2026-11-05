-- The options of an app, free JSON of which the code read one key, give way to
-- typed columns. NULL gives the app every claim, an empty list none.

-- +goose Up
ALTER TABLE app ADD COLUMN receive_claims TEXT[];
-- As the code read the option: once present it restricts, so a value that is
-- not a list gives no claim, and an item that is not a string names none.
UPDATE app SET receive_claims = ARRAY(
  SELECT c #>> '{}'
  FROM jsonb_array_elements(CASE jsonb_typeof(options -> 'receive_claims')
    WHEN 'array' THEN options -> 'receive_claims' ELSE '[]' END) AS c
  WHERE jsonb_typeof(c) = 'string'
) WHERE options ? 'receive_claims';
ALTER TABLE app
  DROP CONSTRAINT app_options,
  DROP COLUMN options,
  -- One dimension, no NULL item: the reader takes nothing else.
  ADD CONSTRAINT app_receive_claims CHECK (CASE
    WHEN array_ndims(receive_claims) IS NULL THEN TRUE
    WHEN array_ndims(receive_claims) > 1 THEN FALSE
    ELSE array_position(receive_claims, NULL) IS NULL
  END);

-- +goose Down
ALTER TABLE app ADD COLUMN options JSONB NOT NULL DEFAULT '{}';
UPDATE app SET options = jsonb_build_object('receive_claims', to_jsonb(receive_claims))
  WHERE receive_claims IS NOT NULL;
ALTER TABLE app
  DROP CONSTRAINT app_receive_claims,
  DROP COLUMN receive_claims,
  ADD CONSTRAINT app_options CHECK (jsonb_typeof(options) = 'object');
