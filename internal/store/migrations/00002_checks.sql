-- The shape the reader takes. A row it cannot read refuses the whole
-- snapshot: at the next refresh, the replicas keep the previous one; at the
-- next start, serve stops. Refused here, at the write, the error goes to
-- whoever wrote. The rules of the domain stay in the code.

-- +goose Up
ALTER TABLE app
  ADD CONSTRAINT app_auth_mode CHECK (auth_mode IN ('network', 'mtls')),
  -- One dimension, no NULL: array_position refuses several dimensions.
  ADD CONSTRAINT app_allowed_sources CHECK (CASE
    WHEN array_ndims(allowed_sources) IS NULL THEN TRUE
    WHEN array_ndims(allowed_sources) > 1 THEN FALSE
    ELSE array_position(allowed_sources, NULL) IS NULL
  END),
  ADD CONSTRAINT app_options CHECK (jsonb_typeof(options) = 'object');
-- A text is an object of locale to string; null stands for no text. Strict:
-- lax would unwrap an array value. Silent: strict errs on a non-object, which
-- jsonb_typeof refuses already.
ALTER TABLE flow
  ADD CONSTRAINT flow_title CHECK (jsonb_typeof(title) = 'object'
    AND NOT jsonb_path_exists(title, 'strict $.* ? (@.type() != "string" && @.type() != "null")', '{}', true)),
  ADD CONSTRAINT flow_description CHECK (jsonb_typeof(description) = 'object'
    AND NOT jsonb_path_exists(description, 'strict $.* ? (@.type() != "string" && @.type() != "null")', '{}', true)),
  ADD CONSTRAINT flow_icon_url CHECK (jsonb_typeof(icon_url) IN ('object', 'null')
    AND NOT jsonb_path_exists(icon_url, 'strict $.* ? (@.type() != "string" && @.type() != "null")', '{}', true));

-- +goose Down
ALTER TABLE flow
  DROP CONSTRAINT flow_icon_url,
  DROP CONSTRAINT flow_description,
  DROP CONSTRAINT flow_title;
ALTER TABLE app
  DROP CONSTRAINT app_options,
  DROP CONSTRAINT app_allowed_sources,
  DROP CONSTRAINT app_auth_mode;
