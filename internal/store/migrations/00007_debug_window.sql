-- The window of debug of the application log (P25, Q131): one row at most,
-- read with the snapshot as the rest of the configuration, its NOTIFY that of
-- the writes, so that every instance sees it. Past its end, the row stays,
-- unread, until another replaces it. Neither the flow nor the app references
-- its table: a window never holds back a deletion. An addition only (rule of
-- the migrations).

-- +goose Up
CREATE TABLE debug_window (
  id         SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  until      TIMESTAMPTZ NOT NULL,
  flow       VARCHAR(128),
  app        VARCHAR(128),
  trace_id   VARCHAR(32) CHECK (trace_id ~ '^[0-9a-f]{32}$'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by VARCHAR(180)
);

-- +goose Down
DROP TABLE debug_window;
