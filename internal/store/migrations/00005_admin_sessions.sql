-- When the sessions of an admin account stop (Q120): a logout, a password or a
-- role changed advance it, and a session opened before it is refused. NULL:
-- none stopped yet. An addition only (rule of the migrations).

-- +goose Up
ALTER TABLE admin_user ADD COLUMN sessions_valid_after TIMESTAMPTZ;

-- +goose Down
ALTER TABLE admin_user DROP COLUMN sessions_valid_after;
