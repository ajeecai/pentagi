-- +goose Up
ALTER TYPE FLOW_STATUS ADD VALUE IF NOT EXISTS 'stopped';

-- +goose Down
-- NOTE: PostgreSQL does not support removing enum values directly.
-- To rollback, recreate the type without 'stopped' if needed.
