-- Shared fixed-window rate limiter (per-IP forgot-password). The key is an
-- opaque hash; no raw identifiers are stored. expires_at = window_start +
-- window so PurgeExpired can remove finished windows.
CREATE TABLE rate_limits (
    key          text PRIMARY KEY,
    window_start timestamptz NOT NULL,
    count        int NOT NULL,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX rate_limits_expires_idx ON rate_limits (expires_at);
