-- Time-boxed (just-in-time) role grants. Rows are kept for audit after they
-- end (expired or revoked) and deleted by the purge loop after the retention
-- period; they are NEVER effective once expires_at has passed or revoked_at is
-- set, whether or not the purge has run.
CREATE TABLE IF NOT EXISTS role_grants (
    id               text PRIMARY KEY,
    realm            text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id          text NOT NULL,
    role             text NOT NULL,
    granted_by       text NOT NULL DEFAULT '',
    reason           text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    revoked_by       text NOT NULL DEFAULT '',
    expiry_reported  boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS role_grants_user_idx ON role_grants (realm, user_id, expires_at);
CREATE INDEX IF NOT EXISTS role_grants_expires_idx ON role_grants (expires_at);

-- Per-realm policy for new grants (absent row = defaults: 8h, reason required, any role).
CREATE TABLE IF NOT EXISTS grant_policies (
    realm                text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    max_duration_seconds integer NOT NULL,
    require_reason       boolean NOT NULL,
    allowed_roles        text[] NOT NULL DEFAULT '{}'
);
