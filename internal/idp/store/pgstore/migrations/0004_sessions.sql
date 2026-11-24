-- SSO sessions: the browser holds a random cookie, only its sha256 is stored.
-- clients lists the client ids that received a code in the session (for
-- back-channel logout). Codes and refresh tokens remember their session.
CREATE TABLE sessions (
    id           text PRIMARY KEY,
    cookie_hash  text NOT NULL UNIQUE,
    realm        text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id      text NOT NULL,
    auth_time    timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    idle_expires timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    ip           text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT '',
    clients      text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL
);
CREATE INDEX sessions_realm_user_idx ON sessions (realm, user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
CREATE INDEX sessions_idle_idx ON sessions (idle_expires);

ALTER TABLE auth_codes ADD COLUMN session_id text NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN session_id text NOT NULL DEFAULT '';
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (realm, session_id);
