-- Single-use emailed capabilities (verify email, reset password). Only the
-- sha256 hex of the token is stored.
CREATE TABLE action_tokens (
    token_hash text PRIMARY KEY,
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id    text NOT NULL,
    purpose    text NOT NULL,
    email      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX action_tokens_user_idx ON action_tokens (realm, user_id, purpose, created_at);
CREATE INDEX action_tokens_expires_idx ON action_tokens (expires_at);
