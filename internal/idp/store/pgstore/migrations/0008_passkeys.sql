-- WebAuthn / passkeys. Credential ids and user handles are base64url text.
-- public_key is the original COSE_Key. A credential id is unique per realm.
CREATE TABLE IF NOT EXISTS passkeys (
    realm           text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    credential_id   text NOT NULL,
    user_id         text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      bytea NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    transports      text[] NOT NULL DEFAULT '{}',
    aaguid          text NOT NULL DEFAULT '',
    name            text NOT NULL DEFAULT '',
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state    boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    PRIMARY KEY (realm, credential_id)
);
CREATE INDEX IF NOT EXISTS passkeys_user_idx ON passkeys (realm, user_id);

-- The random opaque id the authenticator stores as "user handle" (never the
-- username or email).
CREATE TABLE IF NOT EXISTS passkey_user_handles (
    realm   text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    handle  text NOT NULL,
    PRIMARY KEY (realm, user_id),
    UNIQUE (realm, handle)
);

-- One-time challenge markers: a captured registration/assertion cannot be
-- verified twice. Only a digest is stored; rows are purged once expired.
CREATE TABLE IF NOT EXISTS passkey_challenges (
    digest     text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS passkey_challenges_expires_idx ON passkey_challenges (expires_at);

CREATE TABLE IF NOT EXISTS passkey_realm_policy (
    realm            text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    require_passkeys boolean NOT NULL DEFAULT false
);
