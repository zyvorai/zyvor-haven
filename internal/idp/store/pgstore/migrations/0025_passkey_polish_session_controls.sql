-- Passkey polish and session controls (docs/passkeys.md, docs/sso-and-logout.md).
-- Everything is off by default: no row means no limit, no "keep me signed in",
-- no passkey-only option and no front-channel logout.

CREATE TABLE IF NOT EXISTS session_policies (
    realm                 text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    max_sessions          integer NOT NULL DEFAULT 0 CHECK (max_sessions BETWEEN 0 AND 1000),
    on_limit              text NOT NULL DEFAULT '' CHECK (on_limit IN ('', 'revoke_oldest', 'deny_new')),
    remember_me           boolean NOT NULL DEFAULT false,
    remember_idle_seconds bigint NOT NULL DEFAULT 0 CHECK (remember_idle_seconds >= 0),
    remember_max_seconds  bigint NOT NULL DEFAULT 0 CHECK (remember_max_seconds >= 0)
);

-- > 0 marks a "keep me signed in" session: its own idle window.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS remember_idle_seconds bigint NOT NULL DEFAULT 0;

-- Realm option "passkey-only for users who have a passkey".
CREATE TABLE IF NOT EXISTS passkey_signin_policies (
    realm        text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    passkey_only boolean NOT NULL DEFAULT false
);

-- Credentials that have completed a sign-in without a password. Deleting the
-- credential deletes the mark.
CREATE TABLE IF NOT EXISTS passkey_passwordless (
    realm         text NOT NULL,
    credential_id text NOT NULL,
    first_used_at timestamptz NOT NULL,
    PRIMARY KEY (realm, credential_id),
    FOREIGN KEY (realm, credential_id) REFERENCES passkeys (realm, credential_id) ON DELETE CASCADE
);

-- OIDC Front-Channel Logout: the client's frontchannel_logout_uri.
CREATE TABLE IF NOT EXISTS client_frontchannel_logout (
    client_uuid text PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    uri         text NOT NULL
);
