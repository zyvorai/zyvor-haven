-- OAuth 2.0 Dynamic Client Registration (RFC 7591/7592). Only hashes of the
-- initial access token and the registration access token are stored.
CREATE TABLE IF NOT EXISTS dcr_initial_tokens (
    id         text PRIMARY KEY,
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    note       text NOT NULL DEFAULT '',
    count      integer NOT NULL CHECK (count >= 1),
    remaining  integer NOT NULL CHECK (remaining >= 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS dcr_initial_tokens_realm_idx ON dcr_initial_tokens (realm, created_at);

-- Side record of a client created through the registration endpoint. Deleting
-- the client (Admin API, DELETE registration) removes it, so a reused
-- client_id can never inherit an old registration access token.
CREATE TABLE IF NOT EXISTS dcr_clients (
    realm            text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id        text NOT NULL,
    client_uuid      text NOT NULL UNIQUE REFERENCES clients(id) ON DELETE CASCADE,
    reg_token_hash   text NOT NULL,
    created_via      text NOT NULL DEFAULT 'dcr',
    initial_token_id text NOT NULL DEFAULT '',
    application_type text NOT NULL DEFAULT 'web',
    token_auth_method text NOT NULL DEFAULT '',
    scope            text NOT NULL DEFAULT '',
    grant_types      text[] NOT NULL DEFAULT '{}',
    contacts         text[] NOT NULL DEFAULT '{}',
    logo_uri         text NOT NULL DEFAULT '',
    client_uri       text NOT NULL DEFAULT '',
    policy_uri       text NOT NULL DEFAULT '',
    tos_uri          text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    PRIMARY KEY (realm, client_id)
);

CREATE TABLE IF NOT EXISTS dcr_policies (
    realm               text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    max_clients         integer NOT NULL CHECK (max_clients >= 0),
    allowed_grant_types text[] NOT NULL DEFAULT '{}'
);
