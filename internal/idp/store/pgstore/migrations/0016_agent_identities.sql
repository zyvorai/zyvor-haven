-- Agent / MCP identities and their revocable credentials. Credential secrets
-- are stored only as sha256 hex.
CREATE TABLE IF NOT EXISTS agent_identities (
    id             text PRIMARY KEY,
    realm          text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    name           text NOT NULL,
    kind           text NOT NULL DEFAULT 'agent',
    client_id      text NOT NULL,
    owner_user_id  text NOT NULL,
    allowed_scopes text[] NOT NULL DEFAULT '{}',
    allowed_roles  text[] NOT NULL DEFAULT '{}',
    audiences      text[] NOT NULL DEFAULT '{}',
    token_ttl      integer NOT NULL,
    enabled        boolean NOT NULL DEFAULT true,
    created_by     text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    CONSTRAINT agent_identities_name_uq UNIQUE (realm, name),
    CONSTRAINT agent_identities_client_uq UNIQUE (realm, client_id)
);
CREATE INDEX IF NOT EXISTS agent_identities_owner_idx ON agent_identities (realm, owner_user_id);

CREATE TABLE IF NOT EXISTS agent_credentials (
    id           text PRIMARY KEY,
    realm        text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    agent_id     text NOT NULL REFERENCES agent_identities(id) ON DELETE CASCADE,
    secret_hash  text NOT NULL UNIQUE,
    scopes       text[] NOT NULL DEFAULT '{}',
    note         text NOT NULL DEFAULT '',
    created_by   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    revoked_by   text NOT NULL DEFAULT '',
    last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS agent_credentials_agent_idx ON agent_credentials (realm, agent_id);
CREATE INDEX IF NOT EXISTS agent_credentials_expires_idx ON agent_credentials (expires_at);
