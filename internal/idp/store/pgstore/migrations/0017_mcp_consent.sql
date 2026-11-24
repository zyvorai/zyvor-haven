-- MCP clients and consent: Client ID Metadata Document (CIMD) clients, the
-- per-realm consent policy, remembered/revocable grants, the client kill
-- switch and hash-chained consent receipts. No secrets are stored here.

CREATE TABLE IF NOT EXISTS consent_policies (
    realm             text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    cimd_enabled      boolean NOT NULL DEFAULT false,
    cimd_hosts        text[] NOT NULL DEFAULT '{}',
    require_all       boolean NOT NULL DEFAULT false,
    skip_clients      text[] NOT NULL DEFAULT '{}',
    remember_cimd     boolean NOT NULL DEFAULT false,
    grant_ttl_seconds integer NOT NULL DEFAULT 0 CHECK (grant_ttl_seconds >= 0)
);

-- Side record of a client materialised from a metadata document.
CREATE TABLE IF NOT EXISTS consent_clients (
    realm         text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id     text NOT NULL,
    source        text NOT NULL DEFAULT 'cimd',
    name          text NOT NULL DEFAULT '',
    client_uri    text NOT NULL DEFAULT '',
    redirect_uris text[] NOT NULL DEFAULT '{}',
    fingerprint   text NOT NULL DEFAULT '',
    fetched_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    PRIMARY KEY (realm, client_id)
);

CREATE TABLE IF NOT EXISTS consent_grants (
    id          text PRIMARY KEY,
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id     text NOT NULL,
    client_id   text NOT NULL,
    client_name text NOT NULL DEFAULT '',
    scopes      text[] NOT NULL DEFAULT '{}',
    resources   text[] NOT NULL DEFAULT '{}',
    fingerprint text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    revoked_by  text NOT NULL DEFAULT ''
);
-- One not-revoked grant per user and client (expired ones are replaced in place).
CREATE UNIQUE INDEX IF NOT EXISTS consent_grants_active_uidx
    ON consent_grants (realm, user_id, client_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS consent_grants_client_idx ON consent_grants (realm, client_id);

CREATE TABLE IF NOT EXISTS consent_blocks (
    realm     text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id text NOT NULL,
    reason    text NOT NULL DEFAULT '',
    blocked_by text NOT NULL DEFAULT '',
    blocked_at timestamptz NOT NULL,
    PRIMARY KEY (realm, client_id)
);

-- Append-only, per-realm hash chain. seq counts from 1; prev_hash links to the
-- previous row's hash. The application never UPDATEs or DELETEs these rows.
CREATE TABLE IF NOT EXISTS consent_receipts (
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    seq         bigint NOT NULL CHECK (seq >= 1),
    created_at  timestamptz NOT NULL,
    type        text NOT NULL,
    user_id     text NOT NULL DEFAULT '',
    client_id   text NOT NULL DEFAULT '',
    client_name text NOT NULL DEFAULT '',
    scopes      text[] NOT NULL DEFAULT '{}',
    resources   text[] NOT NULL DEFAULT '{}',
    actor       text NOT NULL DEFAULT '',
    detail      text NOT NULL DEFAULT '',
    prev_hash   text NOT NULL DEFAULT '',
    hash        text NOT NULL,
    PRIMARY KEY (realm, seq)
);
CREATE INDEX IF NOT EXISTS consent_receipts_user_idx ON consent_receipts (realm, user_id, seq);
