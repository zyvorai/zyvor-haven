-- SCIM 2.0 server: one bearer token per realm (sha256 hex only) and the
-- provisioning client's externalId per user.
CREATE TABLE IF NOT EXISTS scim_tokens (
    realm      text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    realm_id   text NOT NULL,
    token_hash text NOT NULL,
    read_only  boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS scim_external_ids (
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id text NOT NULL,
    PRIMARY KEY (realm, user_id),
    CONSTRAINT scim_external_ids_uq UNIQUE (realm, external_id)
);
