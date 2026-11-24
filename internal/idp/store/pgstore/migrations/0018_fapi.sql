-- FAPI building blocks: PAR (RFC 9126), JAR (RFC 9101), RAR (RFC 9396), and the
-- per-client "require PAR / require DPoP" switches. Identifiers and tokens are
-- stored as sha256 hex only.

-- Keyed by the client's internal id: deleting a client deletes its keys and
-- switches, a re-created client_id starts from defaults.
CREATE TABLE IF NOT EXISTS client_fapi (
    client_ref             text PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    realm                  text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    require_par            boolean NOT NULL DEFAULT false,
    require_dpop           boolean NOT NULL DEFAULT false,
    require_signed_request boolean NOT NULL DEFAULT false,
    jwks                   text NOT NULL DEFAULT '',
    authz_detail_types     text[] NOT NULL DEFAULT '{}'
);

-- Pushed requests (kind par) and the login context after redemption (kind ctx).
CREATE TABLE IF NOT EXISTS fapi_requests (
    kind       text NOT NULL,
    id_hash    text NOT NULL,
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id  text NOT NULL,
    params     text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (kind, id_hash)
);
CREATE INDEX IF NOT EXISTS fapi_requests_expires_idx ON fapi_requests (expires_at);

-- authorization_details / dpop_jkt carried from /auth to the tokens.
CREATE TABLE IF NOT EXISTS fapi_bindings (
    kind       text NOT NULL,
    key_hash   text NOT NULL,
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id  text NOT NULL,
    details    text NOT NULL DEFAULT '',
    dpop_jkt   text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (kind, key_hash)
);
CREATE INDEX IF NOT EXISTS fapi_bindings_expires_idx ON fapi_bindings (expires_at);
