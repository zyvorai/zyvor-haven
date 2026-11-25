-- Strong client authentication: private_key_jwt, mutual TLS (RFC 8705) and the
-- replay cache of client assertions. Only sha256 hex of a jti is stored.

-- Keyed by the client's internal id: deleting a client deletes its method and
-- keys, a re-created client_id starts from defaults. Public keys only.
CREATE TABLE IF NOT EXISTS client_auth (
    client_ref        text PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    realm             text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    method            text NOT NULL,
    jwks              text NOT NULL DEFAULT '',
    jwks_uri          text NOT NULL DEFAULT '',
    signing_alg       text NOT NULL DEFAULT '',
    tls_subject_dn    text NOT NULL DEFAULT '',
    tls_san_dns       text NOT NULL DEFAULT '',
    tls_san_uri       text NOT NULL DEFAULT '',
    tls_san_ip        text NOT NULL DEFAULT '',
    tls_san_email     text NOT NULL DEFAULT '',
    cert_bound_tokens boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS client_assertions (
    realm          text NOT NULL,
    assertion_hash text NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (realm, assertion_hash)
);
CREATE INDEX IF NOT EXISTS client_assertions_expires_idx ON client_assertions (expires_at);
