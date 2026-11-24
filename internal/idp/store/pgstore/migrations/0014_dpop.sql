-- DPoP (RFC 9449): proof replay cache and refresh token key binding. Only
-- sha256 hex is stored (never a jti or a token).
CREATE TABLE IF NOT EXISTS dpop_proofs (
    realm      text NOT NULL,
    proof_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (realm, proof_hash)
);
CREATE INDEX IF NOT EXISTS dpop_proofs_expires_idx ON dpop_proofs (expires_at);

CREATE TABLE IF NOT EXISTS dpop_refresh_bindings (
    token_hash text PRIMARY KEY,
    jkt        text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS dpop_refresh_bindings_expires_idx ON dpop_refresh_bindings (expires_at);
