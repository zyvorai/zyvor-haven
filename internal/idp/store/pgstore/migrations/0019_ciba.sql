-- CIBA (OpenID Client-Initiated Backchannel Authentication), poll mode.
-- Per-client opt-in (keyed by the client's opaque id, so a deleted and
-- re-created client_id does not inherit it) and the in-flight requests.
-- Neither the auth_req_id nor the approval token is stored, only their sha256 hex.
CREATE TABLE IF NOT EXISTS ciba_clients (
    client_uuid text PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    enabled     boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS ciba_requests (
    auth_req_hash  text PRIMARY KEY,
    approval_hash  text NOT NULL,
    realm          text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id      text NOT NULL,
    user_id        text NOT NULL DEFAULT '',
    scope          text NOT NULL DEFAULT '',
    binding        text NOT NULL DEFAULT '',
    resources      text[] NOT NULL DEFAULT '{}',
    status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    session_id     text NOT NULL DEFAULT '',
    auth_time      timestamptz,
    request_ip     text NOT NULL DEFAULT '',
    interval_secs  integer NOT NULL,
    last_poll      timestamptz,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    UNIQUE (realm, approval_hash)
);
CREATE INDEX IF NOT EXISTS ciba_requests_expires_idx ON ciba_requests (expires_at);
