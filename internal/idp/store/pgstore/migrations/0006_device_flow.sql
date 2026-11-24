-- OAuth 2.0 Device Authorization Grant (RFC 8628).
-- Per-client opt-in, and the table of in-flight device authorization requests.
-- Neither the device code nor the user code is stored, only their sha256 hex.
ALTER TABLE clients ADD COLUMN IF NOT EXISTS device_flow boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS device_codes (
    device_code_hash text PRIMARY KEY,
    user_code_hash   text NOT NULL,
    realm            text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id        text NOT NULL,
    scope            text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    user_id          text NOT NULL DEFAULT '',
    session_id       text NOT NULL DEFAULT '',
    auth_time        timestamptz,
    request_ip       text NOT NULL DEFAULT '',
    request_ua       text NOT NULL DEFAULT '',
    interval_secs    integer NOT NULL,
    last_poll        timestamptz,
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    UNIQUE (realm, user_code_hash)
);
CREATE INDEX IF NOT EXISTS device_codes_expires_idx ON device_codes (expires_at);
