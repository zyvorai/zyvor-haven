-- Login fallback flag, risk-based step-up policy and known devices.
-- A realm without a row has everything off (the behaviour before this
-- migration). known_devices.device_hash is the sha256 of a random browser
-- cookie, never the cookie; ip_hash is a salted hash of a network prefix.
CREATE TABLE IF NOT EXISTS realm_stepup_policy (
    realm                    text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    allow_fallback           boolean NOT NULL DEFAULT false,
    enabled                  boolean NOT NULL DEFAULT false,
    enforce                  boolean NOT NULL DEFAULT false,
    on_new_device            boolean NOT NULL DEFAULT false,
    on_ip_change             boolean NOT NULL DEFAULT false,
    idle_after_seconds       bigint  NOT NULL DEFAULT 0,
    on_max_age               boolean NOT NULL DEFAULT false,
    sensitive_scopes         text[]  NOT NULL DEFAULT '{}',
    sensitive_auth_max_age_seconds bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS known_devices (
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash text NOT NULL,
    ip_hash     text NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    PRIMARY KEY (realm, user_id, device_hash)
);
CREATE INDEX IF NOT EXISTS known_devices_user_idx ON known_devices (realm, user_id, last_seen DESC);
