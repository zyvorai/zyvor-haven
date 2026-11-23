CREATE TABLE realms (
    name                        text PRIMARY KEY,
    id                          text NOT NULL UNIQUE,
    display_name                text NOT NULL DEFAULT '',
    enabled                     boolean NOT NULL DEFAULT true,
    self_registration           boolean NOT NULL DEFAULT false,
    email_verification_required boolean NOT NULL DEFAULT false,
    brute_force_protection      boolean NOT NULL DEFAULT false,
    transport_security          text NOT NULL DEFAULT '',
    password_policy             text NOT NULL DEFAULT '',
    access_token_ttl_ns         bigint NOT NULL DEFAULT 0,
    refresh_token_ttl_ns        bigint NOT NULL DEFAULT 0,
    session_idle_ttl_ns         bigint NOT NULL DEFAULT 0,
    auth_events_logged          boolean NOT NULL DEFAULT false,
    admin_events_logged         boolean NOT NULL DEFAULT false,
    refresh_token_rotation      boolean NOT NULL DEFAULT false,
    created_at                  timestamptz NOT NULL
);
CREATE UNIQUE INDEX realms_name_lower_idx ON realms (lower(name));

CREATE TABLE users (
    id              text PRIMARY KEY,
    realm           text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    username        text NOT NULL,
    email           text NOT NULL DEFAULT '',
    first_name      text NOT NULL DEFAULT '',
    last_name       text NOT NULL DEFAULT '',
    enabled         boolean NOT NULL DEFAULT true,
    email_verified  boolean NOT NULL DEFAULT false,
    pending_actions text[] NOT NULL DEFAULT '{}',
    password_hash   text NOT NULL DEFAULT '',
    roles           text[] NOT NULL DEFAULT '{}',
    groups          text[] NOT NULL DEFAULT '{}',
    failed_logins   integer NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL
);
CREATE UNIQUE INDEX users_realm_username_idx ON users (realm, lower(username));

CREATE TABLE clients (
    id              text PRIMARY KEY,
    realm           text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id       text NOT NULL,
    name            text NOT NULL DEFAULT '',
    enabled         boolean NOT NULL DEFAULT true,
    public          boolean NOT NULL DEFAULT false,
    secret_hash     text NOT NULL DEFAULT '',
    redirect_uris   text[] NOT NULL DEFAULT '{}',
    origins         text[] NOT NULL DEFAULT '{}',
    auth_code_flow  boolean NOT NULL DEFAULT false,
    password_flow   boolean NOT NULL DEFAULT false,
    service_account boolean NOT NULL DEFAULT false,
    require_pkce    boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL,
    UNIQUE (realm, client_id)
);

CREATE TABLE roles (
    id          text PRIMARY KEY,
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    UNIQUE (realm, name)
);

CREATE TABLE groups (
    id    text PRIMARY KEY,
    realm text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    name  text NOT NULL,
    path  text NOT NULL,
    UNIQUE (realm, path)
);

CREATE TABLE signing_keys (
    realm       text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    kid         text NOT NULL,
    alg         text NOT NULL,
    private_pem bytea NOT NULL,
    public_jwk  bytea NOT NULL,
    active      boolean NOT NULL DEFAULT false,
    not_after   timestamptz,
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (realm, kid)
);

CREATE TABLE auth_codes (
    code_hash      text PRIMARY KEY,
    realm          text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id      text NOT NULL,
    user_id        text NOT NULL,
    redirect_uri   text NOT NULL,
    scope          text NOT NULL DEFAULT '',
    nonce          text NOT NULL DEFAULT '',
    code_challenge text NOT NULL DEFAULT '',
    challenge_meth text NOT NULL DEFAULT '',
    auth_time      timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL
);
CREATE INDEX auth_codes_expires_idx ON auth_codes (expires_at);

CREATE TABLE refresh_tokens (
    token_hash text PRIMARY KEY,
    family_id  text NOT NULL,
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id  text NOT NULL,
    user_id    text NOT NULL DEFAULT '',
    scope      text NOT NULL DEFAULT '',
    used       boolean NOT NULL DEFAULT false,
    revoked    boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);

CREATE TABLE events (
    seq       bigserial PRIMARY KEY,
    realm     text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    time      timestamptz NOT NULL,
    type      text NOT NULL,
    user_id   text NOT NULL DEFAULT '',
    client_id text NOT NULL DEFAULT '',
    ip        text NOT NULL DEFAULT '',
    detail    text NOT NULL DEFAULT ''
);
CREATE INDEX events_realm_time_idx ON events (realm, time DESC);
