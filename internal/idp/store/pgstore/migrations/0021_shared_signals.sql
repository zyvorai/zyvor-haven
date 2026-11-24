-- OpenID Shared Signals Framework transmitter (SSF 1.0, push delivery).
-- Receivers authenticate with a bearer token stored only as sha256 hex.
CREATE TABLE IF NOT EXISTS ssf_receivers (
    id            text PRIMARY KEY,
    realm         text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    name          text NOT NULL,
    audience      text NOT NULL,
    token_hash    text NOT NULL UNIQUE,
    all_subjects  boolean NOT NULL DEFAULT false,
    allow_email   boolean NOT NULL DEFAULT false,
    events        text[] NOT NULL DEFAULT '{}',
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ssf_receivers_name_idx ON ssf_receivers (realm, lower(name));

-- authorization_header is sealed with HAVEN_IDP_SECRET_KEY (never plaintext).
CREATE TABLE IF NOT EXISTS ssf_streams (
    id               text PRIMARY KEY,
    realm            text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    receiver_id      text NOT NULL REFERENCES ssf_receivers(id) ON DELETE CASCADE,
    status           text NOT NULL,
    endpoint_url     text NOT NULL,
    sealed_auth      text NOT NULL DEFAULT '',
    events_requested text[] NOT NULL DEFAULT '{}',
    events_delivered text[] NOT NULL DEFAULT '{}',
    description      text NOT NULL DEFAULT '',
    subject_format   text NOT NULL DEFAULT 'opaque',
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS ssf_streams_receiver_idx ON ssf_streams (receiver_id);
CREATE INDEX IF NOT EXISTS ssf_streams_realm_idx ON ssf_streams (realm);

CREATE TABLE IF NOT EXISTS ssf_subjects (
    stream_id  text NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    user_id    text NOT NULL,
    added_at   timestamptz NOT NULL,
    PRIMARY KEY (stream_id, user_id)
);
CREATE INDEX IF NOT EXISTS ssf_subjects_user_idx ON ssf_subjects (user_id);

CREATE TABLE IF NOT EXISTS ssf_outbox (
    id           text PRIMARY KEY,
    realm        text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    stream_id    text NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    jti          text NOT NULL,
    event_type   text NOT NULL,
    set_jwt      text NOT NULL,
    attempts     integer NOT NULL DEFAULT 0,
    next_attempt timestamptz NOT NULL,
    leased_until timestamptz,
    created_at   timestamptz NOT NULL,
    state        text NOT NULL DEFAULT 'pending',
    last_outcome text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ssf_outbox_due_idx ON ssf_outbox (next_attempt) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS ssf_outbox_stream_idx ON ssf_outbox (stream_id);
