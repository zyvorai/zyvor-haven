-- Identity brokering ("Sign in with <upstream OIDC provider>").
-- client_secret_sealed is secretbox output (AES-GCM, bound to idp|realm|alias);
-- the plaintext secret is never stored.
CREATE TABLE IF NOT EXISTS fed_providers (
    realm                text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    alias                text NOT NULL,
    display_name         text NOT NULL DEFAULT '',
    provider_type        text NOT NULL,
    enabled              boolean NOT NULL DEFAULT true,
    trust_email          boolean NOT NULL DEFAULT false,
    config               jsonb NOT NULL DEFAULT '{}',
    client_secret_sealed text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    PRIMARY KEY (realm, alias)
);

-- One row per (provider, upstream subject). Removing the provider or the user
-- removes the link, never the other side.
CREATE TABLE IF NOT EXISTS fed_links (
    realm         text NOT NULL,
    alias         text NOT NULL,
    subject       text NOT NULL,
    user_id       text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mapped_roles  text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL,
    last_login_at timestamptz NOT NULL,
    PRIMARY KEY (realm, alias, subject),
    FOREIGN KEY (realm, alias) REFERENCES fed_providers(realm, alias) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS fed_links_user_idx ON fed_links (realm, user_id);

-- In-flight upstream logins: only hashes of the state and of the browser
-- binding cookie are stored. Single use; expired rows are purged on insert.
CREATE TABLE IF NOT EXISTS fed_login_states (
    state_hash   text PRIMARY KEY,
    realm        text NOT NULL,
    alias        text NOT NULL,
    browser_hash text NOT NULL,
    nonce        text NOT NULL,
    auth_query   text NOT NULL,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS fed_login_states_exp_idx ON fed_login_states (expires_at);
