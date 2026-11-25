-- Authentication context (amr/acr) and step-up. A realm without a row uses the
-- built-in acr ladder. session_authn records the methods of a login; it is
-- written once per SSO session and disappears with it. Sessions created before
-- this migration have no row, so their tokens carry no amr/acr.
CREATE TABLE IF NOT EXISTS realm_acr_policy (
    realm  text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    policy jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS session_authn (
    session_id text PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    amr        text[] NOT NULL DEFAULT '{}'
);
