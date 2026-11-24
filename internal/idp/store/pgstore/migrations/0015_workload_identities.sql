-- Workload identities: one external (issuer, audience, subject) pinned to one
-- registered client. All three are matched exactly; the token endpoint refuses
-- anything that is not an enabled row here.
CREATE TABLE IF NOT EXISTS workload_identities (
    id             text PRIMARY KEY,
    realm          text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    name           text NOT NULL,
    client_id      text NOT NULL,
    issuer         text NOT NULL,
    jwks_uri       text NOT NULL DEFAULT '',
    jwks           text NOT NULL DEFAULT '',
    audience       text NOT NULL,
    subject        text NOT NULL,
    allowed_scopes text[] NOT NULL DEFAULT '{}',
    ttl_seconds    integer NOT NULL,
    enabled        boolean NOT NULL DEFAULT true,
    created_by     text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    CONSTRAINT workload_identities_name_uq UNIQUE (realm, name),
    CONSTRAINT workload_identities_client_uq UNIQUE (realm, client_id),
    CONSTRAINT workload_identities_keys_ck CHECK ((jwks_uri <> '') <> (jwks <> ''))
);
