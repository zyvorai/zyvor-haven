-- TOTP second factor, recovery codes and the per-realm MFA policy.
-- user_totp.sealed_seed is secretbox ciphertext bound to "totp|realm|user_id";
-- the database never holds a plaintext seed. last_used_step is the replay
-- guard (a code from a step <= it is rejected, updated with a conditional
-- UPDATE so parallel submissions cannot both win). Recovery codes are stored
-- only as sha256 hashes and deleted when used.
CREATE TABLE IF NOT EXISTS user_totp (
    realm          text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id        text NOT NULL,
    sealed_seed    text NOT NULL,
    confirmed      boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL,
    last_used_step bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (realm, user_id)
);

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    user_id    text NOT NULL,
    code_hash  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm, user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS realm_mfa_policy (
    realm       text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    require_mfa boolean NOT NULL DEFAULT false
);

-- Deleting a user removes their MFA rows (users has no child FKs of its own).
CREATE OR REPLACE FUNCTION haven_delete_user_mfa() RETURNS trigger AS $$
BEGIN
    DELETE FROM user_totp WHERE realm = OLD.realm AND user_id = OLD.id;
    DELETE FROM user_recovery_codes WHERE realm = OLD.realm AND user_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_delete_mfa ON users;
CREATE TRIGGER users_delete_mfa AFTER DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION haven_delete_user_mfa();
