-- A realm must have exactly one ACTIVE signing key. Two replicas that start at
-- the same moment could each see "no key" and each create one, because the
-- "is there an active key?" check lived in process memory. Enforce it in the
-- database instead, so no number of replicas can race past it.
--
-- Existing data first. Where a realm already has several active keys (this
-- happened on a real two-replica first start), keep the OLDEST active and demote
-- the rest. Demoted keys are only deactivated, never deleted or given an expiry,
-- so tokens they signed keep verifying: they stay published in the JWKS.
UPDATE signing_keys k
   SET active = false
 WHERE k.active
   AND EXISTS (SELECT 1
                 FROM signing_keys o
                WHERE o.realm = k.realm
                  AND o.active
                  AND (o.created_at, o.kid) < (k.created_at, k.kid));

CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active
    ON signing_keys (realm)
 WHERE active;
