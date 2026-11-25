-- Account console (docs/account-console.md): a user's own recent security
-- activity is read per (realm, user), so a busy realm cannot push it out of a
-- realm-wide window and the query does not scan the whole audit table.
CREATE INDEX IF NOT EXISTS events_realm_user_time_idx ON events (realm, user_id, time DESC, seq DESC);
