-- OIDC Back-Channel Logout: per-client endpoint that receives logout tokens.
-- Empty = the client is not notified.
ALTER TABLE clients ADD COLUMN backchannel_logout_uri text NOT NULL DEFAULT '';
