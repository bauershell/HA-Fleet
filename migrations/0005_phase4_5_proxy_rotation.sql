-- Phase 4/5 schema — mirrors 04-data-model.md §2 (grants), §8 (proxy + oauth).
-- In-memory stand-ins in crates/relay/src/proxy.rs; OIDC sessions are not yet
-- implemented (Phase 4 takes the principal in the request body for the demo —
-- SECURITY-TODO.md item 13). Present so the Auth/OIDC service builds against them.

-- Per-(principal→instance) proxy grants, default deny (04 §2, 05 §3) ---------
CREATE TABLE cp_instance_grants (
  grant_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_type text CHECK (subject_type IN ('user','group')),
  subject_id   text NOT NULL,                     -- OIDC sub or group name
  instance_id  uuid REFERENCES instances ON DELETE CASCADE,
  scope        jsonb NOT NULL                     -- {"proxy":true,"read_only":true}
);
CREATE INDEX ON cp_instance_grants (subject_id, instance_id);

-- Short-lived single-consume capability tokens for the IAP (04 §8, 03 §6) ----
CREATE TABLE proxy_tokens (
  token_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  text NOT NULL,                      -- hashed, never plaintext (05 §4)
  principal   text NOT NULL,
  instance_id uuid REFERENCES instances ON DELETE CASCADE,
  scope       jsonb NOT NULL,
  expires_at  timestamptz NOT NULL,               -- short TTL
  consumed    boolean NOT NULL DEFAULT false
);

-- Operator OAuth/OIDC sessions (05 FR-5, 04 §8) ------------------------------
CREATE TABLE oauth_sessions (
  session_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oidc_sub           text NOT NULL,
  refresh_token_hash text,                         -- hashed, never plaintext
  issued_at          timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  revoked            boolean NOT NULL DEFAULT false
);
