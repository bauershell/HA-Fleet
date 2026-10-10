-- Phase 0 schema subset — mirrors 04-data-model.md §1.
-- NOT wired into the relay yet: Phase 0 uses an in-memory registry
-- (crates/relay/src/registry.rs). These migrations exist so Phase 1 can swap
-- the in-memory store for sqlx against Cloud SQL with no model change.
--
-- Requires PostgreSQL with pgcrypto for gen_random_uuid().
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Fleet registry (04 §1) ----------------------------------------------------
CREATE TABLE instances (
  instance_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name   text NOT NULL,
  install_type   text NOT NULL CHECK (install_type IN ('core','container','supervised','haos')),
  ha_version     text,
  agent_version  text,
  enroll_state   text NOT NULL DEFAULT 'pending'
                 CHECK (enroll_state IN ('pending','active','revoked')),
  agent_cert_fp  text,                               -- mTLS client cert fingerprint (03 §1a)
  last_heartbeat timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- online/offline is derived (90s window, 03 §1b / 04 §1). A view keeps the
-- rule in one place rather than a STORED generated column referencing now().
CREATE VIEW instance_status AS
  SELECT instance_id,
         CASE WHEN last_heartbeat > now() - interval '90 seconds'
              THEN 'online' ELSE 'offline' END AS status
  FROM instances;

CREATE TABLE capabilities (
  instance_id   uuid REFERENCES instances ON DELETE CASCADE,
  capability    text NOT NULL,                       -- e.g. 'supervisor.backup' (03 §3)
  advertised_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (instance_id, capability)
);

-- Single-use enrollment claim codes (05 §2). Not in 04 as a standalone table;
-- Phase 0 formalizes it here since enrollment is the first thing built.
CREATE TABLE claim_codes (
  code         text PRIMARY KEY,
  display_name text NOT NULL,
  spent        boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL DEFAULT now() + interval '1 hour',
  spent_at     timestamptz
);
