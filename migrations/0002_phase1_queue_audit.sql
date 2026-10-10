-- Phase 1 schema — mirrors 04-data-model.md §4 (command_queue) + §7 (audit_log).
-- Still not wired into the relay (in-memory stand-ins in crates/relay/src/
-- {queue.rs,audit.rs}); present so Phase 1→persistence is a data-access swap.

-- Generic command queue for writes to offline instances (04 §4, NFR-OFF-2) ---
CREATE TABLE command_queue (
  cmd_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  instance_id     uuid REFERENCES instances ON DELETE CASCADE,
  op              text NOT NULL,                    -- e.g. 'core.restart' (03 §5)
  args            jsonb NOT NULL,
  idempotency_key text UNIQUE NOT NULL,             -- safe-replay guarantee
  state           text NOT NULL DEFAULT 'queued'
                  CHECK (state IN ('queued','sent','applied','failed')),
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON command_queue (instance_id, created_at);

-- Append-only audit log (04 §7, NFR-SEC-5) ----------------------------------
CREATE TABLE audit_log (
  audit_id      bigserial PRIMARY KEY,
  ts            timestamptz NOT NULL DEFAULT now(),
  actor         text,                               -- OIDC sub; NULL for system/agent
  instance_id   uuid REFERENCES instances ON DELETE SET NULL,
  action        text NOT NULL,                      -- op or admin action
  target        jsonb,
  result        text NOT NULL,                      -- 'ok' | 'error'
  detail        jsonb
);
CREATE INDEX ON audit_log (instance_id, ts DESC);
CREATE INDEX ON audit_log (actor, ts DESC);
