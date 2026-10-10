-- Phase 3 schema — mirrors 04-data-model.md §3 (templates), §4 (push_jobs),
-- §6 (log_events). In-memory stand-ins in crates/relay/src/{templates,collector}.rs.

CREATE TABLE templates (
  template_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text NOT NULL CHECK (kind IN ('automation','dashboard')),
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE template_versions (
  version_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id uuid REFERENCES templates ON DELETE CASCADE,
  version     int NOT NULL,
  body        jsonb NOT NULL,
  notes       text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (template_id, version)
);

CREATE TABLE template_assignments (
  assignment_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id   uuid REFERENCES templates ON DELETE CASCADE,
  target_type   text CHECK (target_type IN ('instance','label','group')),
  target_ref    text NOT NULL,
  pinned_version int,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE push_jobs (
  job_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id     uuid REFERENCES templates,
  version         int,
  instance_id     uuid REFERENCES instances,
  idempotency_key text NOT NULL UNIQUE,           -- f(version, instance) (03 §7)
  state           text NOT NULL DEFAULT 'queued'
                  CHECK (state IN ('queued','sent','reconciled','drift','failed')),
  detail          jsonb,
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE log_events (
  id          bigserial PRIMARY KEY,
  instance_id uuid REFERENCES instances ON DELETE CASCADE,
  ts          timestamptz NOT NULL,
  level       text,
  source      text,
  message     text,
  attrs       jsonb
);
CREATE INDEX ON log_events (instance_id, ts DESC);
