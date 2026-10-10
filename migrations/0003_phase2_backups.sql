-- Phase 2 schema — mirrors 04-data-model.md §5 (backup metadata).
-- Blobs live in GCS; Postgres holds metadata + the gs:// pointer. Not yet
-- wired (the backup orchestrator's GCS staging is a later integration step);
-- present so the orchestrator can be built against a real table.

CREATE TABLE backups (
  backup_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  instance_id uuid REFERENCES instances ON DELETE CASCADE,
  ha_slug     text,                              -- Supervisor backup slug
  name        text,
  size_bytes  bigint,
  gcs_object  text,                              -- gs://bucket/path (NULL until uploaded)
  sha256      text,
  state       text NOT NULL DEFAULT 'created'
              CHECK (state IN ('created','uploading','stored','restoring','failed')),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON backups (instance_id, created_at DESC);
