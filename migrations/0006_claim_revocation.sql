-- Phase hardening — mirrors SECURITY-TODO #9 (claim-code revocation).
-- The 0001 claim_codes table already carries expires_at (TTL); this adds the
-- revocation flag so a leaked-but-unspent code can be killed by the operator
-- (05 §2). Idempotent for re-runs over an already-migrated DB.

ALTER TABLE claim_codes ADD COLUMN IF NOT EXISTS revoked boolean NOT NULL DEFAULT false;
