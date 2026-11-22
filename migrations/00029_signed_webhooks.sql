-- +goose Up
-- M5 signed at-least-once webhooks with SSRF-safe dispatch (Issue #39).

-- 1. Extend webhook_endpoints with rotation and key identity tracking
ALTER TABLE webhook_endpoints
    ADD COLUMN IF NOT EXISTS signing_key_id TEXT NOT NULL DEFAULT 'key_1',
    ADD COLUMN IF NOT EXISTS previous_encrypted_secret TEXT,
    ADD COLUMN IF NOT EXISTS previous_signing_key_id TEXT,
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_lookup
    ON webhook_endpoints (organization_id, environment_id, active);

-- 2. Extend webhook_deliveries with revision pinning, error tracking, and cancel status
ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS endpoint_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS run_id UUID,
    ADD COLUMN IF NOT EXISTS last_error TEXT,
    ADD COLUMN IF NOT EXISTS response_snippet TEXT,
    ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;

ALTER TABLE webhook_deliveries DROP CONSTRAINT IF EXISTS webhook_deliveries_status_check;
ALTER TABLE webhook_deliveries ADD CONSTRAINT webhook_deliveries_status_check
    CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED', 'CANCELLED'));

-- Indexes for dispatcher queue and history lookups
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_dispatch
    ON webhook_deliveries (status, next_at)
    WHERE status = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
    ON webhook_deliveries (organization_id, endpoint_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event
    ON webhook_deliveries (organization_id, event_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_run
    ON webhook_deliveries (organization_id, run_id);

-- 3. Security Definer functions for dispatcher cross-tenant queue claiming (RLS bypass)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.claim_webhook_deliveries_batch(p_batch_size INT)
RETURNS TABLE (
    id UUID,
    organization_id UUID,
    endpoint_id UUID,
    endpoint_revision BIGINT,
    url TEXT,
    encrypted_secret TEXT,
    signing_key_id TEXT,
    event_id UUID,
    event_type TEXT,
    run_id UUID,
    payload JSONB,
    attempts INT,
    created_at TIMESTAMPTZ
)
SECURITY DEFINER
SET search_path = app, public, pg_temp
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH picked AS (
        SELECT d.id AS picked_id,
               e.url AS picked_url,
               e.encrypted_secret AS picked_encrypted_secret,
               e.signing_key_id AS picked_signing_key_id
        FROM webhook_deliveries d
        JOIN webhook_endpoints e ON d.endpoint_id = e.id
        WHERE d.status = 'PENDING'
          AND d.next_at <= clock_timestamp()
          AND e.active = true
          AND d.endpoint_revision = e.revision
        ORDER BY d.next_at ASC, d.created_at ASC, d.id ASC
        LIMIT p_batch_size
        FOR UPDATE OF d SKIP LOCKED
    )
    UPDATE webhook_deliveries d
    SET attempts = d.attempts + 1,
        next_at = clock_timestamp() + interval '30 seconds'
    FROM picked
    WHERE d.id = picked.picked_id
    RETURNING d.id, d.organization_id, d.endpoint_id, d.endpoint_revision,
              picked.picked_url, picked.picked_encrypted_secret, picked.picked_signing_key_id,
              d.event_id, d.event_type, d.run_id, d.payload, d.attempts, d.created_at;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.complete_webhook_delivery(
    p_id UUID,
    p_status TEXT,
    p_status_code INT,
    p_last_error TEXT,
    p_snippet TEXT,
    p_next_at TIMESTAMPTZ
)
RETURNS VOID
SECURITY DEFINER
SET search_path = app, public, pg_temp
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE webhook_deliveries
    SET status = p_status,
        last_status_code = p_status_code,
        last_error = p_last_error,
        response_snippet = p_snippet,
        next_at = COALESCE(p_next_at, next_at),
        delivered_at = CASE WHEN p_status = 'DELIVERED' THEN clock_timestamp() ELSE delivered_at END,
        completed_at = CASE WHEN p_status IN ('DELIVERED', 'FAILED', 'CANCELLED') THEN clock_timestamp() ELSE completed_at END
    WHERE id = p_id;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.disable_webhook_endpoint(p_endpoint_id UUID)
RETURNS VOID
SECURITY DEFINER
SET search_path = app, public, pg_temp
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE webhook_endpoints
    SET active = false,
        updated_at = clock_timestamp()
    WHERE id = p_endpoint_id;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION app.claim_webhook_deliveries_batch(INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.complete_webhook_delivery(UUID, TEXT, INT, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.disable_webhook_endpoint(UUID) FROM PUBLIC;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'deadbolt_runtime') THEN
        GRANT EXECUTE ON FUNCTION app.claim_webhook_deliveries_batch(INT) TO deadbolt_runtime;
        GRANT EXECUTE ON FUNCTION app.complete_webhook_delivery(UUID, TEXT, INT, TEXT, TEXT, TIMESTAMPTZ) TO deadbolt_runtime;
        GRANT EXECUTE ON FUNCTION app.disable_webhook_endpoint(UUID) TO deadbolt_runtime;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'deadbolt_system') THEN
        GRANT EXECUTE ON FUNCTION app.claim_webhook_deliveries_batch(INT) TO deadbolt_system;
        GRANT EXECUTE ON FUNCTION app.complete_webhook_delivery(UUID, TEXT, INT, TEXT, TEXT, TIMESTAMPTZ) TO deadbolt_system;
        GRANT EXECUTE ON FUNCTION app.disable_webhook_endpoint(UUID) TO deadbolt_system;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS app.disable_webhook_endpoint(UUID);
DROP FUNCTION IF EXISTS app.complete_webhook_delivery(UUID, TEXT, INT, TEXT, TEXT, TIMESTAMPTZ);
DROP FUNCTION IF EXISTS app.claim_webhook_deliveries_batch(INT);
DROP INDEX IF EXISTS idx_webhook_deliveries_run;
DROP INDEX IF EXISTS idx_webhook_deliveries_event;
DROP INDEX IF EXISTS idx_webhook_deliveries_endpoint;
DROP INDEX IF EXISTS idx_webhook_deliveries_dispatch;

ALTER TABLE webhook_deliveries DROP CONSTRAINT IF EXISTS webhook_deliveries_status_check;
UPDATE webhook_deliveries SET status = 'FAILED' WHERE status = 'CANCELLED';
ALTER TABLE webhook_deliveries ADD CONSTRAINT webhook_deliveries_status_check
    CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED'));

ALTER TABLE webhook_deliveries
    DROP COLUMN IF EXISTS completed_at,
    DROP COLUMN IF EXISTS response_snippet,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS run_id,
    DROP COLUMN IF EXISTS endpoint_revision;

DROP INDEX IF EXISTS idx_webhook_endpoints_lookup;

ALTER TABLE webhook_endpoints
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS rotated_at,
    DROP COLUMN IF EXISTS previous_signing_key_id,
    DROP COLUMN IF EXISTS previous_encrypted_secret,
    DROP COLUMN IF EXISTS signing_key_id;
