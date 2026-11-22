package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Ryanakml/Deadbolt/internal/storage"
	"github.com/Ryanakml/Deadbolt/internal/tenant"
)

type Service struct {
	pool      *storage.Pool
	masterKey []byte
	ssrfCfg   SSRFConfig
}

func NewService(pool *storage.Pool, masterKey []byte, ssrfCfg SSRFConfig) *Service {
	if len(masterKey) == 0 {
		masterKey = DefaultMasterKey()
	}
	return &Service{
		pool:      pool,
		masterKey: masterKey,
		ssrfCfg:   ssrfCfg,
	}
}

// CreateEndpoint registers a new webhook endpoint in the environment, generates
// its initial signing secret and key ID, and records an audit event.
func (s *Service) CreateEndpoint(ctx context.Context, orgID, envID, destURL string, eventTypes []string, audit *tenant.AuditContext) (*WebhookEndpoint, string, error) {
	if audit == nil {
		return nil, "", tenant.ErrAuditRequired
	}
	parsedURL, err := ValidateEndpointURL(destURL, s.ssrfCfg)
	if err != nil {
		return nil, "", err
	}
	normalizedURL := parsedURL.String()

	if len(eventTypes) == 0 {
		return nil, "", fmt.Errorf("%w: at least one event type must be specified", ErrInvalidEvent)
	}
	for _, et := range eventTypes {
		if !IsValidEventType(et) {
			return nil, "", fmt.Errorf("%w: %q", ErrInvalidEvent, et)
		}
	}

	secret, keyID := GenerateSecret()
	encSecret, err := EncryptSecret(secret, s.masterKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt webhook secret: %w", err)
	}

	endpointID, _ := tenant.NewUUID()
	var endpoint WebhookEndpoint

	err = s.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO webhook_endpoints (
				id, organization_id, environment_id, url, encrypted_secret, signing_key_id,
				subscribed_events, active, revision, created_at, updated_at
			) VALUES (
				$1::uuid, $2::uuid, $3::uuid, $4, $5, $6,
				$7, true, 1, clock_timestamp(), clock_timestamp()
			)
			RETURNING id::text, organization_id::text, environment_id::text, url, signing_key_id,
			          subscribed_events, active, revision, created_at, updated_at
		`, endpointID, orgID, envID, normalizedURL, encSecret, keyID, eventTypes)

		if err := row.Scan(
			&endpoint.ID, &endpoint.OrganizationID, &endpoint.EnvironmentID, &endpoint.URL,
			&endpoint.SigningKeyID, &endpoint.SubscribedEvents, &endpoint.Active,
			&endpoint.Revision, &endpoint.CreatedAt, &endpoint.UpdatedAt,
		); err != nil {
			return err
		}

		endpoint.EncryptedSecret = encSecret

		return s.recordAudit(ctx, tx, orgID, "webhook_endpoint.created", endpoint.ID, "WEBHOOK_ENDPOINT", map[string]any{
			"url":        normalizedURL,
			"eventTypes": eventTypes,
			"keyId":      keyID,
		}, audit)
	})

	if err != nil {
		return nil, "", err
	}

	return &endpoint, secret, nil
}

// UpdateEndpoint updates configuration with optimistic CAS on expectedRevision.
// If the URL changes, it cancels unsent deliveries for the prior revision.
// If rotateSecret is true, it preserves the previous secret for the 24-hour overlap window.
func (s *Service) UpdateEndpoint(ctx context.Context, orgID, endpointID string, expectedRevision int64, newURL *string, enabled *bool, eventTypes []string, rotateSecret bool, audit *tenant.AuditContext) (*WebhookEndpoint, string, error) {
	if audit == nil {
		return nil, "", tenant.ErrAuditRequired
	}

	var endpoint WebhookEndpoint
	var freshlyGeneratedSecret string

	err := s.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		var currentEncSecret string
		var currentKeyID string
		var prevEncSecret *string
		var prevKeyID *string
		var rotatedAt *time.Time

		err := tx.QueryRow(ctx, `
			SELECT id::text, organization_id::text, environment_id::text, url, encrypted_secret, signing_key_id,
			       previous_encrypted_secret, previous_signing_key_id, rotated_at,
			       subscribed_events, active, revision, created_at, updated_at
			FROM webhook_endpoints
			WHERE id = $1::uuid AND organization_id = $2::uuid
			FOR UPDATE
		`, endpointID, orgID).Scan(
			&endpoint.ID, &endpoint.OrganizationID, &endpoint.EnvironmentID, &endpoint.URL,
			&currentEncSecret, &currentKeyID, &prevEncSecret, &prevKeyID, &rotatedAt,
			&endpoint.SubscribedEvents, &endpoint.Active, &endpoint.Revision,
			&endpoint.CreatedAt, &endpoint.UpdatedAt,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEndpointNotFound
			}
			return err
		}

		if endpoint.Revision != expectedRevision {
			return ErrRevisionConflict
		}

		urlChanged := false
		targetURL := endpoint.URL
		if newURL != nil && *newURL != "" && *newURL != endpoint.URL {
			parsedURL, err := ValidateEndpointURL(*newURL, s.ssrfCfg)
			if err != nil {
				return err
			}
			targetURL = parsedURL.String()
			urlChanged = true
		}

		targetActive := endpoint.Active
		if enabled != nil {
			targetActive = *enabled
		}

		targetEvents := endpoint.SubscribedEvents
		if len(eventTypes) > 0 {
			for _, et := range eventTypes {
				if !IsValidEventType(et) {
					return fmt.Errorf("%w: %q", ErrInvalidEvent, et)
				}
			}
			targetEvents = eventTypes
		}

		targetEncSecret := currentEncSecret
		targetKeyID := currentKeyID
		targetPrevEncSecret := prevEncSecret
		targetPrevKeyID := prevKeyID
		targetRotatedAt := rotatedAt

		if rotateSecret {
			sec, kid := GenerateSecret()
			freshlyGeneratedSecret = sec
			enc, err := EncryptSecret(sec, s.masterKey)
			if err != nil {
				return err
			}
			targetPrevEncSecret = &currentEncSecret
			targetPrevKeyID = &currentKeyID
			now := time.Now().UTC()
			targetRotatedAt = &now
			targetEncSecret = enc
			targetKeyID = kid
		}

		nextRevision := endpoint.Revision + 1

		err = tx.QueryRow(ctx, `
			UPDATE webhook_endpoints
			SET url = $1,
			    active = $2,
			    subscribed_events = $3,
			    encrypted_secret = $4,
			    signing_key_id = $5,
			    previous_encrypted_secret = $6,
			    previous_signing_key_id = $7,
			    rotated_at = $8,
			    revision = $9,
			    updated_at = clock_timestamp()
			WHERE id = $10::uuid AND organization_id = $11::uuid
			RETURNING id::text, organization_id::text, environment_id::text, url, signing_key_id,
			          previous_signing_key_id, rotated_at, subscribed_events, active, revision,
			          created_at, updated_at
		`, targetURL, targetActive, targetEvents, targetEncSecret, targetKeyID,
			targetPrevEncSecret, targetPrevKeyID, targetRotatedAt, nextRevision,
			endpointID, orgID,
		).Scan(
			&endpoint.ID, &endpoint.OrganizationID, &endpoint.EnvironmentID, &endpoint.URL,
			&endpoint.SigningKeyID, &endpoint.PreviousSigningKeyID, &endpoint.RotatedAt,
			&endpoint.SubscribedEvents, &endpoint.Active, &endpoint.Revision,
			&endpoint.CreatedAt, &endpoint.UpdatedAt,
		)
		if err != nil {
			return err
		}
		endpoint.EncryptedSecret = targetEncSecret
		endpoint.PreviousEncryptedSecret = targetPrevEncSecret

		// If URL changed, cancel old unsent deliveries for prior revision (Blueprint §21)
		if urlChanged {
			if _, err := tx.Exec(ctx, `
				UPDATE webhook_deliveries
				SET status = 'CANCELLED',
				    last_error = 'Endpoint URL changed to revision ' || $3::text,
				    completed_at = clock_timestamp()
				WHERE endpoint_id = $1::uuid AND organization_id = $2::uuid
				  AND status = 'PENDING' AND endpoint_revision < $3
			`, endpointID, orgID, nextRevision); err != nil {
				return err
			}
		}

		return s.recordAudit(ctx, tx, orgID, "webhook_endpoint.updated", endpoint.ID, "WEBHOOK_ENDPOINT", map[string]any{
			"url":           targetURL,
			"urlChanged":    urlChanged,
			"enabled":       targetActive,
			"eventTypes":    targetEvents,
			"secretRotated": rotateSecret,
			"revision":      nextRevision,
		}, audit)
	})

	if err != nil {
		return nil, "", err
	}

	return &endpoint, freshlyGeneratedSecret, nil
}

// DeleteEndpoint deletes the webhook endpoint and associated deliveries.
func (s *Service) DeleteEndpoint(ctx context.Context, orgID, endpointID string, expectedRevision int64, audit *tenant.AuditContext) error {
	if audit == nil {
		return tenant.ErrAuditRequired
	}

	return s.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		var currentRevision int64
		err := tx.QueryRow(ctx, `
			SELECT revision FROM webhook_endpoints
			WHERE id = $1::uuid AND organization_id = $2::uuid
			FOR UPDATE
		`, endpointID, orgID).Scan(&currentRevision)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEndpointNotFound
			}
			return err
		}

		if currentRevision != expectedRevision {
			return ErrRevisionConflict
		}

		if _, err := tx.Exec(ctx, `
			DELETE FROM webhook_endpoints
			WHERE id = $1::uuid AND organization_id = $2::uuid
		`, endpointID, orgID); err != nil {
			return err
		}

		return s.recordAudit(ctx, tx, orgID, "webhook_endpoint.deleted", endpointID, "WEBHOOK_ENDPOINT", map[string]any{
			"revision": currentRevision,
		}, audit)
	})
}

// GetEndpoint retrieves a single webhook endpoint.
func (s *Service) GetEndpoint(ctx context.Context, orgID, endpointID string) (*WebhookEndpoint, error) {
	var endpoint WebhookEndpoint
	err := s.pool.WithTenantReadOnlyRepeatableReadTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id::text, organization_id::text, environment_id::text, url, signing_key_id,
			       previous_signing_key_id, rotated_at, subscribed_events, active, revision,
			       created_at, updated_at
			FROM webhook_endpoints
			WHERE id = $1::uuid AND organization_id = $2::uuid
		`, endpointID, orgID).Scan(
			&endpoint.ID, &endpoint.OrganizationID, &endpoint.EnvironmentID, &endpoint.URL,
			&endpoint.SigningKeyID, &endpoint.PreviousSigningKeyID, &endpoint.RotatedAt,
			&endpoint.SubscribedEvents, &endpoint.Active, &endpoint.Revision,
			&endpoint.CreatedAt, &endpoint.UpdatedAt,
		)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEndpointNotFound
		}
		return nil, err
	}
	return &endpoint, nil
}

// ListEndpoints lists webhook endpoints in an environment with cursor pagination.
func (s *Service) ListEndpoints(ctx context.Context, orgID, envID string, limit int, cursor string) ([]WebhookEndpoint, *string, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	var items []WebhookEndpoint
	var nextCursor *string

	err := s.pool.WithTenantReadOnlyRepeatableReadTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		query := `
			SELECT id::text, organization_id::text, environment_id::text, url, signing_key_id,
			       previous_signing_key_id, rotated_at, subscribed_events, active, revision,
			       created_at, updated_at
			FROM webhook_endpoints
			WHERE organization_id = $1::uuid AND environment_id = $2::uuid
		`
		var rows pgx.Rows
		var err error

		if cursor != "" {
			query += ` AND id > $3::uuid ORDER BY id ASC LIMIT $4`
			rows, err = tx.Query(ctx, query, orgID, envID, cursor, limit+1)
		} else {
			query += ` ORDER BY id ASC LIMIT $3`
			rows, err = tx.Query(ctx, query, orgID, envID, limit+1)
		}
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var ep WebhookEndpoint
			if err := rows.Scan(
				&ep.ID, &ep.OrganizationID, &ep.EnvironmentID, &ep.URL,
				&ep.SigningKeyID, &ep.PreviousSigningKeyID, &ep.RotatedAt,
				&ep.SubscribedEvents, &ep.Active, &ep.Revision,
				&ep.CreatedAt, &ep.UpdatedAt,
			); err != nil {
				return err
			}
			items = append(items, ep)
		}

		if len(items) > limit {
			nc := items[limit-1].ID
			nextCursor = &nc
			items = items[:limit]
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	if items == nil {
		items = []WebhookEndpoint{}
	}
	return items, nextCursor, nil
}

// ListDeliveries lists deliveries for a specific endpoint.
func (s *Service) ListDeliveries(ctx context.Context, orgID, endpointID string, limit int, cursor string) ([]WebhookDelivery, *string, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	var items []WebhookDelivery
	var nextCursor *string

	err := s.pool.WithTenantReadOnlyRepeatableReadTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		query := `
			SELECT id::text, organization_id::text, endpoint_id::text, endpoint_revision,
			       event_id::text, event_type, run_id::text, payload, attempts, status,
			       next_at, delivered_at, last_status_code, last_error, response_snippet,
			       created_at, completed_at
			FROM webhook_deliveries
			WHERE organization_id = $1::uuid AND endpoint_id = $2::uuid
		`
		var rows pgx.Rows
		var err error

		if cursor != "" {
			query += ` AND id < $3::uuid ORDER BY created_at DESC, id DESC LIMIT $4`
			rows, err = tx.Query(ctx, query, orgID, endpointID, cursor, limit+1)
		} else {
			query += ` ORDER BY created_at DESC, id DESC LIMIT $3`
			rows, err = tx.Query(ctx, query, orgID, endpointID, limit+1)
		}
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var d WebhookDelivery
			var runID *string
			var payloadBytes []byte

			if err := rows.Scan(
				&d.ID, &d.OrganizationID, &d.EndpointID, &d.EndpointRevision,
				&d.EventID, &d.EventType, &runID, &payloadBytes, &d.Attempts, &d.Status,
				&d.NextAt, &d.DeliveredAt, &d.LastStatusCode, &d.LastError, &d.ResponseSnippet,
				&d.CreatedAt, &d.CompletedAt,
			); err != nil {
				return err
			}
			d.RunID = runID
			_ = json.Unmarshal(payloadBytes, &d.Payload)
			items = append(items, d)
		}

		if len(items) > limit {
			nc := items[limit-1].ID
			nextCursor = &nc
			items = items[:limit]
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	if items == nil {
		items = []WebhookDelivery{}
	}
	return items, nextCursor, nil
}

// Redeliver creates a new delivery attempt for an existing event, pinning the
// endpoint's current active revision (Blueprint §21). If newEndpointID is specified,
// the delivery is routed to the new target endpoint while preserving the original event ID.
func (s *Service) Redeliver(ctx context.Context, orgID, deliveryID string, newEndpointID *string, audit *tenant.AuditContext) (*WebhookDelivery, error) {
	if audit == nil {
		return nil, tenant.ErrAuditRequired
	}

	var newDelivery WebhookDelivery

	err := s.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		var orig WebhookDelivery
		var origPayload []byte
		var origRunID *string

		err := tx.QueryRow(ctx, `
			SELECT endpoint_id::text, event_id::text, event_type, run_id::text, payload
			FROM webhook_deliveries
			WHERE id = $1::uuid AND organization_id = $2::uuid
		`, deliveryID, orgID).Scan(&orig.EndpointID, &orig.EventID, &orig.EventType, &origRunID, &origPayload)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrDeliveryNotFound
			}
			return err
		}

		targetEndpointID := orig.EndpointID
		if newEndpointID != nil && *newEndpointID != "" {
			targetEndpointID = *newEndpointID
		}

		var endpointActive bool
		var currentRevision int64
		err = tx.QueryRow(ctx, `
			SELECT active, revision FROM webhook_endpoints
			WHERE id = $1::uuid AND organization_id = $2::uuid
		`, targetEndpointID, orgID).Scan(&endpointActive, &currentRevision)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEndpointNotFound
			}
			return err
		}

		if !endpointActive {
			return ErrEndpointInactive
		}

		newID, _ := tenant.NewUUID()
		row := tx.QueryRow(ctx, `
			INSERT INTO webhook_deliveries (
				id, organization_id, endpoint_id, endpoint_revision, event_id, event_type,
				run_id, payload, attempts, status, next_at, created_at
			) VALUES (
				$1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6,
				$7, $8, 0, 'PENDING', clock_timestamp(), clock_timestamp()
			)
			RETURNING id::text, organization_id::text, endpoint_id::text, endpoint_revision,
			          event_id::text, event_type, run_id::text, attempts, status, next_at, created_at
		`, newID, orgID, targetEndpointID, currentRevision, orig.EventID, orig.EventType,
			origRunID, origPayload,
		)

		var rID *string
		if err := row.Scan(
			&newDelivery.ID, &newDelivery.OrganizationID, &newDelivery.EndpointID, &newDelivery.EndpointRevision,
			&newDelivery.EventID, &newDelivery.EventType, &rID, &newDelivery.Attempts, &newDelivery.Status,
			&newDelivery.NextAt, &newDelivery.CreatedAt,
		); err != nil {
			return err
		}
		newDelivery.RunID = rID
		_ = json.Unmarshal(origPayload, &newDelivery.Payload)

		return s.recordAudit(ctx, tx, orgID, "webhook_delivery.redelivered", newDelivery.ID, "WEBHOOK_DELIVERY", map[string]any{
			"originalDeliveryId": deliveryID,
			"originalEndpointId": orig.EndpointID,
			"endpointId":         targetEndpointID,
			"revision":           currentRevision,
		}, audit)
	})

	if err != nil {
		return nil, err
	}
	return &newDelivery, nil
}

// EnqueueDeliveryTx inserts delivery intents inside the state-committing transaction (Blueprint §19.1 / §21).
// Result summaries avoid full sensitive payload by default (Blueprint §21).
func (s *Service) EnqueueDeliveryTx(ctx context.Context, tx storage.Tx, orgID, envID, eventType, runID, eventID string, committedAt time.Time, summary map[string]any) error {
	rows, err := tx.Query(ctx, `
		SELECT id::text, revision
		FROM webhook_endpoints
		WHERE organization_id = $1::uuid AND environment_id = $2::uuid
		  AND active = true AND $3 = ANY(subscribed_events)
	`, orgID, envID, eventType)
	if err != nil {
		return err
	}
	defer rows.Close()

	type target struct {
		id       string
		revision int64
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.revision); err != nil {
			return err
		}
		targets = append(targets, t)
	}

	if len(targets) == 0 {
		return nil
	}

	payload := EventPayload{
		ID:             eventID,
		EventType:      eventType,
		EnvironmentID:  envID,
		RunID:          runID,
		PayloadVersion: PayloadVersionV1,
		CommittedAt:    committedAt.UTC().Format(time.RFC3339Nano),
		Summary:        summary,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	for _, tgt := range targets {
		delivID, _ := tenant.NewUUID()
		if _, err := tx.Exec(ctx, `
			INSERT INTO webhook_deliveries (
				id, organization_id, endpoint_id, endpoint_revision, event_id, event_type,
				run_id, payload, attempts, status, next_at, created_at
			) VALUES (
				$1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6,
				$7::uuid, $8, 0, 'PENDING', clock_timestamp(), clock_timestamp()
			)
		`, delivID, orgID, tgt.id, tgt.revision, eventID, eventType, runID, payloadBytes); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) recordAudit(ctx context.Context, tx storage.Tx, orgID, action, targetID, targetType string, details map[string]any, audit *tenant.AuditContext) error {
	if audit == nil {
		audit = &tenant.AuditContext{}
	}
	if details == nil {
		details = make(map[string]any)
	}
	details["actor_type"] = string(audit.ActorType)
	details["actor_role"] = audit.Role
	if len(audit.Capabilities) > 0 {
		details["actor_capabilities"] = audit.Capabilities
	}
	details["actor_scope"] = "organization:" + orgID
	metaBytes, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook audit metadata: %w", err)
	}
	var actorID *string
	if audit.ActorID != nil && *audit.ActorID != "" {
		actorID = audit.ActorID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events (
			organization_id, actor_id, action, target_type, target_id,
			correlation_id, reason, metadata
		) VALUES (
			$1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8
		)
	`, orgID, actorID, action, targetType, targetID, audit.CorrelationID, audit.Reason, metaBytes)
	return err
}
