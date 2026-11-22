package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DispatcherConfig struct {
	PollInterval time.Duration
	BatchSize    int
	Concurrency  int
	SSRF         SSRFConfig
}

func DefaultDispatcherConfig() DispatcherConfig {
	return DispatcherConfig{
		PollInterval: 1 * time.Second,
		BatchSize:    25,
		Concurrency:  5,
		SSRF:         DefaultSSRFConfig(),
	}
}

type Dispatcher struct {
	pool      *pgxpool.Pool
	masterKey []byte
	client    *http.Client
	cfg       DispatcherConfig
	logger    *log.Logger
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewDispatcher(pool *pgxpool.Pool, masterKey []byte, cfg DispatcherConfig, logger *log.Logger) *Dispatcher {
	if len(masterKey) == 0 {
		masterKey = DefaultMasterKey()
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	client := NewSSRFSafeClient(cfg.SSRF)

	return &Dispatcher{
		pool:      pool,
		masterKey: masterKey,
		client:    client,
		cfg:       cfg,
		logger:    logger,
		stopCh:    make(chan struct{}),
	}
}

// Run starts the background dispatcher polling loop.
func (d *Dispatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()

	d.logger.Printf("[WEBHOOKS] Dispatcher started (batch=%d, concurrency=%d)", d.cfg.BatchSize, d.cfg.Concurrency)

	for {
		select {
		case <-ctx.Done():
			d.logger.Printf("[WEBHOOKS] Dispatcher shutting down...")
			d.wg.Wait()
			return ctx.Err()
		case <-d.stopCh:
			d.logger.Printf("[WEBHOOKS] Dispatcher stopped")
			d.wg.Wait()
			return nil
		case <-ticker.C:
			d.dispatchBatch(ctx)
		}
	}
}

// Stop signals the dispatcher to exit.
func (d *Dispatcher) Stop() {
	close(d.stopCh)
	d.wg.Wait()
}

type claimedDelivery struct {
	ID               string
	OrganizationID   string
	EndpointID       string
	EndpointRevision int64
	URL              string
	EncryptedSecret  string
	SigningKeyID     string
	EventID          string
	EventType        string
	RunID            *string
	Payload          []byte
	Attempts         int
	CreatedAt        time.Time
}

// DispatchOnce processes one batch synchronously (useful for integration tests).
func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	return d.dispatchBatch(ctx)
}

func (d *Dispatcher) dispatchBatch(ctx context.Context) (int, error) {
	deliveries, err := d.claimPendingDeliveries(ctx)
	if err != nil {
		d.logger.Printf("[WEBHOOKS] Claim pending deliveries failed: %v", err)
		return 0, err
	}
	if len(deliveries) == 0 {
		return 0, nil
	}

	workCh := make(chan claimedDelivery, len(deliveries))
	for _, item := range deliveries {
		workCh <- item
	}
	close(workCh)

	concurrency := d.cfg.Concurrency
	if concurrency > len(deliveries) {
		concurrency = len(deliveries)
	}

	var batchWg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		batchWg.Add(1)
		go func() {
			defer batchWg.Done()
			for item := range workCh {
				d.executeDelivery(ctx, item)
			}
		}()
	}
	batchWg.Wait()
	return len(deliveries), nil
}

func (d *Dispatcher) claimPendingDeliveries(ctx context.Context) ([]claimedDelivery, error) {
	query := `
		SELECT id::text, organization_id::text, endpoint_id::text, endpoint_revision,
		       url, encrypted_secret, signing_key_id,
		       event_id::text, event_type, run_id::text, payload, attempts, created_at
		FROM app.claim_webhook_deliveries_batch($1::int)
	`

	rows, err := d.pool.Query(ctx, query, d.cfg.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []claimedDelivery
	for rows.Next() {
		var item claimedDelivery
		var runID *string
		var payloadJSON any

		if err := rows.Scan(
			&item.ID, &item.OrganizationID, &item.EndpointID, &item.EndpointRevision,
			&item.URL, &item.EncryptedSecret, &item.SigningKeyID,
			&item.EventID, &item.EventType, &runID, &payloadJSON, &item.Attempts, &item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.RunID = runID

		switch v := payloadJSON.(type) {
		case []byte:
			item.Payload = v
		case string:
			item.Payload = []byte(v)
		default:
			item.Payload, _ = json.Marshal(v)
		}

		items = append(items, item)
	}

	return items, nil
}

func (d *Dispatcher) executeDelivery(ctx context.Context, item claimedDelivery) {
	secret, err := DecryptSecret(item.EncryptedSecret, d.masterKey)
	if err != nil {
		d.markTerminalFailure(ctx, item, 0, fmt.Sprintf("secret decryption failed: %v", err), "")
		return
	}

	timestamp := time.Now().UTC().Unix()
	sigHeader, _ := SignPayload(secret, item.SigningKeyID, timestamp, item.Payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, item.URL, bytes.NewReader(item.Payload))
	if err != nil {
		d.markTerminalFailure(ctx, item, 0, fmt.Sprintf("malformed request: %v", err), "")
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSignature, sigHeader)
	req.Header.Set(HeaderTimestamp, fmt.Sprintf("%d", timestamp))
	req.Header.Set(HeaderKeyID, item.SigningKeyID)
	req.Header.Set(HeaderEvent, item.EventType)
	req.Header.Set(HeaderDelivery, item.ID)

	resp, err := d.client.Do(req)
	if err != nil {
		d.handleNetworkOrTimeoutFailure(ctx, item, err)
		return
	}
	defer resp.Body.Close()

	bodySnippet := readSnippet(resp.Body, 512)
	statusCode := resp.StatusCode

	switch {
	case statusCode >= 200 && statusCode < 300:
		// Success!
		d.markDelivered(ctx, item, statusCode, bodySnippet)

	case statusCode == http.StatusGone: // 410 Gone: auto-disable endpoint (Blueprint §21)
		d.handleEndpointGone(ctx, item, statusCode, bodySnippet)

	case statusCode == http.StatusTooManyRequests || statusCode >= 500:
		// 429 or 5xx: retryable with backoff + jitter up to 1h
		d.scheduleRetry(ctx, item, statusCode, fmt.Sprintf("HTTP %d received", statusCode), bodySnippet)

	default:
		// 3xx (no redirects followed) or other 4xx: terminal failure (Blueprint §21)
		d.markTerminalFailure(ctx, item, statusCode, fmt.Sprintf("HTTP %d terminal error", statusCode), bodySnippet)
	}
}

func (d *Dispatcher) markDelivered(ctx context.Context, item claimedDelivery, statusCode int, snippet string) {
	_, err := d.pool.Exec(ctx, `SELECT app.complete_webhook_delivery($1::uuid, 'DELIVERED'::text, $2::int, NULL::text, $3::text, NULL::timestamptz)`, item.ID, statusCode, snippet)
	if err != nil {
		d.logger.Printf("[WEBHOOKS] Failed marking delivery %s delivered: %v", item.ID, err)
	}
}

func (d *Dispatcher) handleEndpointGone(ctx context.Context, item claimedDelivery, statusCode int, snippet string) {
	_, err := d.pool.Exec(ctx, `SELECT app.disable_webhook_endpoint($1::uuid)`, item.EndpointID)
	if err != nil {
		d.logger.Printf("[WEBHOOKS] Failed disabling endpoint %s: %v", item.EndpointID, err)
	}
	_, err = d.pool.Exec(ctx, `SELECT app.complete_webhook_delivery($1::uuid, 'FAILED'::text, $2::int, 'Endpoint responded with 410 Gone; endpoint disabled'::text, $3::text, NULL::timestamptz)`, item.ID, statusCode, snippet)
	if err != nil {
		d.logger.Printf("[WEBHOOKS] Failed marking 410 delivery %s failed: %v", item.ID, err)
	}
}

func (d *Dispatcher) markTerminalFailure(ctx context.Context, item claimedDelivery, statusCode int, errMsg string, snippet string) {
	var sc *int
	if statusCode > 0 {
		sc = &statusCode
	}
	_, err := d.pool.Exec(ctx, `SELECT app.complete_webhook_delivery($1::uuid, 'FAILED'::text, $2::int, $3::text, $4::text, NULL::timestamptz)`, item.ID, sc, errMsg, snippet)
	if err != nil {
		d.logger.Printf("[WEBHOOKS] Failed marking terminal failure for %s: %v", item.ID, err)
	}
}

func (d *Dispatcher) handleNetworkOrTimeoutFailure(ctx context.Context, item claimedDelivery, dialErr error) {
	d.scheduleRetry(ctx, item, 0, dialErr.Error(), "")
}

func (d *Dispatcher) scheduleRetry(ctx context.Context, item claimedDelivery, statusCode int, errMsg string, snippet string) {
	newAttempts := item.Attempts
	age := time.Since(item.CreatedAt)

	if newAttempts >= MaxAttempts || age >= MaxDeliveryAge {
		// Maximum retry budget exhausted
		d.markTerminalFailure(ctx, item, statusCode, fmt.Sprintf("%s (retry budget exhausted after %d attempts)", errMsg, newAttempts), snippet)
		return
	}

	// Exponential backoff with jitter capped at 1 hour (Blueprint §21)
	baseSeconds := math.Min(3600, 5*math.Pow(2.5, float64(newAttempts-1)))
	jitter := rand.Float64() * (baseSeconds * 0.2)
	delay := time.Duration(baseSeconds+jitter) * time.Second
	if delay > 1*time.Hour {
		delay = 1 * time.Hour
	}
	nextAt := time.Now().Add(delay)

	var sc *int
	if statusCode > 0 {
		sc = &statusCode
	}
	_, err := d.pool.Exec(ctx, `SELECT app.complete_webhook_delivery($1::uuid, 'PENDING'::text, $2::int, $3::text, $4::text, $5::timestamptz)`, item.ID, sc, errMsg, snippet, nextAt)
	if err != nil {
		d.logger.Printf("[WEBHOOKS] Failed updating retry for %s: %v", item.ID, err)
	}
}

func readSnippet(r io.Reader, maxBytes int64) string {
	limitReader := io.LimitReader(r, maxBytes)
	buf, err := io.ReadAll(limitReader)
	if err != nil {
		return ""
	}
	return string(bytes.ToValidUTF8(buf, []byte("?")))
}
