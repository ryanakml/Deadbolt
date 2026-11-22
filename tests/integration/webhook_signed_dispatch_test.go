package integration_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Ryanakml/Deadbolt/internal/execution"
	"github.com/Ryanakml/Deadbolt/internal/storage"
	"github.com/Ryanakml/Deadbolt/internal/tenant"
	"github.com/Ryanakml/Deadbolt/internal/webhooks"
)

func setupWebhookTestContext(t *testing.T) (*tenantTestContext, string, string) {
	t.Helper()
	tc := setupTenantContext(t)
	ctx := context.Background()

	// Guarantee clean test table state across runs using migrator connection (BYPASSRLS)
	_, _ = tc.database.Exec("TRUNCATE webhook_deliveries, webhook_endpoints CASCADE;")

	org, err := tc.service.CreateOrganization(ctx, newUUID(t), "Webhook Org")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	proj, err := tc.service.CreateProject(ctx, org.ID, "Webhook Proj")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := tc.service.CreateEnvironment(ctx, org.ID, proj.ID, tenant.EnvStaging, 10)
	if err != nil {
		t.Fatalf("create environment: %v", err)
	}

	return tc, org.ID, env.ID
}

func TestWebhookSignedDispatchSuccess(t *testing.T) {
	t.Setenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING", "true")
	tc, orgID, envID := setupWebhookTestContext(t)
	defer tc.cleanup()

	var mu sync.Mutex
	var receivedHeaders http.Header
	var receivedBody []byte
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requestCount++
		receivedHeaders = r.Header.Clone()
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	ctx := context.Background()
	masterKey := webhooks.DefaultMasterKey()
	ssrfCfg := webhooks.DefaultSSRFConfig()
	svc := webhooks.NewService(tc.pool, masterKey, ssrfCfg)

	audit := &tenant.AuditContext{
		ActorType:     tenant.IdentityTypeMachine,
		CorrelationID: "webhook-test",
	}

	// 1. Create endpoint
	endpoint, secret, err := svc.CreateEndpoint(ctx, orgID, envID, server.URL, []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if secret == "" {
		t.Fatal("expected raw secret on endpoint creation")
	}
	if endpoint.SigningKeyID == "" {
		t.Fatal("expected signing key id on endpoint creation")
	}

	// 2. Enqueue delivery intent atomically in a tenant transaction
	runID := newUUID(t)
	eventID := newUUID(t)
	payload := map[string]any{
		"event":  "run.succeeded",
		"runId":  runID,
		"status": "SUCCEEDED",
	}
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return svc.EnqueueDeliveryTx(ctx, tx, orgID, envID, "run.succeeded", runID, eventID, time.Now(), payload)
	}); err != nil {
		t.Fatalf("enqueue delivery: %v", err)
	}

	// 3. Dispatch
	cfg := webhooks.DefaultDispatcherConfig()
	dispatcher := webhooks.NewDispatcher(tc.runtimePool, masterKey, cfg, nil)

	dispatched, err := dispatcher.DispatchOnce(ctx)
	if err != nil {
		t.Fatalf("dispatch once: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("expected 1 dispatched delivery, got %d", dispatched)
	}

	// 4. Verify received webhook
	mu.Lock()
	defer mu.Unlock()
	if requestCount != 1 {
		t.Fatalf("expected 1 request received by server, got %d", requestCount)
	}

	sigHeader := receivedHeaders.Get("X-Deadbolt-Signature")
	if sigHeader == "" {
		t.Fatal("expected X-Deadbolt-Signature header")
	}
	keyIDHeader := receivedHeaders.Get("X-Deadbolt-Key-ID")
	if keyIDHeader != endpoint.SigningKeyID {
		t.Fatalf("expected X-Deadbolt-Key-ID %q, got %q", endpoint.SigningKeyID, keyIDHeader)
	}
	eventHeader := receivedHeaders.Get("X-Deadbolt-Event")
	if eventHeader != "run.succeeded" {
		t.Fatalf("expected X-Deadbolt-Event run.succeeded, got %q", eventHeader)
	}

	// Verify HMAC-SHA256 signature with receiver verification helper
	if err := webhooks.VerifyHeader(secret, receivedBody, sigHeader, 5*time.Minute); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// 5. Verify database delivery record state
	var status string
	var attempts int
	var lastStatus int
	var completedAt *time.Time
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT status, attempts, last_status_code, completed_at
			FROM webhook_deliveries
			WHERE event_id = $1::uuid AND endpoint_id = $2::uuid
		`, eventID, endpoint.ID).Scan(&status, &attempts, &lastStatus, &completedAt)
	}); err != nil {
		t.Fatalf("query delivery: %v", err)
	}

	if status != "DELIVERED" {
		t.Fatalf("expected status DELIVERED, got %s", status)
	}
	if attempts != 1 {
		t.Fatalf("expected attempts 1, got %d", attempts)
	}
	if lastStatus != 200 {
		t.Fatalf("expected lastStatus 200, got %d", lastStatus)
	}
	if completedAt == nil {
		t.Fatal("expected completedAt to be set")
	}
}

func TestWebhookKeyRotationOverlap(t *testing.T) {
	t.Setenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING", "true")
	tc, orgID, envID := setupWebhookTestContext(t)
	defer tc.cleanup()

	var mu sync.Mutex
	var lastReceivedBody []byte
	var lastReceivedSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		lastReceivedSig = r.Header.Get("X-Deadbolt-Signature")
		lastReceivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	masterKey := webhooks.DefaultMasterKey()
	ssrfCfg := webhooks.DefaultSSRFConfig()
	svc := webhooks.NewService(tc.pool, masterKey, ssrfCfg)
	audit := &tenant.AuditContext{ActorType: tenant.IdentityTypeMachine}

	// 1. Create endpoint
	endpoint, oldSecret, err := svc.CreateEndpoint(ctx, orgID, envID, server.URL, []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	oldKeyID := endpoint.SigningKeyID

	// 2. Rotate secret
	updated, newSecret, err := svc.UpdateEndpoint(ctx, orgID, endpoint.ID, endpoint.Revision, nil, nil, nil, true, audit)
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	if updated.Revision != 2 {
		t.Fatalf("expected revision 2, got %d", updated.Revision)
	}
	if updated.SigningKeyID == oldKeyID {
		t.Fatal("expected new signing key ID after rotation")
	}
	if newSecret == oldSecret {
		t.Fatal("expected new secret after rotation")
	}

	// 3. Enqueue and dispatch with new secret
	runID := newUUID(t)
	eventID := newUUID(t)
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return svc.EnqueueDeliveryTx(ctx, tx, orgID, envID, "run.succeeded", runID, eventID, time.Now(), map[string]any{"data": 123})
	}); err != nil {
		t.Fatalf("enqueue delivery: %v", err)
	}

	dispatcher := webhooks.NewDispatcher(tc.runtimePool, masterKey, webhooks.DefaultDispatcherConfig(), nil)
	dispatched, err := dispatcher.DispatchOnce(ctx)
	if err != nil || dispatched != 1 {
		t.Fatalf("dispatch once: err=%v dispatched=%d", err, dispatched)
	}

	// 4. Verify receiver verification with new secret
	mu.Lock()
	body := lastReceivedBody
	sig := lastReceivedSig
	mu.Unlock()

	if err := webhooks.VerifyHeader(newSecret, body, sig, 5*time.Minute); err != nil {
		t.Fatalf("verification with new secret failed: %v", err)
	}

	// Verification with old secret must fail for this new payload
	if err := webhooks.VerifyHeader(oldSecret, body, sig, 5*time.Minute); err == nil {
		t.Fatal("verification with old secret should have failed for payload signed with new secret")
	}

	parsedSig, err := webhooks.ParseSignatureHeader(sig)
	if err != nil {
		t.Fatalf("parse signature header: %v", err)
	}
	if parsedSig.KeyID != updated.SigningKeyID {
		t.Fatalf("expected key id %s in signature, got %s", updated.SigningKeyID, parsedSig.KeyID)
	}
}

func TestWebhookRetryBackoffAndTerminalStatus(t *testing.T) {
	t.Setenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING", "true")
	tc, orgID, envID := setupWebhookTestContext(t)
	defer tc.cleanup()

	var mu sync.Mutex
	statusCode := http.StatusInternalServerError

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		code := statusCode
		mu.Unlock()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error": "mock error"}`))
	}))
	defer server.Close()

	ctx := context.Background()
	masterKey := webhooks.DefaultMasterKey()
	ssrfCfg := webhooks.DefaultSSRFConfig()
	svc := webhooks.NewService(tc.pool, masterKey, ssrfCfg)
	audit := &tenant.AuditContext{ActorType: tenant.IdentityTypeMachine}

	endpoint, _, err := svc.CreateEndpoint(ctx, orgID, envID, server.URL, []string{"run.failed"}, audit)
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}

	runID := newUUID(t)
	eventID1 := newUUID(t)
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return svc.EnqueueDeliveryTx(ctx, tx, orgID, envID, "run.failed", runID, eventID1, time.Now(), map[string]any{"err": "fail"})
	}); err != nil {
		t.Fatalf("enqueue delivery: %v", err)
	}

	dispatcher := webhooks.NewDispatcher(tc.runtimePool, masterKey, webhooks.DefaultDispatcherConfig(), nil)

	// Step 1: Dispatch to 500 endpoint -> triggers retry backoff
	dispatched, err := dispatcher.DispatchOnce(ctx)
	if err != nil || dispatched != 1 {
		t.Fatalf("dispatch once: err=%v dispatched=%d", err, dispatched)
	}

	var status string
	var attempts int
	var lastStatus int
	var nextAt time.Time
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT status, attempts, last_status_code, next_at
			FROM webhook_deliveries
			WHERE event_id = $1::uuid
		`, eventID1).Scan(&status, &attempts, &lastStatus, &nextAt)
	}); err != nil {
		t.Fatalf("query delivery: %v", err)
	}

	if status != "PENDING" {
		t.Fatalf("expected PENDING status after 500, got %s", status)
	}
	if attempts != 1 {
		t.Fatalf("expected attempts 1, got %d", attempts)
	}
	if lastStatus != 500 {
		t.Fatalf("expected lastStatus 500, got %d", lastStatus)
	}
	if !nextAt.After(time.Now()) {
		t.Fatalf("expected next_at in the future for retry backoff, got %v", nextAt)
	}

	// Step 2: 410 Gone terminal failure -> auto-disables endpoint
	mu.Lock()
	statusCode = http.StatusGone
	mu.Unlock()

	// Reset next_at to past so it can be claimed immediately
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET next_at = clock_timestamp() - interval '1 second' WHERE event_id = $1::uuid`, eventID1)
		return err
	}); err != nil {
		t.Fatalf("reset next_at: %v", err)
	}

	dispatched, err = dispatcher.DispatchOnce(ctx)
	if err != nil || dispatched != 1 {
		t.Fatalf("dispatch once after 410: err=%v dispatched=%d", err, dispatched)
	}

	// Verify delivery is FAILED and endpoint is disabled
	var active bool
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT status, attempts, last_status_code FROM webhook_deliveries WHERE event_id = $1::uuid`, eventID1).Scan(&status, &attempts, &lastStatus); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT active FROM webhook_endpoints WHERE id = $1::uuid`, endpoint.ID).Scan(&active)
	}); err != nil {
		t.Fatalf("query status: %v", err)
	}

	if status != "FAILED" {
		t.Fatalf("expected status FAILED after 410, got %s", status)
	}
	if attempts != 2 {
		t.Fatalf("expected attempts 2, got %d", attempts)
	}
	if lastStatus != 410 {
		t.Fatalf("expected lastStatus 410, got %d", lastStatus)
	}
	if active {
		t.Fatal("expected endpoint to be auto-disabled after 410 Gone")
	}

	// Step 3: Terminal 400 Bad Request
	mu.Lock()
	statusCode = http.StatusBadRequest
	mu.Unlock()

	endpoint2, _, err := svc.CreateEndpoint(ctx, orgID, envID, server.URL, []string{"run.failed"}, audit)
	if err != nil {
		t.Fatalf("create endpoint2: %v", err)
	}

	eventID2 := newUUID(t)
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return svc.EnqueueDeliveryTx(ctx, tx, orgID, envID, "run.failed", runID, eventID2, time.Now(), map[string]any{"err": "bad"})
	}); err != nil {
		t.Fatalf("enqueue delivery: %v", err)
	}

	dispatched, err = dispatcher.DispatchOnce(ctx)
	if err != nil || dispatched != 1 {
		t.Fatalf("dispatch once: err=%v dispatched=%d", err, dispatched)
	}

	var ep2Active bool
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT status, last_status_code FROM webhook_deliveries WHERE event_id = $1::uuid`, eventID2).Scan(&status, &lastStatus); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT active FROM webhook_endpoints WHERE id = $1::uuid`, endpoint2.ID).Scan(&ep2Active)
	}); err != nil {
		t.Fatalf("query status ep2: %v", err)
	}

	if status != "FAILED" {
		t.Fatalf("expected status FAILED after 400, got %s", status)
	}
	if lastStatus != 400 {
		t.Fatalf("expected lastStatus 400, got %d", lastStatus)
	}
	if !ep2Active {
		t.Fatal("endpoint should NOT be disabled on standard 400 (only 410 disables endpoint)")
	}
}

func TestWebhookSSRFDefense(t *testing.T) {
	// With AllowInsecureHTTP: false, SSRF protection must block private/loopback/metadata destinations
	cfg := webhooks.SSRFConfig{
		AllowInsecureHTTP: false,
		ConnectTimeout:    3 * time.Second,
		TotalTimeout:      10 * time.Second,
	}

	blockedTargets := []string{
		"http://example.com/webhook",       // Plaintext HTTP rejected
		"https://example.com:8080/webhook", // Non-443 port rejected
		"https://127.0.0.1:443/webhook",    // Loopback IPv4
		"https://10.0.0.1:443/webhook",     // RFC1918 Private
		"https://172.16.0.1:443/webhook",   // RFC1918 Private
		"https://192.168.1.1:443/webhook",  // RFC1918 Private
		"https://169.254.169.254:443/meta", // Cloud metadata service
		"https://[::1]:443/webhook",        // Loopback IPv6
		"https://[fe80::1]:443/webhook",    // Link-local IPv6
		"https://[fc00::1]:443/webhook",    // Unique Local IPv6
	}

	for _, target := range blockedTargets {
		_, err := webhooks.ValidateEndpointURL(target, cfg)
		if err == nil {
			t.Errorf("expected SSRF error for target %q, but got nil", target)
		}
	}
}

func TestWebhookURLRevisionCancellation(t *testing.T) {
	t.Setenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING", "true")
	tc, orgID, envID := setupWebhookTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()
	masterKey := webhooks.DefaultMasterKey()
	ssrfCfg := webhooks.DefaultSSRFConfig()
	svc := webhooks.NewService(tc.pool, masterKey, ssrfCfg)
	audit := &tenant.AuditContext{ActorType: tenant.IdentityTypeMachine}

	// 1. Create endpoint revision 1
	endpoint, _, err := svc.CreateEndpoint(ctx, orgID, envID, "https://old.example.com/hook", []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}

	// 2. Enqueue delivery intent for revision 1
	runID := newUUID(t)
	eventID := newUUID(t)
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return svc.EnqueueDeliveryTx(ctx, tx, orgID, envID, "run.succeeded", runID, eventID, time.Now(), map[string]any{"v": 1})
	}); err != nil {
		t.Fatalf("enqueue delivery: %v", err)
	}

	// Verify delivery is PENDING
	var status string
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM webhook_deliveries WHERE event_id = $1::uuid`, eventID).Scan(&status)
	}); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "PENDING" {
		t.Fatalf("expected PENDING status, got %s", status)
	}

	// 3. Update URL -> increments revision to 2 and cancels pending deliveries from rev 1
	newURL := "https://new.example.com/hook"
	updated, _, err := svc.UpdateEndpoint(ctx, orgID, endpoint.ID, endpoint.Revision, &newURL, nil, nil, false, audit)
	if err != nil {
		t.Fatalf("update endpoint: %v", err)
	}
	if updated.Revision != 2 {
		t.Fatalf("expected revision 2, got %d", updated.Revision)
	}

	// 4. Verify the old delivery is CANCELLED
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM webhook_deliveries WHERE event_id = $1::uuid`, eventID).Scan(&status)
	}); err != nil {
		t.Fatalf("query status after update: %v", err)
	}
	if status != "CANCELLED" {
		t.Fatalf("expected CANCELLED status for old revision delivery, got %s", status)
	}
}

func TestWebhookRunCompletionAtomicity(t *testing.T) {
	t.Setenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING", "true")
	tc, server, orgID, envID, _ := setupRunLifecycleTest(t)
	defer tc.cleanup()
	defer server.Close()

	ctx := context.Background()
	_, _ = tc.database.Exec("TRUNCATE webhook_deliveries, webhook_endpoints CASCADE;")
	defer func() {
		_, _ = tc.database.Exec("TRUNCATE webhook_deliveries, webhook_endpoints CASCADE;")
	}()
	masterKey := webhooks.DefaultMasterKey()
	ssrfCfg := webhooks.DefaultSSRFConfig()
	svc := webhooks.NewService(tc.pool, masterKey, ssrfCfg)
	audit := &tenant.AuditContext{ActorType: tenant.IdentityTypeMachine}

	// Register webhook endpoint subscribed to run.succeeded
	endpoint, _, err := svc.CreateEndpoint(ctx, orgID, envID, "https://receiver.example.com/events", []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create webhook endpoint: %v", err)
	}

	// Create run with delay execution workflow
	deploymentID := seedDelayDeployment(t, tc, orgID, envID, "webhook-atomicity-dep")
	execSvc := execution.NewService(tc.pool, tc.service)
	run, _, err := execSvc.CreateRun(ctx, orgID, envID, "delay-flow", "run-atomic-1", &deploymentID, map[string]any{}, audit)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	// Fast forward timer to complete run
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE timers SET due_at=clock_timestamp()-INTERVAL '1 second' WHERE run_id=$1::uuid AND kind='DELAY' AND state='PENDING'`, run.ID)
		return err
	}); err != nil {
		t.Fatalf("update timer: %v", err)
	}

	// Workers are offline! WorkerEngine fires delay timer and completes run
	engine := execution.NewWorkerEngine(tc.pool)
	fired, err := engine.FireDueDelayTimers(ctx, orgID)
	if err != nil || fired != 1 {
		t.Fatalf("fire delay timer: fired=%d err=%v", fired, err)
	}

	// Verify run reached SUCCEEDED
	var runStatus string
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM runs WHERE id=$1::uuid`, run.ID).Scan(&runStatus)
	}); err != nil {
		t.Fatalf("query run status: %v", err)
	}
	if runStatus != "SUCCEEDED" {
		t.Fatalf("expected run status SUCCEEDED, got %s", runStatus)
	}

	// Verify that webhook_deliveries contains the delivery intent for run.succeeded atomically
	var deliveryCount int
	var deliveryStatus string
	var deliveryEventType string
	if err := tc.pool.WithTenantTx(ctx, orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*), COALESCE(min(status), ''), COALESCE(min(event_type), '')
			FROM webhook_deliveries
			WHERE run_id = $1::uuid AND endpoint_id = $2::uuid
		`, run.ID, endpoint.ID).Scan(&deliveryCount, &deliveryStatus, &deliveryEventType)
	}); err != nil {
		t.Fatalf("query webhook delivery: %v", err)
	}

	if deliveryCount != 1 {
		t.Fatalf("expected exactly 1 webhook delivery intent enqueued, got %d", deliveryCount)
	}
	if deliveryEventType != "run.succeeded" {
		t.Fatalf("expected event_type run.succeeded, got %s", deliveryEventType)
	}
	if deliveryStatus != "PENDING" {
		t.Fatalf("expected delivery status PENDING, got %s", deliveryStatus)
	}
}
