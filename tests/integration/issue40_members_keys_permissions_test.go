package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ryanakml/Deadbolt/internal/controlplane"
	"github.com/Ryanakml/Deadbolt/internal/execution"
	"github.com/Ryanakml/Deadbolt/internal/storage"
	"github.com/Ryanakml/Deadbolt/internal/tenant"
	"github.com/Ryanakml/Deadbolt/internal/webhooks"
	"github.com/Ryanakml/Deadbolt/internal/worker"
)

// Issue #40 / M5 Acceptance Tests:
// 1. Role table enforced server-side including last-owner protection & narrower environment policy.
// 2. Keys show secret once and rotate/revoke/expire; sessions/worker revocation blocks subsequent operations.
// 3. Viewer lacks payload/log/artifact, machine keys cannot approve/reconcile; status metadata remains sanitized.
// 4. Redelivery preserves event ID with new delivery attempt, explicit new destination choice option, and visible errors/conflicts in UI/API.

func TestViewerRoleLacksPayloadLogArtifactAndReceivesSanitizedMetadata(t *testing.T) {
	tc, server, orgID, envID, adminKey := setupRunLifecycleTest(t)
	defer server.Close()
	defer tc.cleanup()

	ctx := context.Background()

	// 1. Setup multi-step workflow & enroll worker
	_, bundleDigest := setupInspectorMultiStepWorkflow(t, tc, server, orgID, envID, adminKey)
	sessionCtx, sessionToken := enrollTestWorker(t, tc, server, orgID, envID, bundleDigest)

	// 2. Create and execute a run with payload output
	createReq, _ := http.NewRequest("POST", server.URL+"/v1/workflows/inspector-multi-step/runs", strings.NewReader(`{"environment":"staging","input":{"val":"confidential-user-input"}}`))
	createReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	createReq.Header.Set("Idempotency-Key", "viewer-test-run-1")
	createReq.Header.Set("Content-Type", "application/json")
	createRes, err := http.DefaultClient.Do(createReq)
	if err != nil || createRes.StatusCode != http.StatusAccepted {
		t.Fatalf("create run failed: %v", err)
	}
	var runResp execution.RunDTO
	_ = json.NewDecoder(createRes.Body).Decode(&runResp)
	createRes.Body.Close()

	// Worker polls and starts
	pollBody, _ := json.Marshal(worker.PollRequestDTO{
		ProtocolVersion:   worker.ProtocolVersion,
		RequestID:         "p-viewer-1",
		WorkerID:          sessionCtx.WorkerID,
		SessionID:         sessionCtx.SessionID,
		AvailableSlots:    1,
		DeploymentDigests: []string{bundleDigest},
		Pool:              "default",
	})
	pollReq, _ := http.NewRequest("POST", server.URL+"/worker/v1/poll", bytes.NewReader(pollBody))
	pollReq.Header.Set("Authorization", "Bearer "+sessionToken)
	pollReq.Header.Set("Content-Type", "application/json")
	pollRes, err := http.DefaultClient.Do(pollReq)
	if err != nil || pollRes.StatusCode != http.StatusOK {
		t.Fatalf("worker poll failed: %v", err)
	}
	var pollResp worker.PollResponseDTO
	_ = json.NewDecoder(pollRes.Body).Decode(&pollResp)
	pollRes.Body.Close()
	if len(pollResp.Assignments) == 0 {
		t.Fatal("expected at least one assignment")
	}
	as := pollResp.Assignments[0]

	startReq, _ := http.NewRequest("POST", server.URL+"/worker/v1/start", strings.NewReader(
		fmt.Sprintf(`{"protocolVersion":1,"requestId":"s-viewer-1","workerId":"%s","sessionId":"%s","attemptId":"%s","ownershipEpoch":%d}`, sessionCtx.WorkerID, sessionCtx.SessionID, as.AttemptID, as.OwnershipEpoch),
	))
	startReq.Header.Set("Authorization", "Bearer "+sessionToken)
	startReq.Header.Set("Content-Type", "application/json")
	startRes, err := http.DefaultClient.Do(startReq)
	if err != nil || startRes.StatusCode != http.StatusOK {
		t.Fatalf("worker start failed: %v", err)
	}
	startRes.Body.Close()

	// Complete step-1 with output
	compPayload := worker.CompleteRequestDTO{
		ProtocolVersion: 1,
		RequestID:       "c-viewer-1",
		WorkerID:        sessionCtx.WorkerID,
		SessionID:       sessionCtx.SessionID,
		AttemptID:       as.AttemptID,
		OwnershipEpoch:  as.OwnershipEpoch,
		Outcome:         "SUCCEEDED",
		Output:          map[string]any{"val": "confidential-output-data"},
	}
	digest, _ := worker.CanonicalCompletionDigest(&compPayload)
	compPayload.ResultDigest = digest
	cb, _ := json.Marshal(compPayload)
	compReq, _ := http.NewRequest("POST", server.URL+"/worker/v1/complete", bytes.NewReader(cb))
	compReq.Header.Set("Authorization", "Bearer "+sessionToken)
	compReq.Header.Set("Content-Type", "application/json")
	compRes, err := http.DefaultClient.Do(compReq)
	if err != nil || compRes.StatusCode != http.StatusOK {
		t.Fatalf("worker complete failed: %v", err)
	}
	compRes.Body.Close()

	// 3. Create a human Viewer user in organization
	viewerUserID := newUUID(t)
	if _, err := tc.runtimePool.Exec(ctx, "INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", viewerUserID, "viewer-issue40@corp.test", "Viewer Test"); err != nil {
		t.Fatalf("insert viewer user: %v", err)
	}
	if _, err := tc.service.AddMember(ctx, orgID, viewerUserID, tenant.RoleViewer); err != nil {
		t.Fatalf("add viewer member: %v", err)
	}

	// Create human session for Viewer
	_, rawViewerToken, _, err := tc.sessionStore.CreateSession(ctx, viewerUserID, &orgID, "127.0.0.1", "test-agent", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create viewer session: %v", err)
	}

	viewerDo := func(req *http.Request) (*http.Response, error) {
		req.AddCookie(&http.Cookie{
			Name:  tc.authCfg.SessionCookieName(),
			Value: rawViewerToken,
		})
		req.Header.Set("X-Organization-ID", orgID)
		return http.DefaultClient.Do(req)
	}

	// 4. Assert: Viewer receives 403 FORBIDDEN on /v1/runs/{id}/logs
	logsReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/runs/%s/logs", server.URL, runResp.ID), nil)
	logsRes, err := viewerDo(logsReq)
	if err != nil {
		t.Fatalf("viewer get logs failed: %v", err)
	}
	defer logsRes.Body.Close()
	if logsRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on /v1/runs/{id}/logs for Viewer, got %d", logsRes.StatusCode)
	}
	var logsErr map[string]any
	_ = json.NewDecoder(logsRes.Body).Decode(&logsErr)
	if logsErr["code"] != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN error code on logs, got %v", logsErr["code"])
	}

	// 5. Assert: Viewer receives 403 FORBIDDEN on /v1/artifacts/{id}
	artifactReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/artifacts/%s", server.URL, newUUID(t)), nil)
	artifactRes, err := viewerDo(artifactReq)
	if err != nil {
		t.Fatalf("viewer get artifact failed: %v", err)
	}
	defer artifactRes.Body.Close()
	if artifactRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on /v1/artifacts/{id} for Viewer, got %d", artifactRes.StatusCode)
	}

	// 6. Assert: Viewer receives 403 FORBIDDEN on /environments/{envId}/payload-preview
	previewReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/environments/%s/payload-preview", server.URL, envID), nil)
	previewRes, err := viewerDo(previewReq)
	if err != nil {
		t.Fatalf("viewer payload preview failed: %v", err)
	}
	defer previewRes.Body.Close()
	if previewRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on payload preview for Viewer, got %d", previewRes.StatusCode)
	}

	// 7. Assert: Viewer GET /v1/runs/{id} returns 200 OK with sanitized Output and step Output
	getRunReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/runs/%s", server.URL, runResp.ID), nil)
	getRunRes, err := viewerDo(getRunReq)
	if err != nil {
		t.Fatalf("viewer get run failed: %v", err)
	}
	defer getRunRes.Body.Close()
	if getRunRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /v1/runs/{id} for Viewer, got %d", getRunRes.StatusCode)
	}
	var viewerSnap execution.RunSnapshotDTO
	if err := json.NewDecoder(getRunRes.Body).Decode(&viewerSnap); err != nil {
		t.Fatalf("decode viewer snapshot: %v", err)
	}
	if viewerSnap.Output != nil {
		t.Fatalf("expected run output to be nil for Viewer, got %+v", viewerSnap.Output)
	}
	if viewerSnap.Error != nil {
		t.Fatalf("expected run error to be nil for Viewer, got %+v", viewerSnap.Error)
	}
	for _, step := range viewerSnap.Steps {
		if step.Output != nil {
			t.Fatalf("expected step %s output to be nil for Viewer, got %+v", step.NodeID, step.Output)
		}
		for _, att := range step.Attempts {
			if att.Error != nil {
				t.Fatalf("expected attempt error to be nil for Viewer, got %+v", att.Error)
			}
		}
	}

	// 8. Assert: Viewer GET /v1/runs/{id}/events returns sanitized event payloads
	eventsReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/runs/%s/events", server.URL, runResp.ID), nil)
	eventsRes, err := viewerDo(eventsReq)
	if err != nil {
		t.Fatalf("viewer get events failed: %v", err)
	}
	defer eventsRes.Body.Close()
	if eventsRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /v1/runs/{id}/events for Viewer, got %d", eventsRes.StatusCode)
	}
	var eventsResp struct {
		Events []struct {
			Sequence int64                  `json:"sequence"`
			Type     string                 `json:"type"`
			Payload  map[string]interface{} `json:"payload"`
		} `json:"events"`
	}
	if err := json.NewDecoder(eventsRes.Body).Decode(&eventsResp); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	for _, ev := range eventsResp.Events {
		// Output or confidential data must never leak into event payload for Viewer
		if out, ok := ev.Payload["output"]; ok && out != nil {
			t.Fatalf("event %s leaked output payload to viewer: %+v", ev.Type, ev.Payload)
		}
	}
}

func TestMachineKeysCannotApproveOrReconcile(t *testing.T) {
	tc, server, orgID, envID, adminKey := setupRunLifecycleTest(t)
	defer server.Close()
	defer tc.cleanup()

	ctx := context.Background()
	ownerCaps := tenant.RoleCapabilities(tenant.RoleOwner)
	audit := &tenant.AuditContext{
		ActorID:       &adminKey.ID,
		ActorType:     tenant.IdentityTypeMachine,
		Role:          tenant.RoleOwner,
		Capabilities:  ownerCaps,
		CorrelationID: "machine-key-test",
	}

	// 1. Assert: Service rejects creating machine API key with approvals:decide
	_, err := tc.service.CreateAPIKey(ctx, orgID, envID, []string{tenant.CapApprovalsDecide}, 90, ownerCaps, audit)
	if err == nil || !errors.Is(err, tenant.ErrMachineKeyRestricted) {
		t.Fatalf("expected ErrMachineKeyRestricted when creating key with CapApprovalsDecide, got: %v", err)
	}

	// 2. Assert: Service rejects creating machine API key with runs:reconcile
	_, err = tc.service.CreateAPIKey(ctx, orgID, envID, []string{tenant.CapRunsReconcile}, 90, ownerCaps, audit)
	if err == nil || !errors.Is(err, tenant.ErrMachineKeyRestricted) {
		t.Fatalf("expected ErrMachineKeyRestricted when creating key with CapRunsReconcile, got: %v", err)
	}

	// 3. Assert: Owner HTTP session attempting to create machine key with approvals:decide is rejected (403 MACHINE_KEY_UNAUTHORIZED)
	ownerUserID := newUUID(t)
	if _, err := tc.runtimePool.Exec(ctx, "INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", ownerUserID, "owner-key-test@corp.test", "Owner Test"); err != nil {
		t.Fatalf("insert owner user: %v", err)
	}
	if _, err := tc.service.AddMember(ctx, orgID, ownerUserID, tenant.RoleOwner); err != nil {
		t.Fatalf("add owner member: %v", err)
	}
	_, ownerToken, ownerCsrf, err := tc.sessionStore.CreateSession(ctx, ownerUserID, &orgID, "127.0.0.1", "test-agent", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create owner session: %v", err)
	}

	createReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/environments/%s/api-keys", server.URL, envID), strings.NewReader(`{"capabilities":["approvals:decide"]}`))
	createReq.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: ownerToken})
	createReq.Header.Set("X-Organization-ID", orgID)
	createReq.Header.Set("Origin", "http://localhost:3000")
	createReq.Header.Set("X-CSRF-Token", ownerCsrf)
	createReq.Header.Set("Idempotency-Key", "owner-create-key-decide")
	createReq.Header.Set("Content-Type", "application/json")
	createRes, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create key request failed: %v", err)
	}
	defer createRes.Body.Close()
	var errResp map[string]any
	_ = json.NewDecoder(createRes.Body).Decode(&errResp)
	if createRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for restricted capability approvals:decide, got %d body=%+v", createRes.StatusCode, errResp)
	}
	if errResp["code"] != "MACHINE_KEY_UNAUTHORIZED" {
		t.Fatalf("expected MACHINE_KEY_UNAUTHORIZED error code, got %v", errResp["code"])
	}

	// 4. Assert: Machine key calling POST /v1/approvals/{id}/decision is rejected with 403 APPROVAL_HUMAN_ONLY
	decideReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/approvals/%s/decision", server.URL, newUUID(t)), strings.NewReader(`{"decision":"approved"}`))
	decideReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	decideReq.Header.Set("X-Organization-ID", orgID)
	decideReq.Header.Set("Idempotency-Key", "machine-decide-idemp")
	decideReq.Header.Set("Content-Type", "application/json")
	decideRes, err := http.DefaultClient.Do(decideReq)
	if err != nil {
		t.Fatalf("approval decision request failed: %v", err)
	}
	defer decideRes.Body.Close()
	if decideRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for machine approval decision, got %d", decideRes.StatusCode)
	}
	var decideErr map[string]any
	_ = json.NewDecoder(decideRes.Body).Decode(&decideErr)
	if decideErr["code"] != "APPROVAL_HUMAN_ONLY" && decideErr["code"] != "FORBIDDEN" {
		t.Fatalf("expected APPROVAL_HUMAN_ONLY or FORBIDDEN, got %v", decideErr["code"])
	}

	// 5. Assert: Machine key calling POST /v1/reconciliation-cases/{id}/resolve is rejected with 403 MACHINE_FORBIDDEN
	resolveReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/reconciliation-cases/%s/resolve", server.URL, newUUID(t)), strings.NewReader(`{"resolution":"reclaim"}`))
	resolveReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	resolveReq.Header.Set("X-Organization-ID", orgID)
	resolveReq.Header.Set("Idempotency-Key", "machine-resolve-idemp")
	resolveReq.Header.Set("Content-Type", "application/json")
	resolveRes, err := http.DefaultClient.Do(resolveReq)
	if err != nil {
		t.Fatalf("reconcile resolve request failed: %v", err)
	}
	defer resolveRes.Body.Close()
	if resolveRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for machine reconciliation resolve, got %d", resolveRes.StatusCode)
	}
	var resolveErr map[string]any
	_ = json.NewDecoder(resolveRes.Body).Decode(&resolveErr)
	if resolveErr["code"] != "MACHINE_FORBIDDEN" && resolveErr["code"] != "FORBIDDEN" {
		t.Fatalf("expected MACHINE_FORBIDDEN or FORBIDDEN, got %v", resolveErr["code"])
	}
}

func TestRevokedSessionAndWorkerImmediateBlock(t *testing.T) {
	tc, server, orgID, envID, adminKey := setupRunLifecycleTest(t)
	defer server.Close()
	defer tc.cleanup()

	ctx := context.Background()

	// Setup human user and add to organization
	humanUserID := newUUID(t)
	if _, err := tc.runtimePool.Exec(ctx, "INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", humanUserID, "human-rev@corp.test", "Human Revoke Test"); err != nil {
		t.Fatalf("insert human user: %v", err)
	}
	if _, err := tc.service.AddMember(ctx, orgID, humanUserID, tenant.RoleAdmin); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// 1. Human BFF Cookie Session: Active -> Revoked -> 401 UNAUTHENTICATED
	sess, rawToken, _, err := tc.sessionStore.CreateSession(ctx, humanUserID, &orgID, "127.0.0.1", "test-agent", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	checkSessReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	checkSessReq.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: rawToken})
	resp1, err := http.DefaultClient.Do(checkSessReq)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for active session, got %d err=%v", resp1.StatusCode, err)
	}
	resp1.Body.Close()

	// Revoke the session
	if err := tc.sessionStore.RevokeSession(ctx, sess.ID, "TEST_LOGOUT"); err != nil {
		t.Fatalf("revoke session: %v", err)
	}

	// Subsequent request immediately blocked
	checkSessReq2, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	checkSessReq2.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: rawToken})
	resp2, err := http.DefaultClient.Do(checkSessReq2)
	if err != nil {
		t.Fatalf("request with revoked session failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for revoked session, got %d", resp2.StatusCode)
	}

	// 2. CLI Session: Active -> Revoked -> 401 UNAUTHENTICATED
	cliSess, cliToken, err := tc.sessionStore.CreateCLISession(ctx, humanUserID, &orgID, "127.0.0.1", "dbcli/1.0", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create CLI session: %v", err)
	}
	cliReq1, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	cliReq1.Header.Set("Authorization", "Bearer "+cliToken)
	cliResp1, err := http.DefaultClient.Do(cliReq1)
	if err != nil || cliResp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for active CLI session, got %d", cliResp1.StatusCode)
	}
	cliResp1.Body.Close()

	// Revoke CLI session
	if err := tc.sessionStore.RevokeSession(ctx, cliSess.ID, "CLI_LOGOUT"); err != nil {
		t.Fatalf("revoke CLI session: %v", err)
	}

	cliReq2, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	cliReq2.Header.Set("Authorization", "Bearer "+cliToken)
	cliResp2, err := http.DefaultClient.Do(cliReq2)
	if err != nil {
		t.Fatalf("cli request after revoke failed: %v", err)
	}
	defer cliResp2.Body.Close()
	if cliResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for revoked CLI session, got %d", cliResp2.StatusCode)
	}

	// 3. Worker Session: Active -> Worker Revocation -> 403 WORKER_REVOKED
	sessCtx, sessTok := enrollTestWorker(t, tc, server, orgID, envID, "")

	// Worker poll succeeds
	pollReqBody, _ := json.Marshal(worker.PollRequestDTO{
		ProtocolVersion: worker.ProtocolVersion,
		RequestID:       "poll-rev-1",
		WorkerID:        sessCtx.WorkerID,
		SessionID:       sessCtx.SessionID,
		AvailableSlots:  0,
		Pool:            "default",
	})
	pReq1, _ := http.NewRequest("POST", server.URL+"/worker/v1/poll", bytes.NewReader(pollReqBody))
	pReq1.Header.Set("Authorization", "Bearer "+sessTok)
	pReq1.Header.Set("Content-Type", "application/json")
	pRes1, err := http.DefaultClient.Do(pReq1)
	if err != nil || pRes1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for worker poll, got %d err=%v", pRes1.StatusCode, err)
	}
	pRes1.Body.Close()

	// Revoke the worker
	revReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/workers/%s/revoke", server.URL, sessCtx.WorkerID), nil)
	revReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	revReq.Header.Set("X-Organization-ID", orgID)
	revReq.Header.Set("Idempotency-Key", "revoke-worker-"+sessCtx.WorkerID)
	revRes, err := http.DefaultClient.Do(revReq)
	if err != nil || revRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for revoke worker, got %d err=%v", revRes.StatusCode, err)
	}
	revRes.Body.Close()

	// Subsequent poll returns 403 WORKER_REVOKED
	pReq2, _ := http.NewRequest("POST", server.URL+"/worker/v1/poll", bytes.NewReader(pollReqBody))
	pReq2.Header.Set("Authorization", "Bearer "+sessTok)
	pReq2.Header.Set("Content-Type", "application/json")
	pRes2, err := http.DefaultClient.Do(pReq2)
	if err != nil {
		t.Fatalf("poll after worker revoke failed: %v", err)
	}
	defer pRes2.Body.Close()
	if pRes2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for revoked worker, got %d", pRes2.StatusCode)
	}
	var workerErr map[string]any
	_ = json.NewDecoder(pRes2.Body).Decode(&workerErr)
	if workerErr["code"] != "WORKER_REVOKED" {
		t.Fatalf("expected WORKER_REVOKED error code, got %v", workerErr["code"])
	}

	// 4. Suspended / Removed Member: Access immediately denied with 403 FORBIDDEN_ORGANIZATION_MEMBERSHIP
	user2ID := newUUID(t)
	if _, err := tc.runtimePool.Exec(ctx, "INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", user2ID, "user2-rev@corp.test", "User 2 Test"); err != nil {
		t.Fatalf("insert user 2: %v", err)
	}
	if _, err := tc.service.AddMember(ctx, orgID, user2ID, tenant.RoleDeveloper); err != nil {
		t.Fatalf("add member 2: %v", err)
	}
	_, user2Token, _, err := tc.sessionStore.CreateSession(ctx, user2ID, &orgID, "127.0.0.1", "test-agent", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create user 2 session: %v", err)
	}

	u2Req1, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	u2Req1.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: user2Token})
	u2Res1, err := http.DefaultClient.Do(u2Req1)
	if err != nil || u2Res1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for active user 2, got %d", u2Res1.StatusCode)
	}
	u2Res1.Body.Close()

	// Suspend member
	if err := tc.service.UpdateMemberStatus(ctx, orgID, user2ID, tenant.StatusSuspended); err != nil {
		t.Fatalf("suspend member: %v", err)
	}

	u2Req2, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	u2Req2.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: user2Token})
	u2Res2, err := http.DefaultClient.Do(u2Req2)
	if err != nil {
		t.Fatalf("request for suspended member failed: %v", err)
	}
	defer u2Res2.Body.Close()
	if u2Res2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for suspended member, got %d", u2Res2.StatusCode)
	}
	var suspErr map[string]any
	_ = json.NewDecoder(u2Res2.Body).Decode(&suspErr)
	if suspErr["code"] != "FORBIDDEN_ORGANIZATION_MEMBERSHIP" {
		t.Fatalf("expected FORBIDDEN_ORGANIZATION_MEMBERSHIP, got %v", suspErr["code"])
	}

	// Remove member
	if err := tc.service.RemoveMember(ctx, orgID, user2ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}

	u2Req3, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/organizations/%s", server.URL, orgID), nil)
	u2Req3.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: user2Token})
	u2Res3, err := http.DefaultClient.Do(u2Req3)
	if err != nil {
		t.Fatalf("request for removed member failed: %v", err)
	}
	defer u2Res3.Body.Close()
	if u2Res3.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for removed member, got %d", u2Res3.StatusCode)
	}
}

func TestLastOwnerProtectionEnforcement(t *testing.T) {
	tc, server, orgID, _, _ := setupRunLifecycleTest(t)
	defer server.Close()
	defer tc.cleanup()

	ctx := context.Background()

	// Identify sole bootstrap Owner
	members, err := tc.service.ListMembers(ctx, orgID)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	var soleOwnerID string
	for _, m := range members {
		if m.Role == tenant.RoleOwner && m.Status == tenant.StatusActive {
			soleOwnerID = m.UserID
			break
		}
	}
	if soleOwnerID == "" {
		t.Fatal("expected at least one active owner in bootstrapped organization")
	}

	// Ensure owner user exists in users table for foreign key constraint
	if _, err := tc.runtimePool.Exec(ctx, "INSERT INTO users (id, email, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING", soleOwnerID, "sole-owner@corp.test", "Sole Owner"); err != nil {
		t.Fatalf("upsert sole owner into users table: %v", err)
	}

	// Create session for the owner
	_, ownerToken, ownerCsrf, err := tc.sessionStore.CreateSession(ctx, soleOwnerID, &orgID, "127.0.0.1", "test-owner-agent", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create owner session: %v", err)
	}

	ownerDo := func(req *http.Request) (*http.Response, error) {
		req.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: ownerToken})
		req.Header.Set("X-Organization-ID", orgID)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("X-CSRF-Token", ownerCsrf)
		if req.Header.Get("Idempotency-Key") == "" && req.Method != http.MethodGet && req.Method != http.MethodHead {
			req.Header.Set("Idempotency-Key", newUUID(t))
		}
		return http.DefaultClient.Do(req)
	}

	// 1. Attempt to demote sole Owner -> 403 LAST_OWNER_DEMOTION_FORBIDDEN
	demoteReq, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/organizations/%s/members/%s", server.URL, orgID, soleOwnerID), strings.NewReader(fmt.Sprintf(`{"role":"%s"}`, tenant.RoleDeveloper)))
	demoteReq.Header.Set("Content-Type", "application/json")
	demoteRes, err := ownerDo(demoteReq)
	if err != nil {
		t.Fatalf("demote request failed: %v", err)
	}
	defer demoteRes.Body.Close()
	var demoteErr map[string]any
	_ = json.NewDecoder(demoteRes.Body).Decode(&demoteErr)
	if demoteRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for sole owner demotion, got %d body=%+v", demoteRes.StatusCode, demoteErr)
	}
	if demoteErr["code"] != "LAST_OWNER_DEMOTION_FORBIDDEN" {
		t.Fatalf("expected LAST_OWNER_DEMOTION_FORBIDDEN, got %v", demoteErr["code"])
	}

	// 2. Attempt to suspend sole Owner -> 403 LAST_OWNER_SUSPENSION_FORBIDDEN
	suspReq, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/organizations/%s/members/%s/status", server.URL, orgID, soleOwnerID), strings.NewReader(fmt.Sprintf(`{"status":"%s"}`, tenant.StatusSuspended)))
	suspReq.Header.Set("Content-Type", "application/json")
	suspRes, err := ownerDo(suspReq)
	if err != nil {
		t.Fatalf("suspension request failed: %v", err)
	}
	defer suspRes.Body.Close()
	if suspRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for sole owner suspension, got %d", suspRes.StatusCode)
	}
	var suspErr map[string]any
	_ = json.NewDecoder(suspRes.Body).Decode(&suspErr)
	if suspErr["code"] != "LAST_OWNER_SUSPENSION_FORBIDDEN" {
		t.Fatalf("expected LAST_OWNER_SUSPENSION_FORBIDDEN, got %v", suspErr["code"])
	}

	// 3. Attempt to remove sole Owner -> 403 LAST_OWNER_REMOVAL_FORBIDDEN
	remReq, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/v1/organizations/%s/members/%s", server.URL, orgID, soleOwnerID), nil)
	remRes, err := ownerDo(remReq)
	if err != nil {
		t.Fatalf("removal request failed: %v", err)
	}
	defer remRes.Body.Close()
	if remRes.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for sole owner removal, got %d", remRes.StatusCode)
	}
	var remErr map[string]any
	_ = json.NewDecoder(remRes.Body).Decode(&remErr)
	if remErr["code"] != "LAST_OWNER_REMOVAL_FORBIDDEN" {
		t.Fatalf("expected LAST_OWNER_REMOVAL_FORBIDDEN, got %v", remErr["code"])
	}

	// 4. Add second Owner -> demoting first owner now succeeds
	owner2ID := newUUID(t)
	if _, err := tc.runtimePool.Exec(ctx, "INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", owner2ID, "owner2-issue40@corp.test", "Owner 2 Test"); err != nil {
		t.Fatalf("insert owner 2: %v", err)
	}
	if _, err := tc.service.AddMember(ctx, orgID, owner2ID, tenant.RoleOwner); err != nil {
		t.Fatalf("add owner 2: %v", err)
	}

	demoteReq2, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/organizations/%s/members/%s", server.URL, orgID, soleOwnerID), strings.NewReader(fmt.Sprintf(`{"role":"%s"}`, tenant.RoleDeveloper)))
	demoteReq2.Header.Set("Content-Type", "application/json")
	demoteRes2, err := ownerDo(demoteReq2)
	if err != nil || demoteRes2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK demoting first owner with second owner present, got %d err=%v", demoteRes2.StatusCode, err)
	}
	demoteRes2.Body.Close()

	// 5. Now Owner 2 is the sole active Owner; demoting, suspending, or removing Owner 2 must fail!
	_, owner2Token, owner2Csrf, err := tc.sessionStore.CreateSession(ctx, owner2ID, &orgID, "127.0.0.1", "test-owner2-agent", 12*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("create owner 2 session: %v", err)
	}
	owner2Do := func(req *http.Request) (*http.Response, error) {
		req.AddCookie(&http.Cookie{Name: tc.authCfg.SessionCookieName(), Value: owner2Token})
		req.Header.Set("X-Organization-ID", orgID)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("X-CSRF-Token", owner2Csrf)
		if req.Header.Get("Idempotency-Key") == "" && req.Method != http.MethodGet && req.Method != http.MethodHead {
			req.Header.Set("Idempotency-Key", newUUID(t))
		}
		return http.DefaultClient.Do(req)
	}

	demoteO2Req, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/organizations/%s/members/%s", server.URL, orgID, owner2ID), strings.NewReader(fmt.Sprintf(`{"role":"%s"}`, tenant.RoleDeveloper)))
	demoteO2Req.Header.Set("Content-Type", "application/json")
	demoteO2Res, err := owner2Do(demoteO2Req)
	if err != nil {
		t.Fatalf("demote owner 2 request failed: %v", err)
	}
	defer demoteO2Res.Body.Close()
	if demoteO2Res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden demoting sole remaining owner 2, got %d", demoteO2Res.StatusCode)
	}
}

func TestWebhookManualRedeliveryDestinationChoiceAndConflict(t *testing.T) {
	t.Setenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING", "true")
	tc, orgID, envID := setupWebhookTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// 1. Create a second environment in the same organization
	projects, err := tc.service.ListProjects(ctx, orgID)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	env2, err := tc.service.CreateEnvironment(ctx, orgID, projects[0].ID, tenant.EnvProduction, 10)
	if err != nil {
		t.Fatalf("create second environment: %v", err)
	}

	// 2. Start control plane server and webhook receiver
	server := httptest.NewServer(controlplane.BuildMux(tc.authCfg, tc.runtimePool, nil, nil))
	defer server.Close()

	var mu sync.Mutex
	var receivedCount int
	receiverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	}))
	defer receiverServer.Close()

	// 3. Create webhook service & endpoints
	svc := webhooks.NewService(tc.pool, webhooks.DefaultMasterKey(), webhooks.DefaultSSRFConfig())
	audit := &tenant.AuditContext{
		ActorType:     tenant.IdentityTypeMachine,
		CorrelationID: "webhook-test-redelivery",
	}

	ep1, _, err := svc.CreateEndpoint(ctx, orgID, envID, receiverServer.URL+"/hook1", []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create ep1: %v", err)
	}

	ep2, _, err := svc.CreateEndpoint(ctx, orgID, envID, receiverServer.URL+"/hook2", []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create ep2: %v", err)
	}
	// Disable ep2 to verify ENDPOINT_INACTIVE handling
	isActiveFalse := false
	_, _, err = svc.UpdateEndpoint(ctx, orgID, ep2.ID, ep2.Revision, nil, &isActiveFalse, nil, false, audit)
	if err != nil {
		t.Fatalf("disable ep2: %v", err)
	}

	ep3, _, err := svc.CreateEndpoint(ctx, orgID, envID, receiverServer.URL+"/hook3", []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create ep3: %v", err)
	}

	epEnv2, _, err := svc.CreateEndpoint(ctx, orgID, env2.ID, receiverServer.URL+"/hook-env2", []string{"run.succeeded"}, audit)
	if err != nil {
		t.Fatalf("create epEnv2: %v", err)
	}

	// 4. Enqueue initial delivery for ep1
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
		t.Fatalf("enqueue initial delivery: %v", err)
	}

	// Get initial delivery record
	deliveries, _, err := svc.ListDeliveries(ctx, orgID, ep1.ID, 10, "")
	if err != nil || len(deliveries) == 0 {
		t.Fatalf("list deliveries: %v len=%d", err, len(deliveries))
	}
	initialDelivery := deliveries[0]

	// Bootstrap machine API key scoped to envID
	adminKey := bootstrapTestKey(t, tc.service, orgID, envID, []string{
		tenant.CapWebhooksWrite,
	})

	// Test 4.1: Redeliver to original endpoint (empty JSON body)
	redeliverReq1, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/webhook-deliveries/%s/redeliver", server.URL, initialDelivery.ID), strings.NewReader(`{}`))
	redeliverReq1.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	redeliverReq1.Header.Set("X-Organization-ID", orgID)
	redeliverReq1.Header.Set("Idempotency-Key", "redeliver-test-orig-1")
	redeliverReq1.Header.Set("Content-Type", "application/json")
	redeliverRes1, err := http.DefaultClient.Do(redeliverReq1)
	if err != nil || redeliverRes1.StatusCode != http.StatusOK {
		t.Fatalf("redeliver original failed: status %d err %v", redeliverRes1.StatusCode, err)
	}
	var newDel1 webhooks.WebhookDelivery
	if err := json.NewDecoder(redeliverRes1.Body).Decode(&newDel1); err != nil {
		t.Fatalf("decode redeliver result: %v", err)
	}
	redeliverRes1.Body.Close()

	if newDel1.EventID != eventID {
		t.Fatalf("expected preserved EventID %s, got %s", eventID, newDel1.EventID)
	}
	if newDel1.EndpointID != ep1.ID {
		t.Fatalf("expected EndpointID %s, got %s", ep1.ID, newDel1.EndpointID)
	}
	if newDel1.Attempts != 0 {
		t.Fatalf("expected Attempts 0 for new redelivery, got %d", newDel1.Attempts)
	}

	// Test 4.2: Redeliver specifying explicit new destination choice (ep3)
	redeliverReq2, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/webhook-deliveries/%s/redeliver", server.URL, initialDelivery.ID), strings.NewReader(fmt.Sprintf(`{"endpointId":"%s"}`, ep3.ID)))
	redeliverReq2.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	redeliverReq2.Header.Set("X-Organization-ID", orgID)
	redeliverReq2.Header.Set("Idempotency-Key", "redeliver-test-dest-2")
	redeliverReq2.Header.Set("Content-Type", "application/json")
	redeliverRes2, err := http.DefaultClient.Do(redeliverReq2)
	if err != nil || redeliverRes2.StatusCode != http.StatusOK {
		t.Fatalf("redeliver with destination choice failed: status %d err %v", redeliverRes2.StatusCode, err)
	}
	var newDel2 webhooks.WebhookDelivery
	if err := json.NewDecoder(redeliverRes2.Body).Decode(&newDel2); err != nil {
		t.Fatalf("decode destination redeliver result: %v", err)
	}
	redeliverRes2.Body.Close()

	if newDel2.EventID != eventID {
		t.Fatalf("expected preserved EventID %s, got %s", eventID, newDel2.EventID)
	}
	if newDel2.EndpointID != ep3.ID {
		t.Fatalf("expected EndpointID %s, got %s", ep3.ID, newDel2.EndpointID)
	}
	if newDel2.Attempts != 0 {
		t.Fatalf("expected Attempts 0, got %d", newDel2.Attempts)
	}

	// Test 4.3: Redeliver specifying inactive destination (ep2) -> 409 Conflict ENDPOINT_INACTIVE
	redeliverReq3, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/webhook-deliveries/%s/redeliver", server.URL, initialDelivery.ID), strings.NewReader(fmt.Sprintf(`{"endpointId":"%s"}`, ep2.ID)))
	redeliverReq3.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	redeliverReq3.Header.Set("X-Organization-ID", orgID)
	redeliverReq3.Header.Set("Idempotency-Key", "redeliver-test-inact-3")
	redeliverReq3.Header.Set("Content-Type", "application/json")
	redeliverRes3, err := http.DefaultClient.Do(redeliverReq3)
	if err != nil {
		t.Fatalf("redeliver inactive endpoint request failed: %v", err)
	}
	defer redeliverRes3.Body.Close()
	if redeliverRes3.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for inactive destination endpoint, got %d", redeliverRes3.StatusCode)
	}
	var conflictErr map[string]any
	_ = json.NewDecoder(redeliverRes3.Body).Decode(&conflictErr)
	if conflictErr["code"] != "ENDPOINT_INACTIVE" {
		t.Fatalf("expected ENDPOINT_INACTIVE error code, got %v", conflictErr["code"])
	}

	// Test 4.4: Redeliver across environments with machine key -> 403 Forbidden ENVIRONMENT_MISMATCH
	redeliverReq4, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/webhook-deliveries/%s/redeliver", server.URL, initialDelivery.ID), strings.NewReader(fmt.Sprintf(`{"endpointId":"%s"}`, epEnv2.ID)))
	redeliverReq4.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	redeliverReq4.Header.Set("X-Organization-ID", orgID)
	redeliverReq4.Header.Set("Idempotency-Key", "redeliver-test-cross-4")
	redeliverReq4.Header.Set("Content-Type", "application/json")
	redeliverRes4, err := http.DefaultClient.Do(redeliverReq4)
	if err != nil {
		t.Fatalf("redeliver cross-environment request failed: %v", err)
	}
	defer redeliverRes4.Body.Close()
	if redeliverRes4.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-environment machine redelivery, got %d", redeliverRes4.StatusCode)
	}
	var envErr map[string]any
	_ = json.NewDecoder(redeliverRes4.Body).Decode(&envErr)
	if envErr["code"] != "ENVIRONMENT_MISMATCH" {
		t.Fatalf("expected ENVIRONMENT_MISMATCH error code, got %v", envErr["code"])
	}
}
