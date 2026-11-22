package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Ryanakml/Deadbolt/internal/contracts"
	"github.com/Ryanakml/Deadbolt/internal/storage"
	"github.com/Ryanakml/Deadbolt/internal/tenant"
)

// TestConsecutiveMinorCompatibilityAndUnsupportedMajorRejection proves:
// 1. Current/previous tested minor in the same major pass CI and register successfully.
// 2. Unsupported majors (e.g. manifestVersion: 2 or protocolMajor: 2) fail actionably with HTTP 422.
func TestConsecutiveMinorCompatibilityAndUnsupportedMajorRejection(t *testing.T) {
	tc, server, orgID, envID, adminKey := setupRunLifecycleTest(t)
	defer tc.cleanup()
	defer server.Close()

	schema := map[string]any{
		"type":                 "object",
		"properties":           map[string]any{"x": map[string]any{"type": "string"}},
		"required":             []any{"x"},
		"additionalProperties": false,
	}

	tasks := []map[string]any{{
		"name":                "t1",
		"entrypoint":          "tasks/t1.js",
		"timeoutMs":           30000,
		"recovery":            "idempotent",
		"idempotencyWindowMs": 305000,
		"inputSchema":         schema,
		"outputSchema":        schema,
	}}
	workflows := []map[string]any{{
		"manifestVersion": 1,
		"name":            "minor-wf",
		"inputSchema":     schema,
		"outputSchema":    schema,
		"nodes": []map[string]any{{
			"id":    "n1",
			"type":  "task",
			"task":  "t1",
			"after": []any{},
			"input": map[string]any{"x": map[string]any{"$ref": "run.input", "pointer": "/x"}},
		}},
		"output": map[string]any{"x": map[string]any{"$ref": "step.output", "stepId": "n1", "pointer": "/x"}},
	}}

	registerManifest := func(m map[string]any, idempKey string) (int, map[string]any) {
		b, _ := json.Marshal(m)
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/deployments?environment=%s", server.URL, envID), bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
		req.Header.Set("X-Organization-ID", orgID)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", idempKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		var res map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&res)
		return resp.StatusCode, res
	}

	// Minor version 1.0.0 (previous minor)
	m10 := map[string]any{
		"manifestVersion":      1,
		"sdkVersion":           "1.0.0",
		"protocolMajor":        1,
		"nodeRuntimeMajor":     24,
		"targetOS":             "linux",
		"targetArchitecture":   "amd64",
		"dependencyLockDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bundleDigest":         "1010101010101010101010101010101010101010101010101010101010101010",
		"secretNames":          []string{},
		"tasks":                tasks,
		"workflows":            workflows,
	}
	code, res := registerManifest(m10, "compat-minor-1-0")
	if code != http.StatusCreated {
		t.Fatalf("minor 1.0.0 expected 201, got %d (%v)", code, res)
	}

	// Minor version 1.1.0 (consecutive minor in same major)
	m11 := map[string]any{
		"manifestVersion":      1,
		"sdkVersion":           "1.1.0",
		"protocolMajor":        1,
		"nodeRuntimeMajor":     24,
		"targetOS":             "linux",
		"targetArchitecture":   "amd64",
		"dependencyLockDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bundleDigest":         "1111111111111111111111111111111111111111111111111111111111111111",
		"secretNames":          []string{},
		"tasks":                tasks,
		"workflows":            workflows,
	}
	code, res = registerManifest(m11, "compat-minor-1-1")
	if code != http.StatusCreated {
		t.Fatalf("minor 1.1.0 expected 201, got %d (%v)", code, res)
	}

	// Unsupported protocol major (protocolMajor: 2)
	mBadProto := map[string]any{
		"manifestVersion":      1,
		"sdkVersion":           "2.0.0",
		"protocolMajor":        2,
		"nodeRuntimeMajor":     24,
		"targetOS":             "linux",
		"targetArchitecture":   "amd64",
		"dependencyLockDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bundleDigest":         "2222222222222222222222222222222222222222222222222222222222222222",
		"secretNames":          []string{},
		"tasks":                tasks,
		"workflows":            workflows,
	}
	code, res = registerManifest(mBadProto, "compat-bad-proto")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported protocolMajor 2 expected 422, got %d (%v)", code, res)
	}

	// Unsupported manifest major (manifestVersion: 2)
	mBadManifest := map[string]any{
		"manifestVersion":      2,
		"sdkVersion":           "1.0.0",
		"protocolMajor":        1,
		"nodeRuntimeMajor":     24,
		"targetOS":             "linux",
		"targetArchitecture":   "amd64",
		"dependencyLockDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bundleDigest":         "3333333333333333333333333333333333333333333333333333333333333333",
		"secretNames":          []string{},
		"tasks":                tasks,
		"workflows":            workflows,
	}
	code, res = registerManifest(mBadManifest, "compat-bad-manifest")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported manifestVersion 2 expected 422, got %d (%v)", code, res)
	}
}

// TestRunPinningAcrossRollbackAndPointerMove proves:
// 1. Old run stays pinned to its creation deployment while channel moves to new deployment and rolls back.
// 2. Referenced deployment deletion fails (HTTP 409 Conflict) while unreferenced deletion succeeds (204).
// 3. Rerun creates a new run with fresh operation IDs, retaining original deployment by default or explicit override.
func TestRunPinningAcrossRollbackAndPointerMove(t *testing.T) {
	tc, server, orgID, envID, adminKey := setupRunLifecycleTest(t)
	defer tc.cleanup()
	defer server.Close()

	schema := map[string]any{
		"type":                 "object",
		"properties":           map[string]any{"data": map[string]any{"type": "string"}},
		"required":             []any{"data"},
		"additionalProperties": false,
	}
	tasks := []map[string]any{{
		"name":                "pin-task",
		"entrypoint":          "tasks/pin.js",
		"timeoutMs":           30000,
		"recovery":            "idempotent",
		"idempotencyWindowMs": 305000,
		"inputSchema":         schema,
		"outputSchema":        schema,
	}}
	workflows := []map[string]any{{
		"manifestVersion": 1,
		"name":            "pinned-flow",
		"inputSchema":     schema,
		"outputSchema":    schema,
		"nodes": []map[string]any{{
			"id":    "step-1",
			"type":  "task",
			"task":  "pin-task",
			"after": []any{},
			"input": map[string]any{"data": map[string]any{"$ref": "run.input", "pointer": "/data"}},
		}},
		"output": map[string]any{"data": map[string]any{"$ref": "step.output", "stepId": "step-1", "pointer": "/data"}},
	}}

	bundleA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	bundleB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
	manifestA := createLifecycleManifest(bundleA, tasks, workflows)
	manifestB := createLifecycleManifest(bundleB, tasks, workflows)

	// Step 1: Register and activate Deployment A
	depAID := registerAndActivateTestWorkflow(t, tc, server, adminKey, orgID, envID, "pinned-flow", manifestA)

	// Create Run 1 under Deployment A
	createRun := func(idempKey string, input map[string]any) map[string]any {
		body, _ := json.Marshal(map[string]any{"environment": "staging", "input": input})
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/workflows/pinned-flow/runs", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
		req.Header.Set("X-Organization-ID", orgID)
		req.Header.Set("Idempotency-Key", idempKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusAccepted {
			t.Fatalf("create run failed: %v (status %d)", err, resp.StatusCode)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	run1 := createRun("run-pin-1", map[string]any{"data": "run-1-payload"})
	if run1["deploymentId"] != depAID {
		t.Fatalf("run 1 deploymentId mismatch: want %s, got %v", depAID, run1["deploymentId"])
	}

	// Step 2: Register Deployment B and advance channel to Deployment B (revision 1 -> 2)
	regBReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/deployments?environment=%s", server.URL, envID), bytes.NewReader(manifestB))
	regBReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	regBReq.Header.Set("X-Organization-ID", orgID)
	regBReq.Header.Set("Content-Type", "application/json")
	regBReq.Header.Set("Idempotency-Key", "dep-reg-pinned-flow-b")
	regBResp, err := http.DefaultClient.Do(regBReq)
	if err != nil || (regBResp.StatusCode != http.StatusOK && regBResp.StatusCode != http.StatusCreated) {
		t.Fatalf("register dep B failed: %v", err)
	}
	var regB struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(regBResp.Body).Decode(&regB)
	regBResp.Body.Close()
	depBID := regB.ID

	// Seed worker for bundle B
	workerBID, _ := tenant.NewUUID()
	sessionBID, _ := tenant.NewUUID()
	_ = tc.pool.WithTenantTx(context.Background(), orgID, func(ctx context.Context, tx storage.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO workers (id,organization_id,environment_id,public_key,status) VALUES ($1,$2,$3,'pk','ACTIVE')`, workerBID, orgID, envID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO worker_sessions (id,organization_id,worker_id,environment_id,session_token_hash,expires_at) VALUES ($1,$2,$3,$4,'h',clock_timestamp()+interval '1 hour')`, sessionBID, orgID, workerBID, envID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO worker_deployments (session_id,organization_id,bundle_digest) VALUES ($1,$2,$3)`, sessionBID, orgID, bundleB); err != nil {
			return err
		}
		return nil
	})

	actBBody, _ := json.Marshal(map[string]any{
		"deploymentId":      depBID,
		"expectedRevision":  1,
		"allowSingleWorker": true,
	})
	actBReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/workflows/pinned-flow/activate?environment=%s", server.URL, envID), bytes.NewReader(actBBody))
	actBReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	actBReq.Header.Set("X-Organization-ID", orgID)
	actBReq.Header.Set("Content-Type", "application/json")
	actBReq.Header.Set("Idempotency-Key", "dep-act-pinned-flow-b")
	actBResp, err := http.DefaultClient.Do(actBReq)
	if err != nil || actBResp.StatusCode != http.StatusOK {
		var actErr map[string]any
		if actBResp != nil {
			_ = json.NewDecoder(actBResp.Body).Decode(&actErr)
		}
		t.Fatalf("activate dep B failed: status %v body %+v", actBResp.StatusCode, actErr)
	}
	actBResp.Body.Close()

	// Create Run 2 under Deployment B
	run2 := createRun("run-pin-2", map[string]any{"data": "run-2-payload"})
	if run2["deploymentId"] != depBID {
		t.Fatalf("run 2 deploymentId mismatch: want %s, got %v", depBID, run2["deploymentId"])
	}

	// Verify Run 1 STILL has deployment A (INV-02 / ADR-10)
	var run1CurrentDep string
	if err := tc.pool.WithTenantTx(context.Background(), orgID, func(ctx context.Context, tx storage.Tx) error {
		return tx.QueryRow(ctx, `SELECT deployment_id::text FROM runs WHERE id=$1::uuid`, run1["id"]).Scan(&run1CurrentDep)
	}); err != nil {
		t.Fatal(err)
	}
	if run1CurrentDep != depAID {
		t.Fatalf("Run 1 lost original deployment: want %s, got %s", depAID, run1CurrentDep)
	}

	// Step 3: Rollback! Activate Deployment A back onto channel (revision 2 -> 3)
	actBody, _ := json.Marshal(map[string]any{
		"deploymentId":      depAID,
		"expectedRevision":  2,
		"allowSingleWorker": true,
	})
	actReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/workflows/pinned-flow/activate?environment=%s", server.URL, envID), bytes.NewReader(actBody))
	actReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	actReq.Header.Set("X-Organization-ID", orgID)
	actReq.Header.Set("Idempotency-Key", "rollback-to-a")
	actReq.Header.Set("Content-Type", "application/json")
	actResp, err := http.DefaultClient.Do(actReq)
	if err != nil || actResp.StatusCode != http.StatusOK {
		t.Fatalf("rollback activation failed: %v status=%d", err, actResp.StatusCode)
	}
	actResp.Body.Close()

	// Create Run 3 (after rollback)
	run3 := createRun("run-pin-3", map[string]any{"data": "run-3-payload"})
	if run3["deploymentId"] != depAID {
		t.Fatalf("run 3 should point to rolled-back depA: want %s, got %v", depAID, run3["deploymentId"])
	}
	// Run 1 and Run 2 still preserve their exact historical deployments
	if err := tc.pool.WithTenantTx(context.Background(), orgID, func(ctx context.Context, tx storage.Tx) error {
		var dep1, dep2 string
		if err := tx.QueryRow(ctx, `SELECT deployment_id::text FROM runs WHERE id=$1::uuid`, run1["id"]).Scan(&dep1); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT deployment_id::text FROM runs WHERE id=$1::uuid`, run2["id"]).Scan(&dep2); err != nil {
			return err
		}
		if dep1 != depAID || dep2 != depBID {
			return fmt.Errorf("historical runs altered: dep1=%s, dep2=%s", dep1, dep2)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Step 4: Deleting referenced deployments MUST FAIL with 409 Conflict
	delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/deployments/%s?environment=%s", server.URL, depAID, envID), nil)
	delReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	delReq.Header.Set("X-Organization-ID", orgID)
	delReq.Header.Set("Idempotency-Key", "del-dep-a")
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when deleting active/referenced depA, got %d", delResp.StatusCode)
	}

	delReqB, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/deployments/%s?environment=%s", server.URL, depBID, envID), nil)
	delReqB.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	delReqB.Header.Set("X-Organization-ID", orgID)
	delReqB.Header.Set("Idempotency-Key", "del-dep-b")
	delRespB, err := http.DefaultClient.Do(delReqB)
	if err != nil {
		t.Fatal(err)
	}
	delRespB.Body.Close()
	if delRespB.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when deleting run-referenced depB, got %d", delRespB.StatusCode)
	}

	// Register an unreferenced Deployment C
	bundleC := "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc3"
	manifestC := createLifecycleManifest(bundleC, tasks, workflows)
	regReqC, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/deployments?environment=%s", server.URL, envID), bytes.NewReader(manifestC))
	regReqC.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	regReqC.Header.Set("X-Organization-ID", orgID)
	regReqC.Header.Set("Idempotency-Key", "reg-dep-c")
	regReqC.Header.Set("Content-Type", "application/json")
	regRespC, err := http.DefaultClient.Do(regReqC)
	if err != nil || regRespC.StatusCode != http.StatusCreated {
		t.Fatalf("register depC failed: %v status=%d", err, regRespC.StatusCode)
	}
	var regC struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(regRespC.Body).Decode(&regC)
	regRespC.Body.Close()

	// Deleting unreferenced Deployment C MUST SUCCEED with 204 No Content
	delReqC, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/deployments/%s?environment=%s", server.URL, regC.ID, envID), nil)
	delReqC.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	delReqC.Header.Set("X-Organization-ID", orgID)
	delReqC.Header.Set("Idempotency-Key", "del-dep-c")
	delRespC, err := http.DefaultClient.Do(delReqC)
	if err != nil {
		t.Fatal(err)
	}
	delRespC.Body.Close()
	if delRespC.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 No Content when deleting unreferenced depC, got %d", delRespC.StatusCode)
	}

	// Step 5: Test Rerun endpoint (POST /v1/runs/{id}/rerun)
	// 5a. Default rerun: retains original deployment A and original input
	rerunReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/runs/%s/rerun", server.URL, run1["id"]), bytes.NewReader([]byte("{}")))
	rerunReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	rerunReq.Header.Set("X-Organization-ID", orgID)
	rerunReq.Header.Set("Idempotency-Key", "rerun-run1-default")
	rerunReq.Header.Set("Content-Type", "application/json")
	rerunResp, err := http.DefaultClient.Do(rerunReq)
	if err != nil {
		t.Fatal(err)
	}
	defer rerunResp.Body.Close()
	if rerunResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on rerun, got %d", rerunResp.StatusCode)
	}
	var rerunRun1 map[string]any
	_ = json.NewDecoder(rerunResp.Body).Decode(&rerunRun1)

	if rerunRun1["id"] == run1["id"] {
		t.Fatalf("rerun must mint new run ID (INV-09), got identical ID %v", rerunRun1["id"])
	}
	if rerunRun1["deploymentId"] != depAID {
		t.Fatalf("rerun must use original deployment by default, want %s, got %v", depAID, rerunRun1["deploymentId"])
	}
	if rerunRun1["status"] != string(contracts.RunStatusQUEUED) {
		t.Fatalf("rerun must start as QUEUED from beginning, got %v", rerunRun1["status"])
	}
	if rerunRun1["revision"] != float64(1) {
		t.Fatalf("rerun must start at revision 1, got %v", rerunRun1["revision"])
	}

	// Verify new run has its own fresh steps
	var originalStepID, rerunStepID string
	if err := tc.pool.WithTenantTx(context.Background(), orgID, func(ctx context.Context, tx storage.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT id::text FROM run_steps WHERE run_id=$1::uuid`, run1["id"]).Scan(&originalStepID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT id::text FROM run_steps WHERE run_id=$1::uuid`, rerunRun1["id"]).Scan(&rerunStepID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if originalStepID == rerunStepID {
		t.Fatalf("rerun step must have new operation ID, got same %s", originalStepID)
	}

	// 5b. Rerun with explicit deployment and input override
	overrideBody := fmt.Sprintf(`{"deploymentId":%q,"input":{"data":"overridden-input"}}`, depBID)
	rerunReq2, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/runs/%s/rerun", server.URL, run1["id"]), bytes.NewReader([]byte(overrideBody)))
	rerunReq2.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	rerunReq2.Header.Set("X-Organization-ID", orgID)
	rerunReq2.Header.Set("Idempotency-Key", "rerun-run1-override")
	rerunReq2.Header.Set("Content-Type", "application/json")
	rerunResp2, err := http.DefaultClient.Do(rerunReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer rerunResp2.Body.Close()
	if rerunResp2.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on rerun override, got %d", rerunResp2.StatusCode)
	}
	var rerunRun2 map[string]any
	_ = json.NewDecoder(rerunResp2.Body).Decode(&rerunRun2)
	if rerunRun2["deploymentId"] != depBID {
		t.Fatalf("expected overridden deploymentId %s, got %v", depBID, rerunRun2["deploymentId"])
	}

	// Step 6: Verify list deployments and list workflows
	listDepReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/deployments?environment=%s", server.URL, envID), nil)
	listDepReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	listDepReq.Header.Set("X-Organization-ID", orgID)
	listDepResp, err := http.DefaultClient.Do(listDepReq)
	if err != nil {
		t.Fatal(err)
	}
	defer listDepResp.Body.Close()
	if listDepResp.StatusCode != http.StatusOK {
		t.Fatalf("list deployments failed: %d", listDepResp.StatusCode)
	}
	var depList struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.NewDecoder(listDepResp.Body).Decode(&depList)
	if len(depList.Items) < 2 {
		t.Fatalf("expected at least 2 deployments, got %d", len(depList.Items))
	}

	listWfReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/workflows?environment=%s", server.URL, envID), nil)
	listWfReq.Header.Set("Authorization", "Bearer "+adminKey.PlaintextKey)
	listWfReq.Header.Set("X-Organization-ID", orgID)
	listWfResp, err := http.DefaultClient.Do(listWfReq)
	if err != nil {
		t.Fatal(err)
	}
	defer listWfResp.Body.Close()
	if listWfResp.StatusCode != http.StatusOK {
		t.Fatalf("list workflows failed: %d", listWfResp.StatusCode)
	}
	var wfList struct {
		Items []struct {
			Name               string `json:"name"`
			ActiveDeploymentID string `json:"activeDeploymentId"`
		} `json:"items"`
	}
	_ = json.NewDecoder(listWfResp.Body).Decode(&wfList)
	if len(wfList.Items) == 0 || wfList.Items[0].Name != "pinned-flow" {
		t.Fatalf("expected pinned-flow in workflows list, got %+v", wfList.Items)
	}
}
