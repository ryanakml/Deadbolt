# Compatibility, Deployment Rollback, and Rerun Guide

This guide details the operational and architectural contracts for SDK/Agent compatibility, deployment rollbacks, worker inventory reconciliation, and run rerun semantics across Deadbolt, adhering to **Blueprint §4, §12, §20, §23, §26** and **ADR-10**.

---

## 1. Architectural Principles & Invariants

| Invariant | Principle | Enforcement Mechanism |
| :--- | :--- | :--- |
| **INV-02** | **Run Immutability & Deployment Pinning** | Every run is permanently pinned to the exact deployment (`deployment_id` and SHA-256 `bundle_digest`) active when created. Pointer movement or rollbacks never alter running or historical runs. |
| **INV-09** | **Terminal History Preservation** | Terminal runs (`SUCCEEDED`, `FAILED`, `CANCELLED`, `TIMED_OUT`) cannot be modified or re-opened. Reruns mint brand-new runs starting at `QUEUED` / `revision: 1` with fresh step and attempt IDs. |
| **ADR-10** | **Explicit Channel Revisions** | Workflow channels use compare-and-swap (`expectedRevision`) for all pointer updates. Rollback is an explicit forward revision that re-points the active deployment. |
| **§20** | **Referential Integrity on Deletion** | Deployments referenced by active workflow channels or existing runs cannot be deleted (`409 Conflict: DEPLOYMENT_REFERENCED`). |

---

## 2. SDK & Agent Version Compatibility

### Consecutive Minor Version Compatibility
Control Plane, Worker Agents, and TypeScript SDK maintain strict semantic versioning within the same major version:
- **Consecutive Minor Versions:** Any worker agent running version `X.Y` can execute workflows compiled by SDK `X.(Y-1)` or `X.(Y+1)` provided the `protocolMajor` and `manifestVersion` match.
- **Protocol Major Match:** `protocolMajor` (currently `1`) and `manifestVersion` (currently `1`) must match exactly.
- **Node Runtime Baseline:** Node runtime major is validated against the supported host runtime (Node 24).

### Actionable Rejection of Unsupported Majors
Submitting a manifest or connecting an agent with an unsupported major version fails immediately and actionably:
- Manifest submission with `manifestVersion != 1` returns **HTTP 422 Unprocessable Content**:
  ```json
  {
    "code": "UNSUPPORTED_MANIFEST_VERSION",
    "message": "Manifest version 2 is unsupported by this engine (expected 1)",
    "retryable": false
  }
  ```
- Agent polling with `protocolMajor != 1` returns **HTTP 422 Unprocessable Content**:
  ```json
  {
    "code": "UNSUPPORTED_PROTOCOL_VERSION",
    "message": "Agent protocol major 2 is unsupported (expected 1)",
    "retryable": false
  }
  ```

---

## 3. Retained Bundle Obligations & Worker Inventory

### Retained Bundles for Historical Runs
Because existing runs remain pinned to their original `deployment_id` (INV-02), the orchestrator requires workers that can execute those specific bundles until all in-flight runs reach a terminal state.

### Worker Availability & Loss Warning
Workers advertise their deployed bundles during registration and periodic polling:
1. When a worker is drained (`POST /v1/workers/{id}/drain`) or revoked (`POST /v1/workers/{id}/revoke`), Deadbolt automatically runs `ReconcileAvailabilityTx`.
2. If an active workflow channel's deployment has **zero active, non-draining workers** advertising its bundle digest:
   - The deployment's `compatibility_warning_at` timestamp is set.
   - An outbox event `deployment.compatibility_lost` is emitted.
   - Control Plane alarms and dashboard indicators notify operators that newly admitted runs cannot be claimed until compatible workers reconnect.

### Referenced Registration Deletion Protection
To prevent broken audit trails and orphaned runs:
- `DELETE /v1/deployments/{id}` queries `runs` and `workflow_channels`.
- If any run references the deployment, or if the deployment is currently active on any workflow channel, deletion is rejected with **HTTP 409 Conflict (`DEPLOYMENT_REFERENCED`)**.
- Only deployments with **0 run references** and **no active channel pointers** can be purged.

---

## 4. Deployment Rollback & Channel Pointer Movements

Workflow execution is decoupled from authoring via **Workflow Channels**:
- Each environment (`staging`, `production`) maintains channel pointers (`workflow_channels`) mapping `workflow_name` to `active_deployment_id` with a monotonic integer `revision`.
- Advancing a channel requires atomic CAS (`expectedRevision`):
  ```bash
  curl -X POST "https://controlplane.deadbolt.local/v1/workflows/my-pipeline/activate?environment=staging" \
    -H "Authorization: Bearer $DEADBOLT_KEY" \
    -H "X-Organization-ID: $ORG_ID" \
    -H "Content-Type: application/json" \
    -d '{
      "deploymentId": "018d9600-0000-7000-8000-000000000001",
      "expectedRevision": 2,
      "allowSingleWorker": true
    }'
  ```

### Rollback Semantics
- Rolling back from Deployment B (rev 2) to Deployment A (prior deployment) does NOT decrement the channel revision.
- It performs a new forward CAS operation (rev 2 $\to$ rev 3), setting `active_deployment_id = Deployment A`.
- **Immediate Outcome:**
  - All new runs created after revision 3 immediately use Deployment A.
  - In-flight runs that were created during revision 2 continue executing against Deployment B until completion.
  - Workers advertising Bundle A claim the new runs; workers advertising Bundle B finish the old runs.

---

## 5. Rerun Semantics & Side-Effect Warnings

### Invariant INV-09 Compliance
Under no circumstances does a rerun reopen, mutate, or overwrite a finished run record:
- The completed run remains permanently in the database with its original status, timing, step outputs, and audit trail.
- Initiating a rerun invokes `POST /v1/runs/{id}/rerun`.

### Rerun Execution Behavior
When `POST /v1/runs/{id}/rerun` is invoked:
1. **Fresh Identifiers:** A new run is created with a brand-new `id` (UUIDv7), `status = QUEUED`, `revision = 1`, and fresh `run_steps` with new attempt IDs.
2. **Default Deployment Binding:** By default, the rerun uses the **original run's deployment**, preserving the exact code version that executed previously.
3. **Explicit Deployment Override:** An operator may optionally pass `"explicitDeploymentId": "..."` to migrate the rerun to a newer (or rolled back) deployment.
4. **Explicit Input Override:** An operator may optionally pass `"explicitInput": { ... }` to correct flawed inputs.
5. **Audit Logging:** An audit entry is recorded linking the new run ID with `rerun_from_run_id` in the metadata.

### Side-Effect Warning & Gating
Re-executing a workflow carries inherent side-effect risks (e.g. charge operations, external emails, third-party webhooks) if intermediate tasks are not idempotent.

- **API Acknowledgement:** When changing inputs or deployment versions, requests are logged with side-effect advisories.
- **Dashboard UI Control:**
  - The Web UI displays a modal warning:
    > **Warning: Re-running this workflow will execute tasks from the beginning.**
    > If external services or non-idempotent actions were already executed by the original run, duplicate side-effects may occur.
  - Operator confirmation is required before dispatching the rerun request.

---

## 6. Control Plane API Reference

### `GET /v1/deployments`
Lists immutable deployment registrations with pagination and worker compatibility status.
- **Query Params:** `environment` (optional filter), `limit` (default 25), `cursor`.
- **Capabilities Required:** `deployments:register` or `runs:read`.

### `DELETE /v1/deployments/{id}`
Deletes an unreferenced deployment registration.
- **Headers:** `X-Organization-ID`.
- **Response:** `204 No Content` on success; `409 Conflict` (`DEPLOYMENT_REFERENCED`) if active or referenced by runs.
- **Capabilities Required:** `deployments:register` or `deployments:write`.

### `GET /v1/workflows`
Lists workflows with active channel pointers, current revisions, and deployment bundle summaries.
- **Query Params:** `environment` (required UUID or name), `limit`, `cursor`.
- **Capabilities Required:** `workflows:read` or `runs:read`.

### `POST /v1/runs/{id}/rerun`
Dispatches a new run starting from the beginning.
- **Headers:** `X-Organization-ID`, `Idempotency-Key`.
- **Body:**
  ```json
  {
    "explicitDeploymentId": "018d9600-...", // optional override
    "explicitInput": { ... }                // optional override
  }
  ```
- **Response:** `202 Accepted` returning the newly created `RunSnapshotDTO`.
- **Capabilities Required:** `runs:create`.

---

## 7. Dashboard UI Workflows

The Deadbolt Web Dashboard (`apps/dashboard/`) includes dedicated operator controls:
1. **Deployments View (`#deployments-view`):**
   - Displays all registered bundles, SDK versions, node runtimes, creation timestamps, and active channel statuses.
   - Allows safe deletion of unreferenced deployments with confirmation dialogs.
2. **Worker Inventory Actions:**
   - Real-time worker inventory table includes **Drain** and **Revoke** action buttons gated by RBAC (`roleCanDrainWorkers`).
   - Triggering drain or revoke immediately reflects worker state changes and initiates deployment availability reconciliation.
3. **Run Inspector Rerun Action:**
   - The Run Inspector displays a **Rerun** button for terminal runs.
   - Opens the Rerun dialog showing the default deployment binding, allowing input adjustments, and displaying the side-effect safety warning before submittal.
