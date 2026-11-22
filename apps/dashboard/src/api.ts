import {
  Run,
  Worker,
  RunSnapshot,
  RunEventsResponse,
  TaskLogsResponse,
  ResolveReconciliationRequest,
  ResolveReconciliationResponse,
  Approval,
  Schedule,
  ScheduleOccurrence,
  WebhookEndpoint,
  WebhookDelivery,
  OrganizationMember,
  APIKeySummary,
  GeneratedKey,
} from "./types.js";

export interface ListRunsResponse {
  items: Run[];
  nextCursor?: string | null;
}

export interface ListWorkersResponse {
  items: Worker[];
  nextCursor?: string | null;
}

export interface AuthMembership {
  OrganizationID: string;
  OrganizationName: string;
  Role: string;
  Status: string;
}

export interface AuthSession {
  user: { id: string; email: string; name: string };
  active_organization_id: string | null;
  memberships: AuthMembership[];
}

export interface SwitchOrgResponse {
  session_id: string;
  active_organization_id: string;
  csrf_token: string;
}

export interface ProjectSummary {
  id: string;
  name: string;
}

export interface EnvironmentSummary {
  id: string;
  name: string;
}

// CatalogEnvironment is one selectable environment with enough project
// context to disambiguate identical environment names across projects.
// The option value is always the canonical environment UUID.
export interface CatalogEnvironment {
  projectId: string;
  projectName: string;
  environmentId: string;
  environmentName: string;
}

export function formatEnvironmentLabel(env: CatalogEnvironment): string {
  return `${env.projectName} / ${env.environmentName}`;
}

// EnvironmentSelection tracks the dashboard's canonical environment choice
// for the active organization. Switching organizations clears stale
// catalog/selection so an environment ID from the previous org can never
// be reused.
export interface EnvironmentSelection {
  orgId: string | null;
  catalog: CatalogEnvironment[];
  selectedEnvironmentId: string | null;
}

export function createEnvironmentSelection(): EnvironmentSelection {
  return { orgId: null, catalog: [], selectedEnvironmentId: null };
}

export function setSelectionOrganization(
  sel: EnvironmentSelection,
  orgId: string | null,
): void {
  if (sel.orgId !== orgId) {
    sel.orgId = orgId;
    sel.catalog = [];
    sel.selectedEnvironmentId = null;
  }
}

export function setSelectionCatalog(
  sel: EnvironmentSelection,
  catalog: CatalogEnvironment[],
): string | null {
  sel.catalog = [...catalog];
  if (
    sel.selectedEnvironmentId &&
    catalog.some((e) => e.environmentId === sel.selectedEnvironmentId)
  ) {
    return sel.selectedEnvironmentId;
  }
  sel.selectedEnvironmentId =
    catalog.length > 0 ? catalog[0].environmentId : null;
  return sel.selectedEnvironmentId;
}

export function selectEnvironment(
  sel: EnvironmentSelection,
  envId: string | null,
): string | null {
  if (!envId) {
    sel.selectedEnvironmentId = null;
    return null;
  }
  if (sel.catalog.some((e) => e.environmentId === envId)) {
    sel.selectedEnvironmentId = envId;
    return envId;
  }
  return sel.selectedEnvironmentId;
}

export function getSelectedEnvironmentId(
  sel: EnvironmentSelection,
): string | null {
  return sel.selectedEnvironmentId;
}

// apiFetch keeps every dashboard request on same-origin cookies explicitly.
// The dashboard never handles bearer tokens; authentication is the HttpOnly
// BFF session cookie.
export async function apiFetch(
  input: string,
  init: RequestInit = {},
): Promise<Response> {
  return fetch(input, { credentials: "same-origin", ...init });
}

export function isUnauthorized(err: unknown): boolean {
  return err instanceof Error && err.message.includes("HTTP 401");
}

export function isConflict(err: unknown): boolean {
  return err instanceof Error && err.message.includes("HTTP 409");
}

// newIdempotencyKey mints a unique command key for one user decision. The
// dialog keeps the key for the lifetime of its submission so a retry of the
// same ambiguous submit reuses the identity instead of forking commands.
export function newIdempotencyKey(): string {
  const cryptoObj = typeof crypto !== "undefined" ? crypto : undefined;
  if (cryptoObj && "randomUUID" in cryptoObj) {
    return (cryptoObj as Crypto).randomUUID();
  }
  return `resolve-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 14)}`;
}

// readCsrfToken reads the SPA-readable CSRF bootstrap cookie without ever
// touching the HttpOnly session value. Both hosted (__Host-) and local
// (non-secure) cookie names are accepted.
export function readCsrfToken(): string {
  if (typeof document === "undefined") return "";
  for (const part of document.cookie.split(";")) {
    const [rawName, ...rest] = part.trim().split("=");
    const name = rawName.trim();
    if (name === "__Host-csrf_token" || name === "deadbolt_local_csrf") {
      return decodeURIComponent(rest.join("=").trim());
    }
  }
  return "";
}

export class DashboardApiClient {
  private baseUrl: string;

  constructor(baseUrl = "") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  // getSession returns the current BFF session, or null when the browser is
  // unauthenticated. Other failures are thrown for the bootstrap to render.
  public async getSession(): Promise<AuthSession | null> {
    const res = await apiFetch(`${this.baseUrl}/api/auth/session`);
    if (res.status === 401) return null;
    if (!res.ok) {
      throw new Error(
        `Failed to get session (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<AuthSession>;
  }

  // switchOrganization establishes the session's active organization. The
  // server rotates session cookies; CSRF rules still apply.
  public async switchOrganization(orgId: string): Promise<SwitchOrgResponse> {
    const res = await apiFetch(`${this.baseUrl}/api/auth/switch-org`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": readCsrfToken(),
      },
      body: JSON.stringify({ organization_id: orgId }),
    });
    if (!res.ok) {
      throw new Error(
        `Failed to switch organization (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<SwitchOrgResponse>;
  }

  public async listRuns(
    environment: string,
    cursor?: string,
    limit = 25,
  ): Promise<ListRunsResponse> {
    // environment MUST be the canonical environment UUID. Bare names that
    // exist in several projects are ambiguous and rejected server-side.
    const params = new URLSearchParams({ environment });
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));

    const res = await apiFetch(`${this.baseUrl}/v1/runs?${params.toString()}`);
    if (!res.ok) {
      throw new Error(
        `Failed to list runs (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<ListRunsResponse>;
  }

  public async getRun(runId: string): Promise<RunSnapshot> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to get run (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<RunSnapshot>;
  }

  public async listWorkers(
    environment: string,
    cursor?: string,
    limit = 25,
  ): Promise<ListWorkersResponse> {
    // environment MUST be the canonical environment UUID (see listRuns).
    const params = new URLSearchParams({ environment });
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));

    const res = await apiFetch(
      `${this.baseUrl}/v1/workers?${params.toString()}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to list workers (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<ListWorkersResponse>;
  }

  public async getRunEvents(
    runId: string,
    cursor?: number,
    limit = 50,
  ): Promise<RunEventsResponse> {
    const params = new URLSearchParams();
    if (cursor !== undefined && cursor !== null) {
      params.set("cursor", String(cursor));
    }
    if (limit) {
      params.set("limit", String(limit));
    }
    const q = params.toString() ? `?${params.toString()}` : "";
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}/events${q}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to get run events (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<RunEventsResponse>;
  }

  public async getRunLogs(
    runId: string,
    stepId?: string,
    attemptId?: string,
    cursor?: string,
    limit = 50,
  ): Promise<TaskLogsResponse> {
    const params = new URLSearchParams();
    if (stepId) params.set("stepId", stepId);
    if (attemptId) params.set("attemptId", attemptId);
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));

    const q = params.toString() ? `?${params.toString()}` : "";
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}/logs${q}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to get run logs (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<TaskLogsResponse>;
  }

  // resolveReconciliationCase submits one audited human decision for an
  // unknown-outcome hold. The caller binds the expectedRevision read from
  // the snapshot; a 409 means the case changed and the dialog must refresh
  // instead of retrying blindly. Every decision carries an Idempotency-Key:
  // pass the dialog's key so an ambiguous resubmit reuses the same command
  // identity instead of creating a second decision.
  public async resolveReconciliationCase(
    caseId: string,
    body: ResolveReconciliationRequest,
    idempotencyKey?: string,
  ): Promise<ResolveReconciliationResponse> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/reconciliation-cases/${encodeURIComponent(caseId)}/resolve`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to resolve case (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<ResolveReconciliationResponse>;
  }

  // listApprovals returns the approvals inbox for the selected environment so an
  // operator can see every pending decision without hunting for it per run.
  public async listApprovals(
    environmentId: string,
    status?: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CANCELLED",
  ): Promise<Approval[]> {
    const q = new URLSearchParams({ environment: environmentId });
    if (status) q.set("status", status);
    const res = await apiFetch(`${this.baseUrl}/v1/approvals?${q.toString()}`);
    if (!res.ok) {
      throw new Error(
        `Failed to list approvals (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const body = (await res.json()) as { items?: Approval[] };
    return body.items ?? [];
  }

  // decideApproval commits one human approve/reject decision.
  //
  // Both outcomes are successful: the node's job was to collect a valid
  // decision, and a rejection is a business result rather than a failure. The
  // caller binds expectedRevision, so a 409 means someone else already acted
  // and the dialog must refresh instead of retrying blindly. Repeating the same
  // decision is idempotent.
  public async decideApproval(
    approvalId: string,
    decision: "approved" | "rejected",
    expectedRevision: number,
    comment?: string,
    idempotencyKey?: string,
  ): Promise<{ id: string; status: string; revision: number }> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/approvals/${encodeURIComponent(approvalId)}/decision`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({
          decision,
          expectedRevision,
          ...(comment ? { comment } : {}),
        }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to decide approval (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<{
      id: string;
      status: string;
      revision: number;
    }>;
  }

  // cancelRun requests durable cancellation. The caller binds the revision
  // read from the snapshot; a 409 means the run changed and the dialog must
  // refresh instead of retrying blindly. Cancelling never rolls back
  // external side effects already performed.
  public async cancelRun(
    runId: string,
    expectedRevision: number,
    idempotencyKey?: string,
  ): Promise<Run> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}/cancel`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expectedRevision }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to cancel run (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Run>;
  }

  // pauseRun requests durable pause. The caller binds expectedRevision;
  // a 409 means the run changed and the dialog must refresh instead of retrying blindly.
  public async pauseRun(
    runId: string,
    expectedRevision: number,
    idempotencyKey?: string,
  ): Promise<Run> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}/pause`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expectedRevision }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to pause run (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Run>;
  }

  // resumeRun resumes a paused or pausing run.
  public async resumeRun(
    runId: string,
    expectedRevision: number,
    idempotencyKey?: string,
  ): Promise<Run> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}/resume`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expectedRevision }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to resume run (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Run>;
  }

  // rerunRun creates a new run from an existing run.
  public async rerunRun(
    runId: string,
    options: { deploymentId?: string; input?: unknown },
    idempotencyKey?: string,
  ): Promise<Run> {
    const body: Record<string, unknown> = {};
    if (options.deploymentId !== undefined) {
      body.deploymentId = options.deploymentId;
    }
    if (options.input !== undefined) {
      body.input = options.input;
    }
    const res = await apiFetch(
      `${this.baseUrl}/v1/runs/${encodeURIComponent(runId)}/rerun`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to rerun run (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Run>;
  }

  // drainWorker requests graceful drain of an active worker.
  public async drainWorker(
    workerId: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/workers/${encodeURIComponent(workerId)}/drain`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to drain worker (HTTP ${res.status}): ${res.statusText}`,
      );
    }
  }

  // revokeWorker immediately revokes a worker and its sessions.
  public async revokeWorker(
    workerId: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/workers/${encodeURIComponent(workerId)}/revoke`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to revoke worker (HTTP ${res.status}): ${res.statusText}`,
      );
    }
  }

  // listDeployments lists registered deployments for the environment.
  public async listDeployments(
    environmentId: string,
    limit?: number,
    cursor?: string,
  ): Promise<{ items: any[]; nextCursor: string | null }> {
    const params = new URLSearchParams({ environment: environmentId });
    if (limit) params.set("limit", String(limit));
    if (cursor) params.set("cursor", cursor);
    const res = await apiFetch(
      `${this.baseUrl}/v1/deployments?${params.toString()}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to list deployments (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json();
  }

  // deleteDeployment deletes an unreferenced deployment registration.
  public async deleteDeployment(
    environmentId: string,
    deploymentId: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const params = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/deployments/${encodeURIComponent(deploymentId)}?${params.toString()}`,
      {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to delete deployment (HTTP ${res.status}): ${res.statusText}`,
      );
    }
  }

  // listWorkflows lists workflow channels and active deployments.
  public async listWorkflows(
    environmentId: string,
    limit?: number,
    cursor?: string,
  ): Promise<{ items: any[]; nextCursor: string | null }> {
    const params = new URLSearchParams({ environment: environmentId });
    if (limit) params.set("limit", String(limit));
    if (cursor) params.set("cursor", cursor);
    const res = await apiFetch(
      `${this.baseUrl}/v1/workflows?${params.toString()}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to list workflows (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json();
  }

  // activateWorkflow activates or rolls back a workflow deployment.
  public async activateWorkflow(
    environmentId: string,
    workflowName: string,
    deploymentId: string,
    expectedRevision: number,
    allowSingleWorker?: boolean,
    idempotencyKey?: string,
  ): Promise<any> {
    const params = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/workflows/${encodeURIComponent(workflowName)}/activate?${params.toString()}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({
          deploymentId,
          expectedRevision,
          allowSingleWorker: allowSingleWorker ?? false,
        }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to activate workflow deployment (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json();
  }

  // listSchedules returns the schedule definitions for the selected
  // environment. The backend requires the schedules:write capability; a 403
  // means the identity lacks it and the dashboard renders a capability
  // notice instead of schedule CTAs.
  public async listSchedules(environmentId: string): Promise<Schedule[]> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(`${this.baseUrl}/v1/schedules?${q.toString()}`);
    if (!res.ok) {
      throw new Error(
        `Failed to list schedules (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const body = (await res.json()) as { items?: Schedule[] };
    return body.items ?? [];
  }

  // createSchedule creates one schedule definition in the selected
  // environment. The caller passes the dialog's Idempotency-Key so an
  // ambiguous resubmit reuses the same command identity.
  public async createSchedule(
    environmentId: string,
    body: {
      workflow: string;
      cron: string;
      timezone: string;
      deploymentId?: string;
    },
    idempotencyKey?: string,
  ): Promise<Schedule> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(`${this.baseUrl}/v1/schedules?${q.toString()}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": readCsrfToken(),
        "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(
        `Failed to create schedule (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Schedule>;
  }

  // updateSchedule replaces the configuration of one schedule definition.
  // The caller binds expectedRevision read from the list; a 409 means the
  // schedule changed and the dialog must refresh instead of retrying
  // blindly.
  public async updateSchedule(
    scheduleId: string,
    environmentId: string,
    expectedRevision: number,
    configuration: {
      workflow: string;
      cron: string;
      timezone: string;
      deploymentId?: string;
    },
    idempotencyKey?: string,
  ): Promise<Schedule> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/schedules/${encodeURIComponent(scheduleId)}?${q.toString()}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expectedRevision, configuration }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to update schedule (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Schedule>;
  }

  // deleteSchedule removes one schedule definition. The server needs no body;
  // an empty object is sent with the standard mutation headers so CSRF and
  // idempotency handling stay uniform with the other schedule mutations.
  public async deleteSchedule(
    scheduleId: string,
    environmentId: string,
    idempotencyKey?: string,
  ): Promise<{ deleted: boolean; id: string }> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/schedules/${encodeURIComponent(scheduleId)}?${q.toString()}`,
      {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({}),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to delete schedule (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<{ deleted: boolean; id: string }>;
  }

  // pauseSchedule pauses one schedule definition. A 409 with code
  // INVALID_SCHEDULE_STATE means the schedule is already paused; a 409 with
  // REVISION_CONFLICT means the revision moved. Both refresh in-dialog.
  public async pauseSchedule(
    scheduleId: string,
    environmentId: string,
    expectedRevision: number,
    idempotencyKey?: string,
  ): Promise<Schedule> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/schedules/${encodeURIComponent(scheduleId)}/pause?${q.toString()}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expectedRevision }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to pause schedule (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Schedule>;
  }

  // resumeSchedule resumes a paused schedule definition.
  public async resumeSchedule(
    scheduleId: string,
    environmentId: string,
    expectedRevision: number,
    idempotencyKey?: string,
  ): Promise<Schedule> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/schedules/${encodeURIComponent(scheduleId)}/resume?${q.toString()}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expectedRevision }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to resume schedule (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<Schedule>;
  }

  // listScheduleOccurrences returns the decided slots of one schedule, newest
  // first, with keyset pagination. The dashboard renders skipped reasons
  // verbatim and never invents history client-side.
  public async listScheduleOccurrences(
    scheduleId: string,
    environmentId: string,
    limit?: number,
    cursor?: string,
  ): Promise<{ items: ScheduleOccurrence[]; nextCursor?: string | null }> {
    const q = new URLSearchParams({ environment: environmentId });
    if (limit) q.set("limit", String(limit));
    if (cursor) q.set("cursor", cursor);
    const res = await apiFetch(
      `${this.baseUrl}/v1/schedules/${encodeURIComponent(scheduleId)}/occurrences?${q.toString()}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to list schedule occurrences (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const body = (await res.json()) as {
      items?: ScheduleOccurrence[];
      nextCursor?: string | null;
    };
    return { items: body.items ?? [], nextCursor: body.nextCursor ?? null };
  }

  // listProjects discovers the active organization's projects through the
  // existing public tenant API using the BFF session cookie.
  public async listProjects(): Promise<ProjectSummary[]> {
    const res = await apiFetch(`${this.baseUrl}/v1/projects`);
    if (!res.ok) {
      throw new Error(
        `Failed to list projects (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const data = (await res.json()) as { projects?: ProjectSummary[] };
    return data.projects ?? [];
  }

  // listProjectEnvironments lists one project's environments through the
  // existing public tenant API using the BFF session cookie.
  public async listProjectEnvironments(
    projectId: string,
  ): Promise<EnvironmentSummary[]> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/projects/${encodeURIComponent(projectId)}/environments`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to list environments (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const data = (await res.json()) as {
      environments?: EnvironmentSummary[];
    };
    return data.environments ?? [];
  }

  // loadEnvironmentCatalog discovers every environment in the active
  // organization with project context. Callers MUST use environmentId as
  // the selector value and for runs/workers requests.
  public async loadEnvironmentCatalog(): Promise<CatalogEnvironment[]> {
    const projects = await this.listProjects();
    const catalog: CatalogEnvironment[] = [];
    for (const p of projects) {
      if (!p || !p.id) continue;
      const envs = await this.listProjectEnvironments(p.id);
      for (const e of envs) {
        if (!e || !e.id) continue;
        catalog.push({
          projectId: p.id,
          projectName: p.name ?? p.id,
          environmentId: e.id,
          environmentName: e.name ?? e.id,
        });
      }
    }
    return catalog;
  }

  // listWebhookEndpoints lists webhook endpoints in the current environment.
  public async listWebhookEndpoints(
    environmentId: string,
    limit?: number,
    cursor?: string,
  ): Promise<{ items: WebhookEndpoint[]; nextCursor?: string | null }> {
    const q = new URLSearchParams({ environment: environmentId });
    if (limit) q.set("limit", String(limit));
    if (cursor) q.set("cursor", cursor);
    const res = await apiFetch(
      `${this.baseUrl}/v1/webhook-endpoints?${q.toString()}`,
    );
    if (!res.ok) {
      throw new Error(
        `Failed to list webhook endpoints (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const body = (await res.json()) as {
      items?: WebhookEndpoint[];
      nextCursor?: string | null;
    };
    return { items: body.items ?? [], nextCursor: body.nextCursor ?? null };
  }

  // createWebhookEndpoint registers a new webhook endpoint.
  public async createWebhookEndpoint(
    environmentId: string,
    url: string,
    eventTypes: string[],
    enabled = true,
  ): Promise<WebhookEndpoint> {
    const q = new URLSearchParams({ environment: environmentId });
    const res = await apiFetch(
      `${this.baseUrl}/v1/webhook-endpoints?${q.toString()}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
        },
        body: JSON.stringify({ url, eventTypes, enabled }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to create webhook endpoint (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<WebhookEndpoint>;
  }

  // updateWebhookEndpoint updates URL, enabled status, or rotates secret.
  public async updateWebhookEndpoint(
    endpointId: string,
    expectedRevision: number,
    config?: { url?: string; enabled?: boolean; eventTypes?: string[] },
    rotateSecret?: boolean,
  ): Promise<WebhookEndpoint> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/webhook-endpoints/${encodeURIComponent(endpointId)}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
        },
        body: JSON.stringify({
          expectedRevision,
          configuration: config,
          rotateSecret: rotateSecret ?? false,
        }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to update webhook endpoint (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    return res.json() as Promise<WebhookEndpoint>;
  }

  // deleteWebhookEndpoint deletes a webhook endpoint.
  public async deleteWebhookEndpoint(
    endpointId: string,
    expectedRevision: number,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/webhook-endpoints/${encodeURIComponent(endpointId)}`,
      {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
        },
        body: JSON.stringify({ expectedRevision }),
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to delete webhook endpoint (HTTP ${res.status}): ${res.statusText}`,
      );
    }
  }

  // listWebhookDeliveries lists deliveries for a specific endpoint.
  public async listWebhookDeliveries(
    endpointId: string,
    limit?: number,
    cursor?: string,
  ): Promise<{ items: WebhookDelivery[]; nextCursor?: string | null }> {
    const q = new URLSearchParams();
    if (limit) q.set("limit", String(limit));
    if (cursor) q.set("cursor", cursor);
    const qs = q.toString();
    const url = `${this.baseUrl}/v1/webhook-endpoints/${encodeURIComponent(endpointId)}/deliveries${qs ? `?${qs}` : ""}`;
    const res = await apiFetch(url);
    if (!res.ok) {
      throw new Error(
        `Failed to list webhook deliveries (HTTP ${res.status}): ${res.statusText}`,
      );
    }
    const body = (await res.json()) as {
      items?: WebhookDelivery[];
      nextCursor?: string | null;
    };
    return { items: body.items ?? [], nextCursor: body.nextCursor ?? null };
  }

  // redeliverWebhook re-enqueues a webhook delivery, optionally to an explicit new destination endpoint.
  public async redeliverWebhook(
    deliveryId: string,
    newEndpointId?: string,
  ): Promise<WebhookDelivery> {
    const body: Record<string, string> = {};
    if (newEndpointId) {
      body.endpointId = newEndpointId;
    }
    const res = await apiFetch(
      `${this.baseUrl}/v1/webhook-deliveries/${encodeURIComponent(deliveryId)}/redeliver`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
        },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(
        res,
        "Failed to redeliver webhook",
      );
      throw new Error(errMsg);
    }
    return res.json() as Promise<WebhookDelivery>;
  }

  // listMembers lists all members of an organization.
  public async listMembers(orgId: string): Promise<OrganizationMember[]> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/organizations/${encodeURIComponent(orgId)}/members`,
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to list members");
      throw new Error(errMsg);
    }
    const body = (await res.json()) as { members?: OrganizationMember[] };
    return body.members ?? [];
  }

  // addMember adds a new member to an organization.
  public async addMember(
    orgId: string,
    userId: string,
    role: string,
    idempotencyKey?: string,
  ): Promise<OrganizationMember> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/organizations/${encodeURIComponent(orgId)}/members`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ userId, role }),
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to add member");
      throw new Error(errMsg);
    }
    return res.json() as Promise<OrganizationMember>;
  }

  // updateMemberRole updates a member's role.
  public async updateMemberRole(
    orgId: string,
    userId: string,
    role: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ role }),
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(
        res,
        "Failed to update member role",
      );
      throw new Error(errMsg);
    }
  }

  // updateMemberStatus updates a member's status (ACTIVE / SUSPENDED).
  public async updateMemberStatus(
    orgId: string,
    userId: string,
    status: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}/status`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ status }),
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(
        res,
        "Failed to update member status",
      );
      throw new Error(errMsg);
    }
  }

  // removeMember removes a member from an organization.
  public async removeMember(
    orgId: string,
    userId: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}`,
      {
        method: "DELETE",
        headers: {
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to remove member");
      throw new Error(errMsg);
    }
  }

  // listApiKeys lists all API keys for an environment.
  public async listApiKeys(envId: string): Promise<APIKeySummary[]> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/environments/${encodeURIComponent(envId)}/api-keys`,
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to list API keys");
      throw new Error(errMsg);
    }
    const body = (await res.json()) as { api_keys?: APIKeySummary[] };
    return body.api_keys ?? [];
  }

  // createApiKey creates a new machine API key for an environment.
  public async createApiKey(
    envId: string,
    capabilities: string[],
    expiryDays = 90,
    idempotencyKey?: string,
  ): Promise<GeneratedKey> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/environments/${encodeURIComponent(envId)}/api-keys`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ capabilities, expiry_days: expiryDays }),
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to create API key");
      throw new Error(errMsg);
    }
    return res.json() as Promise<GeneratedKey>;
  }

  // rotateApiKey rotates an existing API key, revoking the old one and returning a new plaintext secret.
  public async rotateApiKey(
    keyId: string,
    expiryDays = 90,
    idempotencyKey?: string,
  ): Promise<GeneratedKey> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/api-keys/${encodeURIComponent(keyId)}/rotate`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
        body: JSON.stringify({ expiry_days: expiryDays }),
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to rotate API key");
      throw new Error(errMsg);
    }
    return res.json() as Promise<GeneratedKey>;
  }

  // revokeApiKey revokes an existing API key immediately.
  public async revokeApiKey(
    keyId: string,
    idempotencyKey?: string,
  ): Promise<void> {
    const res = await apiFetch(
      `${this.baseUrl}/v1/api-keys/${encodeURIComponent(keyId)}`,
      {
        method: "DELETE",
        headers: {
          "X-CSRF-Token": readCsrfToken(),
          "Idempotency-Key": idempotencyKey ?? newIdempotencyKey(),
        },
      },
    );
    if (!res.ok) {
      const errMsg = await extractErrorMessage(res, "Failed to revoke API key");
      throw new Error(errMsg);
    }
  }
}

async function extractErrorMessage(
  res: Response,
  defaultPrefix: string,
): Promise<string> {
  try {
    const data = (await res.json()) as { message?: string; code?: string };
    if (data && typeof data.message === "string" && data.message.length > 0) {
      return data.message;
    }
    if (data && typeof data.code === "string" && data.code.length > 0) {
      return data.code;
    }
  } catch {
    // fallback
  }
  return `${defaultPrefix} (HTTP ${res.status}): ${res.statusText}`;
}
