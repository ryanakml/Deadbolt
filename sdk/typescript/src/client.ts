import { createHmac, timingSafeEqual } from "node:crypto";
import { ContractError, fail, type JSONValue } from "./json.js";
import type { RunStatus, StepStatus } from "./enums.js";
import { type ObjectValue } from "./schema.js";

export interface WebhookEndpoint {
  id: string;
  url: string;
  enabled: boolean;
  revision: number;
  eventTypes: string[];
  secret?: string;
  signingKeyId?: string;
}

export interface WebhookDelivery {
  id: string;
  endpointId: string;
  endpointRevision: number;
  eventId: string;
  eventType: string;
  runId?: string;
  payload: Record<string, unknown>;
  attempts: number;
  status: "PENDING" | "DELIVERED" | "FAILED" | "CANCELLED";
  nextAt: string;
  deliveredAt?: string;
  lastStatusCode?: number;
  lastError?: string;
  responseSnippet?: string;
  createdAt: string;
  completedAt?: string;
}

/**
 * Verifies that a webhook request came from Deadbolt by checking the HMAC-SHA256
 * signature over timestamp.body and ensuring the timestamp is within tolerance.
 */
export function verifyWebhookSignature(
  secret: string,
  timestamp: number,
  body: string | Buffer,
  signatureHex: string,
  toleranceSeconds = 300,
): boolean {
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > toleranceSeconds) {
    return false;
  }
  const payloadToSign = `${timestamp}.${typeof body === "string" ? body : body.toString("utf8")}`;
  const hmac = createHmac("sha256", secret);
  hmac.update(payloadToSign);
  const expectedHex = hmac.digest("hex");
  if (expectedHex.length !== signatureHex.length) {
    return false;
  }
  return timingSafeEqual(
    Buffer.from(expectedHex, "hex"),
    Buffer.from(signatureHex, "hex"),
  );
}

export interface ErrorEnvelope {
  code: string;
  message: string;
  requestId?: string;
  details?: JSONValue;
  retryable?: boolean;
}

export class DeadboltApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly details?: JSONValue;
  readonly retryable?: boolean;

  constructor(status: number, envelope: ErrorEnvelope) {
    super(`[${status}] ${envelope.code}: ${envelope.message}`);
    this.name = "DeadboltApiError";
    this.status = status;
    this.code = envelope.code;
    this.requestId = envelope.requestId;
    this.details = envelope.details;
    this.retryable = envelope.retryable;
  }
}

export class DeadboltExecutionError extends Error {
  readonly code: string;
  readonly snapshot: RunSnapshot;

  constructor(code: string, message: string, snapshot: RunSnapshot) {
    super(message);
    this.name = "DeadboltExecutionError";
    this.code = code;
    this.snapshot = snapshot;
  }
}

export class DeadboltTimeoutError extends Error {
  constructor(message = "Polling timed out waiting for run to complete") {
    super(message);
    this.name = "DeadboltTimeoutError";
  }
}

export interface Run {
  readonly id: string;
  readonly organizationId?: string;
  readonly projectId?: string;
  readonly environmentId?: string;
  readonly workflowName: string;
  readonly deploymentId: string;
  readonly status: RunStatus;
  readonly reasonCode?: string;
  readonly revision: number;
  readonly createdAt: string;
  readonly deadlineAt?: string;
  /** HTTP 202 Accepted denotes persisted acceptance in the control plane, not completion. */
  readonly isAccepted: boolean;
}

export interface RunStep {
  readonly id: string;
  readonly nodeId: string;
  readonly status: StepStatus;
  readonly waitReason?: string;
  readonly dueAt?: string;
  readonly currentEpoch?: number;
  readonly attempts?: readonly unknown[];
}

export interface RunSnapshot extends Run {
  readonly lastEventSequence: number;
  readonly steps: readonly RunStep[];
  readonly output?: JSONValue;
  readonly error?: ErrorEnvelope;
}

export interface DeadboltClientOptions {
  baseUrl?: string;
  apiKey?: string;
  environment?: string;
  fetch?: typeof fetch;
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
}

export interface CreateRunOptions {
  workflow: string;
  input: JSONValue;
  /** Mandatory idempotency key to prevent duplicate runs per Blueprint §14.2 & §20.1 */
  idempotencyKey: string;
  environment?: string;
  deploymentId?: string;
}

export interface PollOptions {
  intervalMs?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export class DeadboltClient {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly defaultEnvironment: string;
  private readonly customFetch: typeof fetch;
  readonly defaultPollIntervalMs: number;
  readonly defaultPollTimeoutMs: number;

  constructor(options: DeadboltClientOptions = {}) {
    const envUrl =
      typeof process !== "undefined" && process.env?.DEADBOLT_API_URL
        ? process.env.DEADBOLT_API_URL
        : undefined;
    this.baseUrl = (
      options.baseUrl ??
      envUrl ??
      "http://localhost:8080"
    ).replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.defaultEnvironment = options.environment ?? "development";
    this.customFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.defaultPollIntervalMs = options.pollIntervalMs ?? 500;
    this.defaultPollTimeoutMs = options.pollTimeoutMs ?? 60000;
  }

  private async request<T>(
    method: string,
    path: string,
    headers: Record<string, string> = {},
    body?: unknown,
  ): Promise<{ status: number; data: T }> {
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const reqHeaders: Record<string, string> = {
      Accept: "application/json",
      ...headers,
    };

    if (this.apiKey && !reqHeaders.Authorization) {
      reqHeaders.Authorization = `Bearer ${this.apiKey}`;
    }

    let reqBody: string | undefined;
    if (body !== undefined) {
      reqHeaders["Content-Type"] = "application/json";
      reqBody = JSON.stringify(body);
    }

    const response = await this.customFetch(url, {
      method,
      headers: reqHeaders,
      body: reqBody,
    });

    let data: any;
    const text = await response.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { code: "INVALID_JSON_RESPONSE", message: text };
      }
    }

    if (!response.ok) {
      const envelope: ErrorEnvelope = {
        code: data?.code ?? `HTTP_${response.status}`,
        message: data?.message ?? response.statusText,
        requestId: data?.requestId,
        details: data?.details,
        retryable: data?.retryable,
      };
      throw new DeadboltApiError(response.status, envelope);
    }

    return { status: response.status, data: data as T };
  }

  readonly runs = {
    /**
     * Creates and enqueues a new workflow run.
     * Enforces Idempotency-Key header.
     * HTTP 202 response represents persisted acceptance in the control plane, not completion.
     */
    create: async (options: CreateRunOptions): Promise<Run> => {
      if (
        !options.idempotencyKey ||
        typeof options.idempotencyKey !== "string" ||
        options.idempotencyKey.trim() === ""
      ) {
        fail("MISSING_IDEMPOTENCY_KEY");
      }

      const workflowName = options.workflow;
      const environment = options.environment ?? this.defaultEnvironment;

      const body: Record<string, unknown> = {
        environment,
        input: options.input,
      };
      if (options.deploymentId) {
        body.deploymentId = options.deploymentId;
      }

      const res = await this.request<Run>(
        "POST",
        `/v1/workflows/${encodeURIComponent(workflowName)}/runs`,
        { "Idempotency-Key": options.idempotencyKey },
        body,
      );

      // HTTP 202 is persisted acceptance per Blueprint §4.3 & §20.1
      return {
        ...res.data,
        isAccepted: res.status === 202,
      };
    },

    /**
     * Retrieves the current snapshot of a run.
     */
    get: async (runId: string): Promise<RunSnapshot> => {
      if (!runId || typeof runId !== "string") {
        fail("INVALID_RUN_ID");
      }
      const res = await this.request<RunSnapshot>(
        "GET",
        `/v1/runs/${encodeURIComponent(runId)}`,
      );
      return {
        ...res.data,
        isAccepted: true,
      };
    },

    /**
     * Gets the current status of a run.
     */
    getStatus: async (
      runId: string,
    ): Promise<{
      id: string;
      status: RunStatus;
      revision: number;
      reasonCode?: string;
    }> => {
      const snapshot = await this.runs.get(runId);
      return {
        id: snapshot.id,
        status: snapshot.status,
        revision: snapshot.revision,
        reasonCode: snapshot.reasonCode,
      };
    },

    /**
     * Polls the run status until completion (SUCCEEDED, FAILED, CANCELLED).
     * Returns the output on SUCCEEDED, or throws DeadboltExecutionError on failure.
     */
    pollResult: async (
      runId: string,
      options: PollOptions = {},
    ): Promise<JSONValue | undefined> => {
      const intervalMs = options.intervalMs ?? this.defaultPollIntervalMs;
      const timeoutMs = options.timeoutMs ?? this.defaultPollTimeoutMs;
      const startTime = Date.now();

      while (true) {
        if (options.signal?.aborted) {
          throw new ContractError("ABORTED", "Polling aborted by signal");
        }

        const snapshot = await this.runs.get(runId);

        if (snapshot.status === "SUCCEEDED") {
          return snapshot.output;
        }

        if (snapshot.status === "FAILED") {
          throw new DeadboltExecutionError(
            "RUN_FAILED",
            snapshot.reasonCode || snapshot.error?.message || "Run failed",
            snapshot,
          );
        }

        if (snapshot.status === "CANCELLED") {
          throw new DeadboltExecutionError(
            "RUN_CANCELLED",
            snapshot.reasonCode || "Run cancelled",
            snapshot,
          );
        }

        if (Date.now() - startTime >= timeoutMs) {
          throw new DeadboltTimeoutError(
            `Timed out after ${timeoutMs}ms waiting for run ${runId} to complete (current status: ${snapshot.status})`,
          );
        }

        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      }
    },

    /**
     * Requests a durable pause on an active run with expectedRevision check.
     */
    pause: async (
      runId: string,
      expectedRevision: number,
      idempotencyKey?: string,
    ): Promise<Run> => {
      if (!runId || typeof runId !== "string") {
        fail("INVALID_RUN_ID");
      }
      const headers: Record<string, string> = {
        "Idempotency-Key": idempotencyKey || `pause-${runId}-${Date.now()}`,
      };
      const res = await this.request<Run>(
        "POST",
        `/v1/runs/${encodeURIComponent(runId)}/pause`,
        headers,
        { expectedRevision },
      );
      return res.data;
    },

    /**
     * Resumes a paused or pausing run with expectedRevision check.
     */
    resume: async (
      runId: string,
      expectedRevision: number,
      idempotencyKey?: string,
    ): Promise<Run> => {
      if (!runId || typeof runId !== "string") {
        fail("INVALID_RUN_ID");
      }
      const headers: Record<string, string> = {
        "Idempotency-Key": idempotencyKey || `resume-${runId}-${Date.now()}`,
      };
      const res = await this.request<Run>(
        "POST",
        `/v1/runs/${encodeURIComponent(runId)}/resume`,
        headers,
        { expectedRevision },
      );
      return res.data;
    },

    /**
     * Requests durable cancellation on an active run with expectedRevision check.
     */
    cancel: async (
      runId: string,
      expectedRevision: number,
      idempotencyKey?: string,
    ): Promise<Run> => {
      if (!runId || typeof runId !== "string") {
        fail("INVALID_RUN_ID");
      }
      const headers: Record<string, string> = {
        "Idempotency-Key": idempotencyKey || `cancel-${runId}-${Date.now()}`,
      };
      const res = await this.request<Run>(
        "POST",
        `/v1/runs/${encodeURIComponent(runId)}/cancel`,
        headers,
        { expectedRevision },
      );
      return res.data;
    },

    /**
     * Reruns an existing workflow execution from the beginning as a new run
     * with fresh operation IDs. Preserves original deployment and input by default.
     */
    rerun: async (options: {
      runId: string;
      idempotencyKey?: string;
      deploymentId?: string;
      input?: unknown;
    }): Promise<Run> => {
      if (!options.runId || typeof options.runId !== "string") {
        fail("INVALID_RUN_ID");
      }
      const headers: Record<string, string> = {
        "Idempotency-Key":
          options.idempotencyKey || `rerun-${options.runId}-${Date.now()}`,
      };
      const body: Record<string, unknown> = {};
      if (options.deploymentId !== undefined) {
        body.deploymentId = options.deploymentId;
      }
      if (options.input !== undefined) {
        body.input = options.input;
      }
      const res = await this.request<Run>(
        "POST",
        `/v1/runs/${encodeURIComponent(options.runId)}/rerun`,
        headers,
        body,
      );
      return res.data;
    },
  };

  readonly deployments = {
    /**
     * Registers an immutable deployment manifest in the control plane.
     */
    register: async (
      manifest: ObjectValue,
    ): Promise<{ id: string; status: string }> => {
      const res = await this.request<{ id: string; status: string }>(
        "POST",
        "/v1/deployments",
        {},
        manifest,
      );
      return res.data;
    },

    /**
     * Lists registered deployments for the environment.
     */
    list: async (options?: {
      limit?: number;
      cursor?: string;
    }): Promise<{
      items: Array<{
        id: string;
        manifestHash: string;
        bundleDigest: string;
        status: string;
        createdAt: string;
        compatibilityWarningAt?: string | null;
      }>;
      nextCursor: string | null;
    }> => {
      const q = new URLSearchParams();
      if (options?.limit) q.set("limit", String(options.limit));
      if (options?.cursor) q.set("cursor", options.cursor);
      const suffix = q.toString() ? `?${q.toString()}` : "";
      const res = await this.request<{
        items: Array<{
          id: string;
          manifestHash: string;
          bundleDigest: string;
          status: string;
          createdAt: string;
          compatibilityWarningAt?: string | null;
        }>;
        nextCursor: string | null;
      }>("GET", `/v1/deployments${suffix}`);
      return res.data;
    },

    /**
     * Deletes an unreferenced deployment registration.
     */
    delete: async (
      deploymentId: string,
      idempotencyKey?: string,
    ): Promise<void> => {
      const headers: Record<string, string> = {
        "Idempotency-Key":
          idempotencyKey || `delete-dep-${deploymentId}-${Date.now()}`,
      };
      await this.request<void>(
        "DELETE",
        `/v1/deployments/${encodeURIComponent(deploymentId)}`,
        headers,
      );
    },
  };

  readonly workflows = {
    /**
     * Activates a deployment for new workflow runs.
     */
    activate: async (options: {
      workflowName: string;
      deploymentId: string;
      expectedRevision: number;
      allowSingleWorker?: boolean;
      idempotencyKey?: string;
    }): Promise<{
      name: string;
      activeDeploymentId: string | null;
      revision: number;
      warning?: string;
    }> => {
      const headers: Record<string, string> = {
        "Idempotency-Key":
          options.idempotencyKey ||
          `activate-${options.workflowName}-${Date.now()}`,
      };
      const res = await this.request<{
        name: string;
        activeDeploymentId: string | null;
        revision: number;
        warning?: string;
      }>(
        "POST",
        `/v1/workflows/${encodeURIComponent(options.workflowName)}/activate`,
        headers,
        {
          deploymentId: options.deploymentId,
          expectedRevision: options.expectedRevision,
          allowSingleWorker: options.allowSingleWorker ?? false,
        },
      );
      return res.data;
    },

    /**
     * Lists workflows in the environment.
     */
    list: async (options?: {
      limit?: number;
      cursor?: string;
    }): Promise<{
      items: Array<{
        name: string;
        activeDeploymentId: string | null;
        revision: number;
        warning?: string;
      }>;
      nextCursor: string | null;
    }> => {
      const q = new URLSearchParams();
      if (options?.limit) q.set("limit", String(options.limit));
      if (options?.cursor) q.set("cursor", options.cursor);
      const suffix = q.toString() ? `?${q.toString()}` : "";
      const res = await this.request<{
        items: Array<{
          name: string;
          activeDeploymentId: string | null;
          revision: number;
          warning?: string;
        }>;
        nextCursor: string | null;
      }>("GET", `/v1/workflows${suffix}`);
      return res.data;
    },
  };

  readonly artifacts = {
    /**
     * Reserves an upload for one attempt: enforces caps/quota, binds live
     * ownership, and returns the artifact id plus a single-object PUT URL.
     */
    create: async (options: {
      runId: string;
      attemptId: string;
      ownershipEpoch: number;
      sizeBytes: number;
      sha256: string;
      idempotencyKey: string;
    }): Promise<{ id: string; uploadUrl: string; expiresAt: string }> => {
      const res = await this.request<{
        id: string;
        uploadUrl: string;
        expiresAt: string;
      }>(
        "POST",
        "/v1/artifacts",
        { "Idempotency-Key": options.idempotencyKey },
        {
          runId: options.runId,
          attemptId: options.attemptId,
          ownershipEpoch: options.ownershipEpoch,
          sizeBytes: options.sizeBytes,
          sha256: options.sha256,
        },
      );
      return res.data;
    },
    /**
     * Finalizes an upload after verifying size and SHA-256 server-side.
     */
    finalize: async (options: {
      id: string;
      attemptId: string;
      ownershipEpoch: number;
      sha256: string;
      idempotencyKey: string;
    }): Promise<{ id: string; status: string }> => {
      const res = await this.request<{ id: string; status: string }>(
        "POST",
        `/v1/artifacts/${encodeURIComponent(options.id)}/finalize`,
        { "Idempotency-Key": options.idempotencyKey },
        {
          attemptId: options.attemptId,
          ownershipEpoch: options.ownershipEpoch,
          sha256: options.sha256,
        },
      );
      return res.data;
    },
    /**
     * Mints a short-lived attachment download URL for a READY artifact.
     */
    downloadUrl: async (
      id: string,
    ): Promise<{ id: string; downloadUrl: string; expiresAt: string }> => {
      const res = await this.request<{
        id: string;
        downloadUrl: string;
        expiresAt: string;
      }>("GET", `/v1/artifacts/${encodeURIComponent(id)}`);
      return res.data;
    },
  };

  readonly webhooks = {
    /**
     * Lists webhook endpoints in the environment.
     */
    list: async (
      environment: string,
      options?: { limit?: number; cursor?: string },
    ): Promise<{ items: WebhookEndpoint[]; nextCursor: string | null }> => {
      const q = new URLSearchParams({ environment });
      if (options?.limit) q.set("limit", String(options.limit));
      if (options?.cursor) q.set("cursor", options.cursor);
      const res = await this.request<{
        items: WebhookEndpoint[];
        nextCursor: string | null;
      }>("GET", `/v1/webhook-endpoints?${q.toString()}`);
      return res.data;
    },

    /**
     * Registers a new webhook endpoint in the environment.
     */
    create: async (
      environment: string,
      options: {
        url: string;
        enabled: boolean;
        eventTypes: string[];
        idempotencyKey?: string;
      },
    ): Promise<WebhookEndpoint> => {
      const q = new URLSearchParams({ environment });
      const headers: Record<string, string> = {};
      if (options.idempotencyKey) {
        headers["Idempotency-Key"] = options.idempotencyKey;
      }
      const res = await this.request<WebhookEndpoint>(
        "POST",
        `/v1/webhook-endpoints?${q.toString()}`,
        headers,
        {
          url: options.url,
          enabled: options.enabled,
          eventTypes: options.eventTypes,
        },
      );
      return res.data;
    },

    /**
     * Updates an existing webhook endpoint configuration with optimistic revision CAS.
     */
    update: async (
      id: string,
      options: {
        expectedRevision: number;
        configuration?: {
          url?: string;
          enabled?: boolean;
          eventTypes?: string[];
        };
        rotateSecret?: boolean;
        idempotencyKey?: string;
      },
    ): Promise<WebhookEndpoint> => {
      const headers: Record<string, string> = {};
      if (options.idempotencyKey) {
        headers["Idempotency-Key"] = options.idempotencyKey;
      }
      const res = await this.request<WebhookEndpoint>(
        "PATCH",
        `/v1/webhook-endpoints/${encodeURIComponent(id)}`,
        headers,
        {
          expectedRevision: options.expectedRevision,
          configuration: options.configuration,
          rotateSecret: options.rotateSecret,
        },
      );
      return res.data;
    },

    /**
     * Deletes a webhook endpoint.
     */
    delete: async (
      id: string,
      expectedRevision: number,
      options?: { idempotencyKey?: string },
    ): Promise<{ deleted: boolean }> => {
      const headers: Record<string, string> = {};
      if (options?.idempotencyKey) {
        headers["Idempotency-Key"] = options.idempotencyKey;
      }
      const res = await this.request<{ deleted: boolean }>(
        "DELETE",
        `/v1/webhook-endpoints/${encodeURIComponent(id)}`,
        headers,
        { expectedRevision },
      );
      return res.data;
    },

    /**
     * Lists delivery attempts for an endpoint.
     */
    listDeliveries: async (
      endpointId: string,
      options?: { limit?: number; cursor?: string },
    ): Promise<{ items: WebhookDelivery[]; nextCursor: string | null }> => {
      const q = new URLSearchParams();
      if (options?.limit) q.set("limit", String(options.limit));
      if (options?.cursor) q.set("cursor", options.cursor);
      const suffix = q.toString() ? `?${q.toString()}` : "";
      const res = await this.request<{
        items: WebhookDelivery[];
        nextCursor: string | null;
      }>(
        "GET",
        `/v1/webhook-endpoints/${encodeURIComponent(endpointId)}/deliveries${suffix}`,
      );
      return res.data;
    },

    /**
     * Re-dispatches an existing event delivery to the endpoint's current active revision,
     * or to an explicit new destination endpoint when endpointId is specified.
     */
    redeliver: async (
      deliveryId: string,
      options?: { endpointId?: string; idempotencyKey?: string },
    ): Promise<WebhookDelivery> => {
      const headers: Record<string, string> = {};
      if (options?.idempotencyKey) {
        headers["Idempotency-Key"] = options.idempotencyKey;
      }
      const body = options?.endpointId
        ? { endpointId: options.endpointId }
        : undefined;
      const res = await this.request<WebhookDelivery>(
        "POST",
        `/v1/webhook-deliveries/${encodeURIComponent(deliveryId)}/redeliver`,
        headers,
        body,
      );
      return res.data;
    },
  };
}
