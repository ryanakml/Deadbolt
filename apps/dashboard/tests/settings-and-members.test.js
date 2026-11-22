import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DashboardApiClient } from "../dist/api.js";

function installFetch(handler) {
  const orig = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (input, init = {}) => {
    seen.push([String(input), init]);
    return handler(String(input), init);
  };
  return {
    seen,
    restore() {
      globalThis.fetch = orig;
    },
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("DashboardApiClient members wire integration", () => {
  test("list, add, update role/status, remove members", async () => {
    const f = installFetch((url, init) => {
      const method = (init?.method || "GET").toUpperCase();
      if (url.includes("/members") && method === "GET") {
        return jsonResponse({
          members: [
            {
              id: "mem-1",
              organizationId: "org-1",
              userId: "u-1",
              role: "owner",
              status: "ACTIVE",
              createdAt: "2026-11-22T08:00:00Z",
              updatedAt: "2026-11-22T08:00:00Z",
            },
          ],
        });
      }
      if (url.includes("/members") && method === "POST") {
        const body = JSON.parse(init.body);
        return jsonResponse(
          {
            id: "mem-2",
            organizationId: "org-1",
            userId: body.userId,
            role: body.role,
            status: "ACTIVE",
            createdAt: "2026-11-22T08:00:00Z",
            updatedAt: "2026-11-22T08:00:00Z",
          },
          201,
        );
      }
      if (url.includes("/status") && method === "PATCH") {
        return jsonResponse({ status: "updated" });
      }
      if (method === "PATCH") {
        return jsonResponse({ status: "updated" });
      }
      if (method === "DELETE") {
        return new Response(null, { status: 204 });
      }
      return jsonResponse({});
    });

    try {
      const client = new DashboardApiClient("https://controlplane.example.com");

      // 1. List members
      const members = await client.listMembers("org-1");
      assert.equal(members.length, 1);
      assert.equal(members[0].role, "owner");
      assert.equal(
        f.seen[0][0],
        "https://controlplane.example.com/v1/organizations/org-1/members",
      );

      // 2. Add member
      const newMember = await client.addMember(
        "org-1",
        "u-2",
        "viewer",
        "idemp-add-1",
      );
      assert.equal(newMember.userId, "u-2");
      assert.equal(f.seen[1][1].method, "POST");
      assert.equal(f.seen[1][1].headers["Idempotency-Key"], "idemp-add-1");
      assert.equal(
        f.seen[1][1].body,
        JSON.stringify({ userId: "u-2", role: "viewer" }),
      );

      // 3. Update role
      await client.updateMemberRole("org-1", "u-2", "operator", "idemp-role-1");
      assert.equal(f.seen[2][1].method, "PATCH");
      assert.equal(
        f.seen[2][0],
        "https://controlplane.example.com/v1/organizations/org-1/members/u-2",
      );
      assert.equal(f.seen[2][1].headers["Idempotency-Key"], "idemp-role-1");
      assert.equal(f.seen[2][1].body, JSON.stringify({ role: "operator" }));

      // 4. Update status
      await client.updateMemberStatus(
        "org-1",
        "u-2",
        "SUSPENDED",
        "idemp-status-1",
      );
      assert.equal(f.seen[3][1].method, "PATCH");
      assert.equal(
        f.seen[3][0],
        "https://controlplane.example.com/v1/organizations/org-1/members/u-2/status",
      );
      assert.equal(f.seen[3][1].headers["Idempotency-Key"], "idemp-status-1");
      assert.equal(f.seen[3][1].body, JSON.stringify({ status: "SUSPENDED" }));

      // 5. Remove member
      await client.removeMember("org-1", "u-2", "idemp-rm-1");
      assert.equal(f.seen[4][1].method, "DELETE");
      assert.equal(
        f.seen[4][0],
        "https://controlplane.example.com/v1/organizations/org-1/members/u-2",
      );
      assert.equal(f.seen[4][1].headers["Idempotency-Key"], "idemp-rm-1");
    } finally {
      f.restore();
    }
  });
});

describe("DashboardApiClient API keys wire integration", () => {
  test("list, create (once), rotate (once), revoke", async () => {
    const f = installFetch((url, init) => {
      const method = (init?.method || "GET").toUpperCase();
      if (url.includes("/api-keys") && method === "GET") {
        return jsonResponse({
          api_keys: [
            {
              id: "key-1",
              environmentId: "env-prod",
              environmentName: "production",
              prefix: "db_production_12345678",
              capabilities: ["runs:read", "runs:create"],
              createdAt: "2026-11-22T08:00:00Z",
            },
          ],
        });
      }
      if (
        url.includes("/environments/") &&
        url.includes("/api-keys") &&
        method === "POST"
      ) {
        return jsonResponse(
          {
            id: "key-new",
            prefix: "db_production_87654321",
            key: "db_production_87654321_secrettokenstring12345",
            environmentId: "env-prod",
            environmentName: "production",
            capabilities: ["runs:read"],
            createdAt: "2026-11-22T08:00:00Z",
          },
          201,
        );
      }
      if (url.includes("/rotate") && method === "POST") {
        return jsonResponse({
          id: "key-rotated",
          prefix: "db_production_abcdef01",
          key: "db_production_abcdef01_rotatedtokenstring54321",
          environmentId: "env-prod",
          environmentName: "production",
          capabilities: ["runs:read", "runs:create"],
          createdAt: "2026-11-22T08:00:00Z",
        });
      }
      if (method === "DELETE") {
        return new Response(null, { status: 204 });
      }
      return jsonResponse({});
    });

    try {
      const client = new DashboardApiClient("https://controlplane.example.com");

      // 1. List API keys
      const keys = await client.listApiKeys("env-prod");
      assert.equal(keys.length, 1);
      assert.equal(keys[0].prefix, "db_production_12345678");

      // 2. Create API key (shows secret once)
      const created = await client.createApiKey(
        "env-prod",
        ["runs:read"],
        90,
        "idemp-key-1",
      );
      assert.equal(
        created.key,
        "db_production_87654321_secrettokenstring12345",
      );
      assert.equal(f.seen[1][1].method, "POST");
      assert.equal(f.seen[1][1].headers["Idempotency-Key"], "idemp-key-1");
      assert.equal(
        f.seen[1][1].body,
        JSON.stringify({ capabilities: ["runs:read"], expiry_days: 90 }),
      );

      // 3. Rotate API key (returns new secret)
      const rotated = await client.rotateApiKey("key-1", 90, "idemp-key-rot-1");
      assert.equal(
        rotated.key,
        "db_production_abcdef01_rotatedtokenstring54321",
      );
      assert.equal(f.seen[2][1].method, "POST");
      assert.equal(f.seen[2][1].headers["Idempotency-Key"], "idemp-key-rot-1");
      assert.equal(f.seen[2][1].body, JSON.stringify({ expiry_days: 90 }));

      // 4. Revoke API key
      await client.revokeApiKey("key-1", "idemp-key-rev-1");
      assert.equal(f.seen[3][1].method, "DELETE");
      assert.equal(
        f.seen[3][0],
        "https://controlplane.example.com/v1/api-keys/key-1",
      );
      assert.equal(f.seen[3][1].headers["Idempotency-Key"], "idemp-key-rev-1");
    } finally {
      f.restore();
    }
  });
});

describe("DashboardApiClient webhook redelivery destination choice", () => {
  test("redeliver webhook with and without explicit endpoint destination", async () => {
    const f = installFetch((url, init) => {
      const parsedBody = init?.body ? JSON.parse(init.body) : {};
      return jsonResponse({
        id: "del-redelivered",
        endpointId: parsedBody.endpointId || "ep-orig",
        endpointRevision: 1,
        eventId: "evt-001",
        eventType: "run.succeeded",
        payload: {},
        attempts: 0,
        status: "PENDING",
        nextAt: "2026-11-22T08:00:00Z",
        createdAt: "2026-11-22T08:00:00Z",
      });
    });

    try {
      const client = new DashboardApiClient("https://controlplane.example.com");

      // 1. Redeliver without destination choice (defaults to original)
      const d1 = await client.redeliverWebhook("del-1");
      assert.equal(d1.id, "del-redelivered");
      assert.equal(f.seen[0][1].body, JSON.stringify({}));

      // 2. Redeliver with explicit new destination endpoint
      const d2 = await client.redeliverWebhook("del-1", "ep-explicit-dest");
      assert.equal(d2.endpointId, "ep-explicit-dest");
      assert.equal(
        f.seen[1][1].body,
        JSON.stringify({ endpointId: "ep-explicit-dest" }),
      );
    } finally {
      f.restore();
    }
  });
});

describe("DashboardApiClient visible error messages", () => {
  test("extracts server error message for last owner demotion violation", async () => {
    const f = installFetch(() => {
      return jsonResponse(
        {
          code: "LAST_OWNER_DEMOTION_FORBIDDEN",
          message: "Cannot demote the sole active owner of the organization",
          requestId: "req-123",
          retryable: false,
        },
        403,
      );
    });

    try {
      const client = new DashboardApiClient("https://controlplane.example.com");

      await assert.rejects(
        async () => {
          await client.updateMemberRole("org-1", "u-owner", "viewer");
        },
        (err) => {
          assert.match(err.message, /Cannot demote the sole active owner/);
          return true;
        },
      );
    } finally {
      f.restore();
    }
  });
});
