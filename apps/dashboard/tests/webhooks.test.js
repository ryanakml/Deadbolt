import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DashboardApiClient } from "../dist/api.js";
import {
  roleCanManageWebhooks,
  sessionCanManageWebhooks,
  WEBHOOKS_WRITE_CAPABILITY,
} from "../dist/permissions.js";

function sessionWithRole(role, status = "ACTIVE", orgId = "org-1") {
  return {
    user: { id: "u-1", email: "op@example.com", name: "Op" },
    active_organization_id: orgId,
    memberships: [
      {
        OrganizationID: orgId,
        OrganizationName: "Acme",
        Role: role,
        Status: status,
      },
    ],
  };
}

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

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status });
}

describe("webhooks:write permissions", () => {
  test("roleCanManageWebhooks mirrors RBAC: operator, admin, owner true; developer, viewer false", () => {
    assert.equal(roleCanManageWebhooks("viewer"), false);
    assert.equal(roleCanManageWebhooks("developer"), false);
    assert.equal(roleCanManageWebhooks("operator"), true);
    assert.equal(roleCanManageWebhooks("admin"), true);
    assert.equal(roleCanManageWebhooks("owner"), true);
    assert.equal(roleCanManageWebhooks(""), false);
    assert.equal(roleCanManageWebhooks(null), false);
    assert.equal(roleCanManageWebhooks(undefined), false);
  });

  test("sessionCanManageWebhooks respects role, status, and active org", () => {
    assert.equal(
      sessionCanManageWebhooks(sessionWithRole("operator"), "org-1"),
      true,
    );
    assert.equal(
      sessionCanManageWebhooks(sessionWithRole("admin"), "org-1"),
      true,
    );
    assert.equal(
      sessionCanManageWebhooks(sessionWithRole("owner"), "org-1"),
      true,
    );

    // developer & viewer denied
    assert.equal(
      sessionCanManageWebhooks(sessionWithRole("developer"), "org-1"),
      false,
    );
    assert.equal(
      sessionCanManageWebhooks(sessionWithRole("viewer"), "org-1"),
      false,
    );

    // inactive status fails closed
    assert.equal(
      sessionCanManageWebhooks(
        sessionWithRole("operator", "SUSPENDED"),
        "org-1",
      ),
      false,
    );

    // org mismatch fails closed
    assert.equal(
      sessionCanManageWebhooks(sessionWithRole("admin"), "org-other"),
      false,
    );
    assert.equal(sessionCanManageWebhooks(null, "org-1"), false);
  });
});

describe("DashboardApiClient webhooks wire integration", () => {
  test("listWebhookEndpoints passes environment query parameter", async () => {
    const f = installFetch((url) => {
      assert.ok(url.includes("/v1/webhook-endpoints?environment=env-1"));
      return jsonResponse({ items: [], nextCursor: null });
    });
    try {
      const client = new DashboardApiClient("https://controlplane.example.com");
      const res = await client.listWebhookEndpoints("env-1");
      assert.deepEqual(res.items, []);
    } finally {
      f.restore();
    }
  });

  test("createWebhookEndpoint issues POST with payload", async () => {
    const f = installFetch((url, init) => {
      assert.ok(url.includes("/v1/webhook-endpoints?environment=env-1"));
      assert.equal(init.method, "POST");
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.url, "https://receiver.example.com/events");
      assert.deepEqual(parsed.eventTypes, ["run.succeeded"]);
      assert.equal(parsed.enabled, true);
      return jsonResponse({
        id: "ep-1",
        url: parsed.url,
        enabled: true,
        revision: 1,
        eventTypes: parsed.eventTypes,
        signingKeyId: "key-1",
        secret: "whsec_abc123",
      });
    });
    try {
      const client = new DashboardApiClient("https://controlplane.example.com");
      const res = await client.createWebhookEndpoint(
        "env-1",
        "https://receiver.example.com/events",
        ["run.succeeded"],
      );
      assert.equal(res.id, "ep-1");
      assert.equal(res.secret, "whsec_abc123");
    } finally {
      f.restore();
    }
  });

  test("updateWebhookEndpoint issues PATCH with revision CAS and configuration", async () => {
    const f = installFetch((url, init) => {
      assert.ok(url.includes("/v1/webhook-endpoints/ep-1"));
      assert.equal(init.method, "PATCH");
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.expectedRevision, 2);
      assert.equal(parsed.rotateSecret, true);
      return jsonResponse({
        id: "ep-1",
        url: "https://receiver.example.com/events",
        enabled: true,
        revision: 3,
        eventTypes: ["run.succeeded"],
        signingKeyId: "key-2",
        secret: "whsec_new456",
      });
    });
    try {
      const client = new DashboardApiClient("https://controlplane.example.com");
      const res = await client.updateWebhookEndpoint(
        "ep-1",
        2,
        undefined,
        true,
      );
      assert.equal(res.revision, 3);
      assert.equal(res.secret, "whsec_new456");
    } finally {
      f.restore();
    }
  });

  test("deleteWebhookEndpoint issues DELETE with revision CAS", async () => {
    const f = installFetch((url, init) => {
      assert.ok(url.includes("/v1/webhook-endpoints/ep-1"));
      assert.equal(init.method, "DELETE");
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.expectedRevision, 3);
      return jsonResponse({ deleted: true });
    });
    try {
      const client = new DashboardApiClient("https://controlplane.example.com");
      await client.deleteWebhookEndpoint("ep-1", 3);
    } finally {
      f.restore();
    }
  });

  test("listWebhookDeliveries lists endpoint deliveries", async () => {
    const f = installFetch((url) => {
      assert.ok(url.includes("/v1/webhook-endpoints/ep-1/deliveries"));
      return jsonResponse({
        items: [
          {
            id: "del-1",
            endpointId: "ep-1",
            endpointRevision: 1,
            eventId: "evt-1",
            eventType: "run.succeeded",
            attempts: 1,
            status: "DELIVERED",
            createdAt: "2026-11-22T00:00:00Z",
          },
        ],
        nextCursor: null,
      });
    });
    try {
      const client = new DashboardApiClient("https://controlplane.example.com");
      const res = await client.listWebhookDeliveries("ep-1");
      assert.equal(res.items.length, 1);
      assert.equal(res.items[0].status, "DELIVERED");
    } finally {
      f.restore();
    }
  });

  test("redeliverWebhook re-enqueues delivery via POST", async () => {
    const f = installFetch((url, init) => {
      assert.ok(url.includes("/v1/webhook-deliveries/del-1/redeliver"));
      assert.equal(init.method, "POST");
      return jsonResponse({
        id: "del-2",
        endpointId: "ep-1",
        endpointRevision: 1,
        eventId: "evt-1",
        eventType: "run.succeeded",
        attempts: 0,
        status: "PENDING",
        createdAt: "2026-11-22T00:01:00Z",
      });
    });
    try {
      const client = new DashboardApiClient("https://controlplane.example.com");
      const res = await client.redeliverWebhook("del-1");
      assert.equal(res.id, "del-2");
      assert.equal(res.status, "PENDING");
    } finally {
      f.restore();
    }
  });
});
