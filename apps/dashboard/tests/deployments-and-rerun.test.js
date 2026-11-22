import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  roleCanDrainWorkers,
  sessionCanDrainWorkers,
  visibleRerunControl,
  WORKERS_DRAIN_CAPABILITY,
} from "../dist/permissions.js";
import { DashboardApiClient } from "../dist/api.js";

function sessionWithRole(role, status = "ACTIVE", orgId = "org-1") {
  return {
    user: { id: "u-1", email: "dev@example.com", name: "Dev" },
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

describe("workers:drain permission gating (Blueprint §24.2)", () => {
  test("capability constant matches specification", () => {
    assert.equal(WORKERS_DRAIN_CAPABILITY, "workers:drain");
  });

  test("only operator, admin, and owner may drain/revoke workers", () => {
    for (const role of ["operator", "admin", "owner", "Owner", "ADMIN"]) {
      assert.equal(roleCanDrainWorkers(role), true, role);
    }
    for (const role of ["viewer", "developer", "", null, undefined]) {
      assert.equal(roleCanDrainWorkers(role), false, String(role));
    }
  });

  test("sessionCanDrainWorkers checks active membership", () => {
    assert.equal(
      sessionCanDrainWorkers(sessionWithRole("operator"), "org-1"),
      true,
    );
    assert.equal(
      sessionCanDrainWorkers(sessionWithRole("developer"), "org-1"),
      false,
    );
    assert.equal(
      sessionCanDrainWorkers(sessionWithRole("operator", "SUSPENDED"), "org-1"),
      false,
    );
    assert.equal(
      sessionCanDrainWorkers(sessionWithRole("operator"), "other-org"),
      false,
    );
    assert.equal(sessionCanDrainWorkers(null, "org-1"), false);
  });
});

describe("visibleRerunControl (Blueprint §20.2 / INV-09)", () => {
  test("renders only for terminal runs when identity can control runs", () => {
    for (const terminal of ["SUCCEEDED", "FAILED", "CANCELLED"]) {
      assert.equal(visibleRerunControl(terminal, true), true, terminal);
      assert.equal(visibleRerunControl(terminal, false), false, `${terminal}-no-perm`);
    }
    for (const nonTerminal of ["QUEUED", "RUNNING", "WAITING", "PAUSING", "PAUSED"]) {
      assert.equal(visibleRerunControl(nonTerminal, true), false, nonTerminal);
      assert.equal(visibleRerunControl(nonTerminal, false), false, `${nonTerminal}-no-perm`);
    }
  });
});

describe("DashboardApiClient deployments and rerun wire", () => {
  test("rerunRun sends CSRF + Idempotency-Key and payload", async () => {
    let capturedUrl = "";
    let capturedInit = null;
    globalThis.fetch = async (url, init) => {
      capturedUrl = String(url);
      capturedInit = init;
      return new Response(JSON.stringify({ id: "new-run-1", workflowName: "wf", status: "QUEUED" }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new DashboardApiClient("http://control-plane.local");
    const result = await client.rerunRun("orig-run-123", {
      deploymentId: "dep-456",
      input: { test: true },
    }, "custom-idemp-1");

    assert.equal(capturedUrl, "http://control-plane.local/v1/runs/orig-run-123/rerun");
    assert.equal(capturedInit.method, "POST");
    assert.equal(capturedInit.headers["Idempotency-Key"], "custom-idemp-1");
    const body = JSON.parse(capturedInit.body);
    assert.equal(body.deploymentId, "dep-456");
    assert.deepEqual(body.input, { test: true });
    assert.equal(result.id, "new-run-1");
  });

  test("drainWorker and revokeWorker hit worker control endpoints", async () => {
    const urls = [];
    globalThis.fetch = async (url, init) => {
      urls.push(String(url));
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    };

    const client = new DashboardApiClient("http://control-plane.local");
    await client.drainWorker("worker-abc", "idemp-drain");
    await client.revokeWorker("worker-abc", "idemp-revoke");

    assert.equal(urls[0], "http://control-plane.local/v1/workers/worker-abc/drain");
    assert.equal(urls[1], "http://control-plane.local/v1/workers/worker-abc/revoke");
  });

  test("listDeployments and deleteDeployment hit deployment endpoints", async () => {
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), method: init?.method ?? "GET" });
      if (init?.method === "DELETE") {
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify({ items: [{ id: "dep-1" }], nextCursor: null }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new DashboardApiClient("http://control-plane.local");
    const listRes = await client.listDeployments("env-uuid", 10);
    assert.equal(calls[0].url, "http://control-plane.local/v1/deployments?environment=env-uuid&limit=10");
    assert.equal(listRes.items.length, 1);

    await client.deleteDeployment("env-uuid", "dep-1", "idemp-del");
    assert.equal(calls[1].url, "http://control-plane.local/v1/deployments/dep-1?environment=env-uuid");
    assert.equal(calls[1].method, "DELETE");
  });
});
