import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { verifyWebhookSignature, DeadboltClient } from "../dist/index.js";

test("verifyWebhookSignature accepts valid signature within tolerance window", () => {
  const secret = "whsec_testsecret1234567890abcdef";
  const now = Math.floor(Date.now() / 1000);
  const body = JSON.stringify({ eventType: "run.succeeded", runId: "123" });

  const hmac = createHmac("sha256", secret);
  hmac.update(`${now}.${body}`);
  const signatureHex = hmac.digest("hex");

  const valid = verifyWebhookSignature(secret, now, body, signatureHex, 300);
  assert.equal(valid, true);
});

test("verifyWebhookSignature rejects timestamp older than tolerance window (5m)", () => {
  const secret = "whsec_testsecret1234567890abcdef";
  const oldTimestamp = Math.floor(Date.now() / 1000) - 301; // 5m 1s ago
  const body = JSON.stringify({ eventType: "run.succeeded", runId: "123" });

  const hmac = createHmac("sha256", secret);
  hmac.update(`${oldTimestamp}.${body}`);
  const signatureHex = hmac.digest("hex");

  const valid = verifyWebhookSignature(
    secret,
    oldTimestamp,
    body,
    signatureHex,
    300,
  );
  assert.equal(valid, false);
});

test("verifyWebhookSignature rejects tampered body or invalid signature", () => {
  const secret = "whsec_testsecret1234567890abcdef";
  const now = Math.floor(Date.now() / 1000);
  const body = JSON.stringify({ eventType: "run.succeeded", runId: "123" });
  const tamperedBody = JSON.stringify({
    eventType: "run.succeeded",
    runId: "123",
    extra: true,
  });

  const hmac = createHmac("sha256", secret);
  hmac.update(`${now}.${body}`);
  const signatureHex = hmac.digest("hex");

  const valid = verifyWebhookSignature(
    secret,
    now,
    tamperedBody,
    signatureHex,
    300,
  );
  assert.equal(valid, false);
});

test("DeadboltClient webhooks wire methods construct expected requests", async () => {
  const recorded = [];
  const fakeFetch = async (url, init) => {
    recorded.push({
      url,
      method: init?.method,
      headers: init?.headers,
      body: init?.body,
    });
    if (url.includes("/v1/webhook-endpoints") && init?.method === "POST") {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "Content-Type": "application/json" }),
        text: async () =>
          JSON.stringify({
            id: "ep-1",
            url: "https://example.com/webhook",
            enabled: true,
            revision: 1,
            eventTypes: ["run.succeeded"],
            secret: "whsec_new",
            signingKeyId: "key_1",
          }),
      };
    }
    if (url.includes("/v1/webhook-endpoints") && init?.method === "GET") {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "Content-Type": "application/json" }),
        text: async () =>
          JSON.stringify({
            items: [],
            nextCursor: null,
          }),
      };
    }
    if (url.includes("/redeliver") && init?.method === "POST") {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "Content-Type": "application/json" }),
        text: async () =>
          JSON.stringify({
            id: "del-2",
            endpointId: "ep-1",
            endpointRevision: 1,
            eventId: "ev-1",
            eventType: "run.succeeded",
            payload: {},
            attempts: 0,
            status: "PENDING",
            nextAt: "2026-11-22T08:00:00Z",
            createdAt: "2026-11-22T08:00:00Z",
          }),
      };
    }
    return {
      ok: true,
      status: 200,
      headers: new Headers({ "Content-Type": "application/json" }),
      text: async () => JSON.stringify({}),
    };
  };

  const client = new DeadboltClient({
    baseUrl: "https://api.deadbolt.test",
    apiKey: "dbe_testkey123",
    fetch: fakeFetch,
  });

  const created = await client.webhooks.create("env-staging", {
    url: "https://example.com/webhook",
    enabled: true,
    eventTypes: ["run.succeeded"],
  });
  assert.equal(created.id, "ep-1");
  assert.equal(created.secret, "whsec_new");

  const list = await client.webhooks.list("env-staging");
  assert.deepEqual(list.items, []);

  const redelivered = await client.webhooks.redeliver("del-1");
  assert.equal(redelivered.id, "del-2");
  assert.equal(redelivered.status, "PENDING");

  const redeliveredWithEndpoint = await client.webhooks.redeliver("del-1", {
    endpointId: "ep-2",
  });
  assert.equal(redeliveredWithEndpoint.id, "del-2");
  const lastCall = recorded[recorded.length - 1];
  assert.equal(
    lastCall.url,
    "https://api.deadbolt.test/v1/webhook-deliveries/del-1/redeliver",
  );
  assert.equal(lastCall.body, JSON.stringify({ endpointId: "ep-2" }));
});
