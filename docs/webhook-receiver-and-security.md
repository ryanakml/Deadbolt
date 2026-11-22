# Webhook Receiver Implementation, Security Contract & Operations Runbook

This document defines the delivery contract, cryptographic verification, SSRF defense architecture, and operational runbook for Deadbolt's signed, at-least-once webhooks (Blueprint §18, §19, §21, §24, §26 and ADR-14).

---

## 1. Webhook Delivery Architecture & Contract

Deadbolt delivers outbound webhooks with **at-least-once** guarantees whenever key runtime state transitions occur in an environment.

### 1.1 Invariants & Reliability Guarantees

- **Transactional Intent Invariant (INV-01 / REQ-EVENT-01):** Webhook delivery intents are enqueued in PostgreSQL in the **exact same transaction** as the workflow state transition (`runs`, `run_steps`, `audit_events`). If the transaction commits, the delivery intent is durable; if the transaction aborts, no delivery is queued.
- **Worker Independence:** Delivery intents are enqueued even when all workers are offline or during worker drains. Terminal run events (`run.succeeded`, `run.failed`, `run.cancelled`) and approval holds (`approval.requested`) generate webhook intents directly from the control-plane execution engine.
- **Non-Reversal Invariant (Blueprint §21):** Webhook delivery outcomes (network timeouts, receiver HTTP 500s, or receiver crashes) **never alter, reverse, or fail a successful run**. Run status is completely decoupled from webhook delivery status.
- **Endpoint Revision CAS:** Webhook endpoints track a monotonically increasing `endpoint_revision`. Delivery intents pin the endpoint revision. If an operator updates the destination URL, all pending deliveries from older revisions are automatically marked `CANCELLED` to prevent misdirected payloads.

---

## 2. Event Types & Headers

### 2.1 Subscribed Events

| Event Type           | Trigger                                                        | Key Payload Attributes                                        |
| :------------------- | :------------------------------------------------------------- | :------------------------------------------------------------ |
| `run.succeeded`      | Workflow run successfully completed all steps                  | `runId`, `workflowName`, `status: "SUCCEEDED"`, `completedAt` |
| `run.failed`         | Workflow run terminated due to unhandled step failure or error | `runId`, `workflowName`, `status: "FAILED"`, `failureReason`  |
| `run.cancelled`      | Operator or API cancelled the active run                       | `runId`, `workflowName`, `status: "CANCELLED"`, `cancelledAt` |
| `approval.requested` | Human approval gate waiting for operator decision              | `runId`, `approvalId`, `gateName`, `requiredRole`             |

### 2.2 HTTP Request Headers

Deadbolt sends the following standard HTTP headers on every outbound webhook request:

| Header                 | Format / Example                           | Description                                             |
| :--------------------- | :----------------------------------------- | :------------------------------------------------------ |
| `Content-Type`         | `application/json`                         | Webhook body format                                     |
| `X-Deadbolt-Signature` | `t=1732233600,v1=abcdef...,kid=key_abc123` | Timestamp, HMAC-SHA256 hex signature, and active key ID |
| `X-Deadbolt-Timestamp` | `1732233600`                               | Unix epoch timestamp (seconds) of dispatch attempt      |
| `X-Deadbolt-Key-ID`    | `key_abc123`                               | Active signing key identifier for key rotation lookups  |
| `X-Deadbolt-Event`     | `run.succeeded`                            | The event type                                          |
| `X-Deadbolt-Delivery`  | `3fa85f64-5717-4562-b3fc-2c963f66afa6`     | Unique UUID identifying this specific delivery attempt  |

---

## 3. Cryptographic Security Contract

### 3.1 HMAC-SHA256 Signature Specification

Signatures are generated using **HMAC-SHA256**:
$$\text{Signature} = \text{HMAC-SHA256}_{\text{secret}}(\text{timestamp} \mathbin{\Vert} \text{"."} \mathbin{\Vert} \text{raw\_body})$$

- `timestamp`: The decimal ASCII string representation of the Unix epoch timestamp in seconds (matches `t=` in `X-Deadbolt-Signature` and `X-Deadbolt-Timestamp`).
- `raw_body`: The exact raw bytes of the HTTP request body as received on the wire (unparsed JSON).

### 3.2 Replay Protection (5-Minute Tolerance Window)

Receivers **MUST** verify that the timestamp is within **5 minutes (300 seconds)** of the receiver's current wall clock:
$$|\text{now} - \text{timestamp}| \le 300\text{ seconds}$$
If the timestamp falls outside this window, the receiver **MUST** reject the request to prevent replay attacks.

### 3.3 Timing-Safe Comparison

Signature verification **MUST** use constant-time byte comparison (`crypto.timingSafeEqual` in Node.js, `hmac.Equal` in Go, `subProcess` safe compare in Python) to prevent timing side-channel attacks.

### 3.4 Key Rotation with 24-Hour Overlap

When a secret is rotated in Deadbolt:

1. Deadbolt generates a new `secret` and a new `signing_key_id`.
2. All new dispatches immediately sign with the new secret and new `kid`.
3. The previous secret and `signing_key_id` remain stored and valid in Deadbolt for a **24-hour overlap window**.
4. Receivers can inspect `kid` from the header. If the receiver maintains key history, it can verify deliveries against the new key or fall back to the old key during this 24-hour migration period.

---

## 4. SSRF Defense & Dialing Architecture

To protect private networks and cloud infrastructure against Server-Side Request Forgery (SSRF) and DNS rebinding attacks, Deadbolt implements an SSRF-safe outbound HTTP transport.

### 4.1 Strict Port & Protocol Enforcement

Outbound webhook destinations must strictly use public **HTTPS on port 443** (`https://...:443` or implicit port 443). Plaintext `http://` or non-standard ports are rejected at endpoint creation and dialing time.

### 4.2 Blocked IP CIDRs

Before dialing, Deadbolt resolves the hostname and validates all resolved IP addresses against a comprehensive denylist:

- **IPv4 Denylist:**
  - `0.0.0.0/8` (Current network)
  - `10.0.0.0/8` (RFC 1918 Private)
  - `100.64.0.0/10` (Shared Address Space)
  - `127.0.0.0/8` (Loopback)
  - `169.254.0.0/16` (Link-Local & Cloud Metadata, e.g. `169.254.169.254`)
  - `172.16.0.0/12` (RFC 1918 Private)
  - `192.168.0.0/16` (RFC 1918 Private)
  - `198.18.0.0/15`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (Documentation/Testing)
  - `224.0.0.0/4` (Multicast), `240.0.0.0/4` (Reserved)
- **IPv6 Denylist:**
  - `::1/128` (Loopback)
  - `fc00::/7` (Unique Local Private)
  - `fe80::/10` (Link-Local)
  - `ff00::/8` (Multicast)

### 4.3 Anti-DNS-Rebinding Socket Dialing

Standard HTTP clients resolve DNS once and dial the domain name, leaving a Time-Of-Check to Time-Of-Use (TOCTOU) vulnerability where an attacker's DNS server answers with a public IP on creation and a private IP during dialing.
Deadbolt's transport eliminates this vulnerability:

1. Re-resolves DNS on every dispatch attempt.
2. Validates every returned IP address.
3. Dials the validated IP address directly on the TCP socket.
4. Preserves the original hostname in TLS `ServerName` (SNI) so certificate verification succeeds without allowing socket rebinding.

### 4.4 Redirect & Timeout Policies

- **Redirects:** Outbound dispatcher **never follows HTTP redirects** (3xx responses). A 3xx response is treated as a terminal failure to prevent open redirect abuse.
- **Timeouts:** 3 seconds TCP/TLS connect timeout; 10 seconds total request timeout.

---

## 5. Retry Schedule & Endpoint Auto-Disabling

| Receiver Response                | Dispatcher Action | Backoff & Policy                                                                |
| :------------------------------- | :---------------- | :------------------------------------------------------------------------------ |
| `2xx` (200, 201, 204)            | Success           | Status marked `DELIVERED`. `completed_at` set.                                  |
| `429` (Rate Limited)             | Retry             | Exponential backoff with jitter up to 1h, max 12 attempts over 24h.             |
| `5xx` / Connection Timeout       | Retry             | Exponential backoff with jitter up to 1h, max 12 attempts over 24h.             |
| `410 Gone`                       | Terminal Disable  | Status marked `FAILED`. **Endpoint automatically disabled** (`active = false`). |
| Other `4xx` (400, 401, 403, 404) | Terminal Failure  | Status marked `FAILED`. Endpoint remains active.                                |

---

## 6. Receiver Implementation Examples

### 6.1 TypeScript / Node.js (Express)

```typescript
import express, { Request, Response } from "express";
import crypto from "crypto";

const app = express();
const WEBHOOK_SECRET = process.env.DEADBOLT_WEBHOOK_SECRET!; // e.g. "whsec_..."
const TOLERANCE_SECONDS = 300; // 5 minutes

// CRITICAL: Webhook signature verification requires the raw unparsed body
app.post(
  "/api/deadbolt-webhook",
  express.raw({ type: "application/json" }),
  (req: Request, res: Response) => {
    const sigHeader = req.header("X-Deadbolt-Signature");
    if (!sigHeader) {
      return res.status(401).send("Missing X-Deadbolt-Signature header");
    }

    // Parse t={timestamp},v1={hash},kid={keyId}
    const params = new Map<string, string>();
    for (const part of sigHeader.split(",")) {
      const [k, v] = part.split("=");
      if (k && v) params.set(k.trim(), v.trim());
    }

    const timestampStr = params.get("t");
    const receivedSig = params.get("v1");
    if (!timestampStr || !receivedSig) {
      return res.status(400).send("Invalid signature header format");
    }

    const timestamp = parseInt(timestampStr, 10);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > TOLERANCE_SECONDS) {
      return res.status(401).send("Webhook signature timestamp expired");
    }

    // Compute expected HMAC-SHA256: timestamp + "." + rawBody
    const rawBody = req.body as Buffer;
    const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
    hmac.update(`${timestamp}.`);
    hmac.update(rawBody);
    const expectedSig = hmac.digest("hex");

    // Timing-safe comparison
    const sigBuf = Buffer.from(receivedSig, "hex");
    const expBuf = Buffer.from(expectedSig, "hex");
    if (
      sigBuf.length !== expBuf.length ||
      !crypto.timingSafeEqual(sigBuf, expBuf)
    ) {
      return res.status(401).send("Invalid webhook signature");
    }

    // Parse and handle event
    const event = JSON.parse(rawBody.toString("utf8"));
    const eventType = req.header("X-Deadbolt-Event");
    console.log(
      `Received verified event ${eventType} (ID: ${event.eventId || event.runId})`,
    );

    // Acknowledge receipt promptly
    return res.status(200).json({ received: true });
  },
);

app.listen(8080, () => console.log("Webhook receiver listening on port 8080"));
```

### 6.2 Go Receiver

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var webhookSecret = "whsec_your_secret_here"

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sigHeader := r.Header.Get("X-Deadbolt-Signature")
	if sigHeader == "" {
		http.Error(w, "Missing signature header", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Cannot read body", http.StatusBadRequest)
		return
	}

	// Parse header
	var timestamp int64
	var signatureHex string
	for _, part := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "t":
				timestamp, _ = strconv.ParseInt(kv[1], 10, 64)
			case "v1":
				signatureHex = kv[1]
			}
		}
	}

	// Verify timestamp tolerance (5 minutes)
	diff := math.Abs(float64(time.Now().Unix() - timestamp))
	if diff > 300 {
		http.Error(w, "Signature timestamp expired", http.StatusUnauthorized)
		return
	}

	// Compute HMAC
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp)))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	actualMAC, err := hex.DecodeString(signatureHex)
	if err != nil || !hmac.Equal(expectedMAC, actualMAC) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	fmt.Printf("Received Deadbolt event %s: %+v\n", r.Header.Get("X-Deadbolt-Event"), payload)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"received": true}`))
}

func main() {
	http.HandleFunc("/webhooks", webhookHandler)
	_ = http.ListenAndServe(":8080", nil)
}
```

---

## 7. Operations Runbook: Webhook Backlogs & Failures

### 7.1 Key Telemetry & Alert Queries

#### 1. Pending Delivery Backlog Count

Alert when pending deliveries overdue for dispatch exceed 500:

```sql
SELECT count(*) AS overdue_backlog
FROM webhook_deliveries
WHERE status = 'PENDING'
  AND next_at < clock_timestamp() - interval '5 minutes';
```

#### 2. Oldest Pending Delivery Age

Alert when oldest pending delivery is > 15 minutes:

```sql
SELECT now() - min(created_at) AS oldest_pending_age
FROM webhook_deliveries
WHERE status = 'PENDING';
```

#### 3. Top Failing Webhook Endpoints

Identify endpoints failing continuously or exhausting retry budgets:

```sql
SELECT
    e.id AS endpoint_id,
    e.url,
    e.organization_id,
    count(d.id) AS failure_count,
    max(d.last_status_code) AS last_status,
    max(d.last_error) AS sample_error
FROM webhook_deliveries d
JOIN webhook_endpoints e ON d.endpoint_id = e.id
WHERE d.status = 'FAILED'
  AND d.created_at > clock_timestamp() - interval '1 hour'
GROUP BY e.id, e.url, e.organization_id
ORDER BY failure_count DESC
LIMIT 10;
```

### 7.2 Incident Triage & Remediation

#### Scenario A: High Dispatch Queue Lag (Worker/Dispatcher Saturation)

- **Symptom:** `overdue_backlog` increases while endpoints respond normally.
- **Root Cause:** Control-plane dispatch pool concurrency limit reached.
- **Mitigation:**
  1. Increase dispatcher concurrency in control-plane environment: `DEADBOLT_WEBHOOKS_CONCURRENCY=20`.
  2. Increase batch size: `DEADBOLT_WEBHOOKS_BATCH_SIZE=100`.
  3. Deploy additional control-plane replicas; dispatches use `FOR UPDATE SKIP LOCKED` and scale horizontally across instances without duplicates.

#### Scenario B: Destination Down / 410 Auto-Disabled

- **Symptom:** Endpoint received `410 Gone` and was auto-disabled.
- **Resolution:**
  1. Customer updates receiver infrastructure.
  2. Customer re-enables or updates endpoint URL via dashboard or `PATCH /v1/webhook-endpoints/{id}` (`{"configuration": {"enabled": true}}`).
  3. Re-deliver failed items via `POST /v1/webhook-deliveries/{delivery_id}/redeliver`.

#### Scenario C: Misdirected URLs / Secret Leaks

- **Symptom:** Destination URL was misconfigured or signing secret compromised.
- **Action:**
  1. Rotate signing secret via Dashboard or `PATCH /v1/webhook-endpoints/{id}` with `{"rotateSecret": true}`. The old secret remains valid for 24h.
  2. If URL was wrong, update the URL. Deadbolt will automatically set `status = 'CANCELLED'` for all unsent deliveries for the old URL revision.
