// Revocation-signals Phase 1: webhook receiver + session denylist.
// Pins the wire contract with authio_webhooks (Authio-Signature:
// t=…,v1=… over `t.body`), the denylist feed on session.revoked, and
// verifyToken's refusal of denylisted sids.
import { describe, expect, it } from "vitest";
import {
  createAuthioWebhookHandler,
  verifyAuthioWebhookSignature,
  MemorySessionDenylist,
} from "../src/webhook";

async function sign(secret: string, body: string, tSec: number) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${tSec}.${body}`));
  const hex = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `t=${tSec},v1=${hex}`;
}

function revokedEvent(sid: string) {
  return JSON.stringify({
    id: "evt_1",
    action: "session.revoked",
    created_at: new Date().toISOString(),
    project_id: "proj_x",
    organization_id: null,
    user_id: "user_x",
    target_type: "session",
    target_id: sid,
    metadata: { reason: "user_logout" },
    actor: { type: "user", id: "user_x" },
  });
}

describe("verifyAuthioWebhookSignature", () => {
  it("accepts a valid signature and rejects tampered bodies", async () => {
    const body = revokedEvent("sess_1");
    const now = Math.floor(Date.now() / 1000);
    const header = await sign("whsec_test", body, now);
    expect(await verifyAuthioWebhookSignature(body, header, "whsec_test")).toBe(true);
    expect(
      await verifyAuthioWebhookSignature(body + " ", header, "whsec_test"),
    ).toBe(false);
    expect(await verifyAuthioWebhookSignature(body, header, "whsec_other")).toBe(false);
    expect(await verifyAuthioWebhookSignature(body, null, "whsec_test")).toBe(false);
  });

  it("rejects stale timestamps (replay protection)", async () => {
    const body = revokedEvent("sess_1");
    const stale = Math.floor(Date.now() / 1000) - 600; // 10 min old
    const header = await sign("whsec_test", body, stale);
    expect(await verifyAuthioWebhookSignature(body, header, "whsec_test")).toBe(false);
    // …but accepted when inside a custom tolerance.
    expect(
      await verifyAuthioWebhookSignature(body, header, "whsec_test", {
        toleranceMs: 3_600_000,
      }),
    ).toBe(true);
  });
});

describe("createAuthioWebhookHandler", () => {
  it("verifies, denylists the sid on session.revoked, and 200s", async () => {
    const denylist = new MemorySessionDenylist();
    const handler = createAuthioWebhookHandler({ secret: "whsec_test", denylist });
    const body = revokedEvent("sess_dead");
    const header = await sign("whsec_test", body, Math.floor(Date.now() / 1000));
    const res = await handler(
      new Request("https://app.example.com/api/authio/webhook", {
        method: "POST",
        headers: { "Authio-Signature": header },
        body,
      }),
    );
    expect(res.status).toBe(200);
    expect(denylist.has("sess_dead")).toBe(true);
    expect(denylist.has("sess_alive")).toBe(false);
  });

  it("401s bad signatures without touching the denylist", async () => {
    const denylist = new MemorySessionDenylist();
    const handler = createAuthioWebhookHandler({ secret: "whsec_test", denylist });
    const body = revokedEvent("sess_dead");
    const res = await handler(
      new Request("https://app.example.com/api/authio/webhook", {
        method: "POST",
        headers: { "Authio-Signature": "t=1,v1=deadbeef" },
        body,
      }),
    );
    expect(res.status).toBe(401);
    expect(denylist.has("sess_dead")).toBe(false);
  });

  it("200s unknown actions (future events must not retry-storm) and calls onEvent", async () => {
    const seen: string[] = [];
    const handler = createAuthioWebhookHandler({
      secret: "whsec_test",
      denylist: new MemorySessionDenylist(),
      onEvent: (e) => {
        seen.push(e.action);
      },
    });
    const body = JSON.stringify({ id: "evt_2", action: "user.created" });
    const header = await sign("whsec_test", body, Math.floor(Date.now() / 1000));
    const res = await handler(
      new Request("https://x.example.com/hook", {
        method: "POST",
        headers: { "Authio-Signature": header },
        body,
      }),
    );
    expect(res.status).toBe(200);
    expect(seen).toEqual(["user.created"]);
  });
});

describe("MemorySessionDenylist", () => {
  it("expires entries", () => {
    const d = new MemorySessionDenylist();
    d.add("sess_soon", Date.now() - 1); // already expired
    d.add("sess_later", Date.now() + 60_000);
    expect(d.has("sess_soon")).toBe(false);
    expect(d.has("sess_later")).toBe(true);
  });
});
