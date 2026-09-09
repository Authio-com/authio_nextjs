/**
 * Authio webhook receiver + session denylist for Next.js BFFs.
 *
 * Revocation-signals program, Phase 1 (2026-09-09). The problem this
 * solves: your BFF's `authio_session` cookie holds a short-lived access
 * JWT that verifies OFFLINE against the JWKS — so when an Authio
 * session is revoked (sign-out elsewhere, admin revoke, refresh-token
 * reuse family kill, session/network policy, impersonation revoke, SCIM
 * deprovisioning), the JWT keeps verifying until it expires. Authio now
 * emits a `session.revoked` webhook at every death point; this module
 * receives it and feeds a session-id denylist that `verifyToken` /
 * `auth` / `authMiddleware` consult, closing the gap to near-real-time.
 *
 * Wiring (App Router):
 *
 *   // app/api/authio/webhook/route.ts
 *   import { createAuthioWebhookHandler } from "@useauthio/nextjs/server";
 *   export const POST = createAuthioWebhookHandler({
 *     secret: process.env.AUTHIO_WEBHOOK_SECRET!, // whsec_…
 *   });
 *
 * That's it — the default in-memory denylist is automatically consulted
 * by `verifyToken`/`auth` in the same process. IMPORTANT caveat: the
 * memory denylist is per-process. On serverless/multi-instance deploys,
 * pass a shared `SessionDenylist` adapter (Redis, Vercel KV, …) to BOTH
 * `createAuthioWebhookHandler` and your verify calls.
 *
 * Signature contract (authio_webhooks, Stripe-style):
 *   Authio-Signature: t=<unix-seconds>,v1=<hex-hmac-sha256>
 * computed over `<t>.<raw-body>` with the endpoint's `whsec_…` secret.
 * Receivers reject when |now - t| exceeds the tolerance (default 5 min).
 */

/** Pluggable session-id denylist. Implement with Redis/KV for multi-instance deploys. */
export interface SessionDenylist {
  /** Record sid as revoked until expiresAtMs (epoch ms). */
  add(sid: string, expiresAtMs: number): Promise<void> | void;
  /** True if sid is currently denylisted. */
  has(sid: string): Promise<boolean> | boolean;
}

/**
 * Default in-memory denylist. Per-process — fine for single-instance
 * Node deployments and for development; use a shared adapter otherwise.
 * Entries expire lazily on access and via periodic sweeps on `add`.
 */
export class MemorySessionDenylist implements SessionDenylist {
  private entries = new Map<string, number>();
  private lastSweep = 0;

  add(sid: string, expiresAtMs: number): void {
    if (!sid) return;
    this.entries.set(sid, expiresAtMs);
    // Amortized sweep: at most once per minute, drop expired entries so
    // a long-lived process doesn't accumulate dead sids forever.
    const now = Date.now();
    if (now - this.lastSweep > 60_000) {
      this.lastSweep = now;
      for (const [k, exp] of this.entries) {
        if (exp <= now) this.entries.delete(k);
      }
    }
  }

  has(sid: string): boolean {
    const exp = this.entries.get(sid);
    if (exp === undefined) return false;
    if (exp <= Date.now()) {
      this.entries.delete(sid);
      return false;
    }
    return true;
  }
}

let defaultDenylist: MemorySessionDenylist | null = null;

/**
 * The process-wide default denylist. `createAuthioWebhookHandler` feeds
 * it when no explicit adapter is given, and `verifyToken`/`auth` consult
 * it automatically — zero-config revocation for single-instance apps.
 */
export function getDefaultSessionDenylist(): MemorySessionDenylist {
  if (!defaultDenylist) defaultDenylist = new MemorySessionDenylist();
  return defaultDenylist;
}

/** The delivery body authio_webhooks POSTs (see its worker's payload marshal). */
export interface AuthioWebhookEvent {
  id: string;
  action: string;
  created_at: string;
  project_id: string;
  organization_id: string | null;
  user_id: string | null;
  target_type: string | null;
  target_id: string | null;
  metadata: Record<string, unknown> | null;
  actor: { type: string | null; id: string | null };
}

const encoder = new TextEncoder();

function timingSafeEqualHex(aHex: string, bHex: string): boolean {
  if (aHex.length !== bHex.length) return false;
  let diff = 0;
  for (let i = 0; i < aHex.length; i++) {
    diff |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verify an `Authio-Signature` header against the raw request body.
 * Web Crypto only — safe on Edge, Node 18+, and Workers runtimes.
 */
export async function verifyAuthioWebhookSignature(
  body: string,
  header: string | null,
  secret: string,
  opts: { toleranceMs?: number; now?: number } = {},
): Promise<boolean> {
  if (!header || !secret) return false;
  let t = "";
  let v1 = "";
  for (const part of header.split(",")) {
    const p = part.trim();
    if (p.startsWith("t=")) t = p.slice(2);
    else if (p.startsWith("v1=")) v1 = p.slice(3);
  }
  if (!t || !v1) return false;
  const ts = Number(t);
  if (!Number.isFinite(ts)) return false;
  const toleranceMs = opts.toleranceMs ?? 300_000;
  const now = opts.now ?? Date.now();
  if (Math.abs(now - ts * 1000) > toleranceMs) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${t}.${body}`),
  );
  const hex = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return timingSafeEqualHex(hex, v1.toLowerCase());
}

export interface AuthioWebhookHandlerOptions {
  /** The endpoint's signing secret (`whsec_…`) from the Authio dashboard. */
  secret: string;
  /**
   * Denylist to feed on `session.revoked`. Defaults to the process-wide
   * memory denylist that `verifyToken`/`auth` consult automatically.
   */
  denylist?: SessionDenylist;
  /**
   * How long a revoked sid stays denylisted, in ms. Cover at least your
   * access-token TTL — after that the JWT is expired anyway. Default 1h.
   */
  denylistTtlMs?: number;
  /** Max signature age. Default 5 minutes (matches Authio's contract). */
  toleranceMs?: number;
  /** Called for EVERY verified event — bring your own routing/side effects. */
  onEvent?: (event: AuthioWebhookEvent) => void | Promise<void>;
}

/**
 * Build a Next.js Route Handler (also plain-`Request` compatible) that
 * receives Authio webhooks: verifies the HMAC signature, denylists the
 * sid on `session.revoked`, and hands every verified event to `onEvent`.
 *
 * Returns 401 on bad/missing/stale signatures, 400 on unparseable JSON,
 * 200 otherwise (including unknown actions — subscribing to more events
 * later must not create retry storms).
 */
export function createAuthioWebhookHandler(
  opts: AuthioWebhookHandlerOptions,
): (req: Request) => Promise<Response> {
  const denylist = opts.denylist ?? getDefaultSessionDenylist();
  const ttlMs = opts.denylistTtlMs ?? 3_600_000;

  return async function authioWebhookHandler(req: Request): Promise<Response> {
    const body = await req.text();
    const ok = await verifyAuthioWebhookSignature(
      body,
      req.headers.get("authio-signature"),
      opts.secret,
      { toleranceMs: opts.toleranceMs },
    );
    if (!ok) {
      return Response.json({ error: "invalid_signature" }, { status: 401 });
    }
    let event: AuthioWebhookEvent;
    try {
      event = JSON.parse(body) as AuthioWebhookEvent;
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }

    if (
      event.action === "session.revoked" &&
      event.target_type === "session" &&
      typeof event.target_id === "string" &&
      event.target_id
    ) {
      await denylist.add(event.target_id, Date.now() + ttlMs);
    }

    if (opts.onEvent) await opts.onEvent(event);
    return Response.json({ received: true });
  };
}
