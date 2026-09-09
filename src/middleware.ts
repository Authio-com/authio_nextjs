import { NextResponse, type NextRequest } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { SessionDenylist } from "./webhook";

export interface AuthMiddlewareOptions {
  /** Auth-core base URL (e.g. https://api.authio.com). */
  apiUrl?: string;
  /** Expected JWT issuer (matches AUTHIO_JWT_ISSUER on the server). Defaults to production's real issuer. */
  issuer?: string;
  /** Expected JWT audience. Defaults to production's real audience. */
  audience?: string;
  /**
   * Your Authio project ID. Strongly recommended — see the security note
   * on `projectId` in `server.ts`. Without it, a token minted in ANY
   * Authio project verifies successfully here, not just yours.
   */
  projectId?: string;
  /** Routes that don't require a session (string equality or regex). */
  publicRoutes?: (string | RegExp)[];
  signInUrl?: string;
  /**
   * Session denylist fed by `createAuthioWebhookHandler` (session.revoked
   * webhooks). NOTE: this middleware typically runs on the Edge runtime
   * in a separate isolate from your Node route handlers, so the default
   * in-memory denylist is NOT shared with it — pass a shared adapter
   * (Redis, Vercel KV, Upstash, …) for denylisting to work here. When
   * omitted, no denylist check runs in the middleware; `verifyToken` /
   * `auth` in your route handlers still check the process-wide default.
   */
  sessionDenylist?: SessionDenylist;
}

const DEFAULT_API_URL = "https://api.authio.com";
const DEFAULT_ISSUER = "https://identity.authio.com";
const DEFAULT_AUDIENCE = "authio";

/** Response/forwarded-request header names this middleware sets from
 * verified claims. Security audit 2026-09-06/07 (SDK-2): these must
 * ALSO be stripped from the INBOUND request before forwarding, or a
 * client can set `x-authio-user-id`/`x-authio-org-id`/`x-authio-role`
 * on their own request and have it read back by a downstream Server
 * Component via `headers()` as if this middleware had verified it. */
const CLAIM_HEADERS = [
  "x-authio-user-id",
  "x-authio-org-id",
  "x-authio-role",
] as const;

/**
 * Next.js Edge middleware that verifies the Authio session JWT against the
 * remote JWKS, gates protected routes, and exposes claims to the request
 * via response headers `x-authio-user-id`, `x-authio-org-id`, and
 * `x-authio-role` so downstream Server Components can read them via
 * `headers().get(...)`.
 */
export function authMiddleware(opts: AuthMiddlewareOptions = {}) {
  const apiUrl = (opts.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, "");
  const jwks = createRemoteJWKSet(
    new URL(apiUrl + "/v1/auth/.well-known/jwks.json"),
  );
  const { publicRoutes = [], signInUrl = "/sign-in" } = opts;

  return async function middleware(req: NextRequest) {
    const { pathname } = req.nextUrl;

    // Strip any inbound claim headers unconditionally, on every path
    // (including public routes) — a client that knows this middleware's
    // header names must never be able to inject them.
    const forwardedHeaders = new Headers(req.headers);
    for (const h of CLAIM_HEADERS) forwardedHeaders.delete(h);

    if (isPublic(pathname, publicRoutes)) {
      return NextResponse.next({ request: { headers: forwardedHeaders } });
    }

    const cookie = req.cookies.get("authio_session")?.value;
    if (!cookie) return redirectToSignIn(req, signInUrl, pathname);

    try {
      const { payload } = await jwtVerify(cookie, jwks, {
        issuer: opts.issuer ?? DEFAULT_ISSUER,
        audience: opts.audience ?? DEFAULT_AUDIENCE,
        algorithms: ["EdDSA"],
      });
      if (opts.projectId && payload.project_id !== opts.projectId) {
        return redirectToSignIn(req, signInUrl, pathname);
      }
      // Revocation-signals Phase 1: refuse structurally valid JWTs whose
      // session was revoked. Only when a shared denylist adapter is
      // configured — see the sessionDenylist option's Edge-runtime note.
      if (
        opts.sessionDenylist &&
        typeof payload.sid === "string" &&
        payload.sid &&
        (await opts.sessionDenylist.has(payload.sid))
      ) {
        return redirectToSignIn(req, signInUrl, pathname);
      }
      if (typeof payload.sub === "string") {
        forwardedHeaders.set("x-authio-user-id", payload.sub);
      }
      if (typeof payload.act_org === "string") {
        forwardedHeaders.set("x-authio-org-id", payload.act_org);
      }
      if (typeof payload.act_role === "string") {
        forwardedHeaders.set("x-authio-role", payload.act_role);
      }
      // Forward on the REQUEST (so headers().get(...) in a downstream
      // Server Component sees them) and keep setting them on the
      // response too, for callers relying on the documented response-
      // header behavior.
      const res = NextResponse.next({ request: { headers: forwardedHeaders } });
      for (const h of CLAIM_HEADERS) {
        const v = forwardedHeaders.get(h);
        if (v) res.headers.set(h, v);
      }
      return res;
    } catch {
      return redirectToSignIn(req, signInUrl, pathname);
    }
  };
}

function isPublic(pathname: string, publicRoutes: (string | RegExp)[]) {
  for (const r of publicRoutes) {
    if (typeof r === "string" ? pathname === r : r.test(pathname)) return true;
  }
  return false;
}

function redirectToSignIn(
  req: NextRequest,
  signInUrl: string,
  pathname: string,
) {
  const url = req.nextUrl.clone();
  url.pathname = signInUrl;
  url.searchParams.set("redirect_url", pathname);
  return NextResponse.redirect(url);
}
