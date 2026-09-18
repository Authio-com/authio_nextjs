import { NextResponse, type NextRequest } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  DEFAULT_API_URL,
  DEFAULT_REFRESH_COOKIE,
  DEFAULT_SESSION_COOKIE,
  envProjectId,
} from "./config";

const DEFAULT_ISSUER = "https://identity.authio.com";
const DEFAULT_AUDIENCE = "authio";

let warnedNoProjectBinding = false;
function warnNoProjectBinding(): void {
  if (warnedNoProjectBinding) return;
  warnedNoProjectBinding = true;
  console.warn(
    "[@useauthio/nextjs] No projectId configured and AUTHIO_PROJECT_ID is unset, " +
      "so this middleware verifies signatures but does NOT bind tokens to your " +
      "tenant. A token minted in any other Authio project will pass. " +
      "Set AUTHIO_PROJECT_ID=proj_… in your server env.",
  );
}

export interface AuthioMiddlewareOptions {
  /** Cookie name for the access JWT. Defaults to "authio_session". */
  sessionCookieName?: string;
  /** Cookie name for the refresh token. Defaults to "authio_refresh". */
  refreshCookieName?: string;
  /** Path to redirect to when refresh fails. Defaults to "/sign-in". */
  signInPath?: string;
  /** Path of the refresh handler. Defaults to "/api/auth/refresh". */
  refreshPath?: string;
  /**
   * Path prefixes that should bypass auth gating. The middleware
   * compares with `startsWith` so trailing slashes are forgiving —
   * `"/sign-in"` matches `/sign-in`, `/sign-in/foo`, etc. The root
   * `"/"` is special-cased to exact-match only (a `startsWith("/")`
   * prefix would match every path and disable gating entirely).
   *
   * Defaults cover the routes the rest of @useauthio/nextjs ships:
   *   - `/sign-in`           — your sign-in page
   *   - `/api/auth/`         — callback / refresh / sign-out handlers
   *   - `/_next/`            — Next.js asset pipeline
   *   - `/favicon`           — favicon.ico and friends
   */
  publicPaths?: string[];
  /**
   * Query-param name to carry the originally-requested path through
   * the refresh / sign-in redirect. Defaults to "next".
   */
  nextParam?: string;
  /**
   * When set to a number in (0, 1], the middleware proactively
   * routes safe-method requests through the refresh handler when
   * the access JWT has less than this fraction of its original
   * lifetime remaining. e.g. `0.25` triggers a refresh when the
   * JWT is in its last 25% of life.
   *
   * The middleware does NOT verify the JWT — it decodes the
   * unauthenticated body to read `exp` and `iat` for lifetime math.
   * Verification still happens in the RSC `auth()` helper and the
   * downstream API. The proactive refresh is a UX optimisation:
   * users with long-lived (24h+) access cookies never see the
   * one-extra-redirect of reactive refresh on the navigation that
   * happens to land in the last sliver of the JWT's life.
   *
   * No effect when the JWT lacks `iat` (we can't compute the
   * original lifetime). Set to `undefined` (default) to disable.
   */
  proactiveRefreshThreshold?: number;
  /** Auth-core base URL. Defaults to `https://auth-api.authio.com`. */
  apiUrl?: string;
  /** Expected JWT issuer. Defaults to production's real issuer. */
  issuer?: string;
  /** Expected JWT audience. Defaults to production's real audience. */
  audience?: string;
  /**
   * Your Authio project ID. Defaults to `AUTHIO_PROJECT_ID` from the
   * server env. Every tenant's tokens share one signing key and one
   * issuer/audience, so this claim is the only thing separating your
   * users from someone else's Authio project — see `config.envProjectId`.
   */
  projectId?: string;
  /**
   * Verify the access cookie's signature, expiry, issuer, audience and
   * tenant before letting the request through. Defaults to `true`.
   *
   * Set `false` ONLY if every protected page and route handler in your
   * app independently calls `auth()` (or verifies the JWT itself) and
   * you have measured the per-request JWKS verification as a problem.
   * With `false` this middleware gates on cookie PRESENCE alone, so
   * anyone can set `document.cookie` and pass it.
   */
  verify?: boolean;
}

const DEFAULT_PUBLIC_PATHS = [
  "/sign-in",
  "/api/auth/",
  "/_next/",
  "/favicon",
];

/**
 * Decode a JWT body without verifying. Edge-runtime safe — uses
 * Web `atob` rather than `Buffer`. Returns `null` on any structural
 * failure so callers fall back to "we don't know the lifetime".
 *
 * The result is NEVER trusted for authorization; it's used only to
 * read `exp`/`iat` for proactive-refresh lifetime math.
 */
function decodeJwtUnverified(
  token: string,
): { exp?: number; iat?: number } | null {
  const parts = token.split(".");
  const body = parts[1];
  if (!body) return null;
  try {
    const padded = body
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(body.length + ((4 - (body.length % 4)) % 4), "=");
    const json = atob(padded);
    const obj = JSON.parse(json) as { exp?: unknown; iat?: unknown };
    return {
      exp: typeof obj.exp === "number" ? obj.exp : undefined,
      iat: typeof obj.iat === "number" ? obj.iat : undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Drop-in Next.js middleware that handles the Authio session-refresh
 * flow without any cookie-parsing logic in the customer's app.
 *
 * Behaviour:
 *   - Public path → `NextResponse.next()`
 *   - Access cookie present AND VERIFIED (signature, expiry, issuer,
 *     audience, and `project_id` when a tenant is configured) →
 *     `NextResponse.next()`
 *   - Access cookie expired AND refresh cookie present AND safe-method
 *     → 307 to the refresh handler
 *   - Access cookie structurally invalid (bad signature, wrong tenant)
 *     → 307 to sign-in, WITHOUT attempting a refresh: a refresh would
 *     fail the same way and the two routes would ping-pong.
 *   - Access cookie missing AND refresh cookie present AND
 *     safe-method GET/HEAD → 307 redirect to the refresh handler
 *     (`/api/auth/refresh?next=<current>`). The refresh handler
 *     exchanges the refresh token against auth-core and bounces
 *     the user back to `<current>` with a freshly-rotated cookie
 *     pair — they never see the sign-in page just because the
 *     15-minute access JWT aged out.
 *   - Otherwise → 307 redirect to `/sign-in?next=<current>`.
 *
 * Verification is on by default (security audit 2026-09-18, SDK-5).
 * Before that this middleware gated on cookie PRESENCE alone, so
 * `document.cookie = "authio_session=x"` walked straight through it —
 * safe only if every protected page independently called `auth()`,
 * which nothing told you to do. Pass `verify: false` to restore the old
 * behaviour if you have that discipline and measured a problem.
 *
 * Silent-renewal is GATED to safe methods because following a 307
 * across a refresh round-trip would lose the original request body
 * / method. A POST from a stale tab falls through to the /sign-in
 * branch; once the user re-authenticates they can resubmit.
 *
 * Use directly in your `src/middleware.ts`:
 *
 * ```ts
 * import { createAuthioMiddleware } from "@useauthio/nextjs";
 *
 * export default createAuthioMiddleware();
 *
 * export const config = {
 *   matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
 * };
 * ```
 *
 * For a customer with their own auth-gated section, set
 * `publicPaths` to whatever the marketing site / public pages live
 * under so they don't get caught by the redirect.
 */
export function createAuthioMiddleware(opts: AuthioMiddlewareOptions = {}) {
  const sessionCookieName = opts.sessionCookieName ?? DEFAULT_SESSION_COOKIE;
  const refreshCookieName = opts.refreshCookieName ?? DEFAULT_REFRESH_COOKIE;
  const signInPath = opts.signInPath ?? "/sign-in";
  const refreshPath = opts.refreshPath ?? "/api/auth/refresh";
  const publicPaths = opts.publicPaths ?? DEFAULT_PUBLIC_PATHS;
  const nextParam = opts.nextParam ?? "next";
  const proactiveThreshold =
    typeof opts.proactiveRefreshThreshold === "number" &&
    opts.proactiveRefreshThreshold > 0 &&
    opts.proactiveRefreshThreshold <= 1
      ? opts.proactiveRefreshThreshold
      : null;

  const verify = opts.verify !== false;
  const apiUrl = (opts.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, "");
  const issuer = opts.issuer ?? DEFAULT_ISSUER;
  const audience = opts.audience ?? DEFAULT_AUDIENCE;
  const projectId = opts.projectId ?? envProjectId();
  // Built once per middleware instance; jose caches the document and
  // refetches only on an unknown `kid`.
  const jwks = verify
    ? createRemoteJWKSet(new URL(apiUrl + "/v1/auth/.well-known/jwks.json"))
    : null;

  if (verify && !projectId) warnNoProjectBinding();

  /**
   * True when the access cookie is a genuine, unexpired token for this
   * tenant. A failure here is treated exactly like a missing cookie: the
   * caller falls through to silent refresh (safe methods with a refresh
   * cookie) or to the sign-in page. That also fixes a UX bug in the
   * presence-only behaviour — an EXPIRED access cookie used to be waved
   * through, so the user landed on a page whose `auth()` returned null
   * instead of being refreshed.
   */
  async function sessionState(
    token: string,
  ): Promise<"valid" | "expired" | "invalid"> {
    if (!jwks) return "valid";
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience,
        algorithms: ["EdDSA"],
      });
      if (projectId && payload.project_id !== projectId) return "invalid";
      if (typeof payload.sub !== "string" || !payload.sub) return "invalid";
      return "valid";
    } catch (err) {
      // Expiry is the one failure a refresh can actually fix. Everything
      // else — bad signature, wrong issuer/audience, wrong tenant — is
      // structural: bouncing through /api/auth/refresh would mint a token
      // that fails the same way, so we would ping-pong between the two
      // routes forever. Send those straight to sign-in.
      const code = (err as { code?: string } | null)?.code;
      return code === "ERR_JWT_EXPIRED" ? "expired" : "invalid";
    }
  }

  return async function authioMiddleware(
    req: NextRequest,
  ): Promise<NextResponse> {
    const { pathname, search } = req.nextUrl;

    for (const p of publicPaths) {
      // "/" is matched exact-only. Prefix-matching it with startsWith
      // would match every pathname and silently disable the whole gate.
      if (p === "/") {
        if (pathname === "/") return NextResponse.next();
        continue;
      }
      if (pathname === p || pathname.startsWith(p)) {
        return NextResponse.next();
      }
    }

    const session = req.cookies.get(sessionCookieName)?.value;
    const refresh = req.cookies.get(refreshCookieName)?.value;
    const next = pathname + (search ?? "");
    const isSafeMethod = req.method === "GET" || req.method === "HEAD";

    const state = session ? await sessionState(session) : "invalid";

    if (session && state === "valid") {
      // Proactive renewal: when the JWT is close enough to expiring
      // that the next page-load would otherwise hit the reactive
      // refresh path, route this safe-method navigation through the
      // refresh handler now. Saves the user one redirect on the
      // boundary navigation. No-op when the threshold isn't set or
      // the JWT lacks `iat`.
      if (proactiveThreshold && refresh && isSafeMethod) {
        const claims = decodeJwtUnverified(session);
        if (claims?.exp && claims?.iat) {
          const now = Math.floor(Date.now() / 1000);
          const remaining = claims.exp - now;
          const lifetime = claims.exp - claims.iat;
          if (
            remaining > 0 &&
            lifetime > 0 &&
            remaining < lifetime * proactiveThreshold
          ) {
            const url = req.nextUrl.clone();
            url.pathname = refreshPath;
            url.search = "";
            if (next && next !== "/") url.searchParams.set(nextParam, next);
            return NextResponse.redirect(url);
          }
        }
      }
      return NextResponse.next();
    }

    if (refresh && isSafeMethod && (!session || state === "expired")) {
      const url = req.nextUrl.clone();
      url.pathname = refreshPath;
      url.search = "";
      if (next && next !== "/") url.searchParams.set(nextParam, next);
      return NextResponse.redirect(url);
    }

    const url = req.nextUrl.clone();
    url.pathname = signInPath;
    url.search = "";
    if (next && next !== "/") url.searchParams.set(nextParam, next);
    return NextResponse.redirect(url);
  };
}
