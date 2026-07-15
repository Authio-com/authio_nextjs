import { NextResponse, type NextRequest } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  resolveCookieConfig,
  safeNext,
  type AuthioCookieConfig,
  type ResolvedAuthioCookieConfig,
} from "./config";
import { SDK_USER_AGENT } from "./version";

/**
 * Generate a 32-byte random nonce for the callback-state cookie.
 * Web Crypto is universally available across Edge + Node 18+; we avoid
 * `node:crypto` so this stays Edge-runtime safe. Returns base64url
 * (no padding), 43 chars — matches the auth-core sanitizer's accepted
 * charset.
 */
function generateCallbackStateNonce(): string {
  const bytes = new Uint8Array(32);
  // Web Crypto is in the global scope on every supported runtime
  // (Edge, Node 18+, Cloudflare Workers, Deno). No import needed.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).crypto.getRandomValues(bytes);
  // Convert to base64url manually so we don't need a buffer polyfill
  // on the Edge runtime where Buffer is not a global.
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  // btoa is available on Edge; produces base64 with `+`/`/`/`=`.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const b64 = (globalThis as any).btoa(bin) as string;
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const PKCE_CHARSET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const b64 = (globalThis as any).btoa(bin) as string;
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** RFC 7636 code_verifier — 64 chars from the unreserved charset. */
function generatePkceVerifier(): string {
  const bytes = new Uint8Array(64);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).crypto.getRandomValues(bytes);
  let verifier = "";
  for (let i = 0; i < bytes.length; i++) {
    verifier += PKCE_CHARSET[bytes[i]! % PKCE_CHARSET.length];
  }
  return verifier;
}

/** S256 code_challenge for a verifier (RFC 7636 §4.2). */
async function pkceChallengeS256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const digest = await (globalThis as any).crypto.subtle.digest(
    "SHA-256",
    data,
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

/**
 * Route-handler factories. These are the BFF half of the Authio
 * cookie-renewal flow:
 *
 *   - `createAuthioCallbackHandler()` →  app/api/auth/callback/route.ts
 *   - `createAuthioRefreshHandler()`  →  app/api/auth/refresh/route.ts
 *   - `createAuthioSignOutHandler()`  →  app/api/auth/sign-out/route.ts
 *
 * They mirror the contract used by the hosted-UI redirect and the
 * `/v1/auth/refresh` endpoint exactly — what the Authio dashboard
 * itself runs in production. Everything is configurable but the
 * defaults match what `createAuthioMiddleware()` expects, so a
 * customer who scaffolds with `create-authio-app` gets a working
 * session lifecycle by importing four functions.
 */

export interface AuthioHandlerOptions extends AuthioCookieConfig {
  /** Path to redirect to on success (callback). Defaults to "/". */
  signedInRedirect?: string;
  /** Path to redirect to on auth failure. Defaults to "/sign-in". */
  signInPath?: string;
  /**
   * Extra headers to attach to every fetch into auth-core. Useful for
   * customers whose project resolution depends on a header
   * (`X-Authio-Project: proj_…`) instead of the host-mapped lookup
   * the public `auth-api.authio.com` does. Set this once on every
   * handler factory invocation alongside `apiUrl`.
   */
  apiHeaders?: Record<string, string>;
  /**
   * How error codes travel to the sign-in page when a handler bounces.
   *
   *   - `"flash"` (default, v0.5): the code is carried in the
   *     short-lived `authio_signin_flash` cookie and the redirect URL
   *     stays clean. Read it with `readAuthioSignInError()` on your
   *     sign-in page. Error codes in URLs leak into browser history,
   *     server access logs, Referer headers, and analytics — Authio
   *     surfaces no longer write them.
   *   - `"query"`: the pre-v0.5 behaviour (`/sign-in?error=<code>`),
   *     kept as an escape hatch for apps that parse the query string
   *     and can't migrate yet.
   *
   * `readAuthioSignInError()` reads BOTH sources, so upgrading the
   * SDK never breaks an existing sign-in page.
   */
  errorPassing?: "flash" | "query";
}

/**
 * One-shot flash cookie that carries the sign-in error code across the
 * redirect to `signInPath`. Deliberately NOT HttpOnly so client
 * components can read + clear it (`document.cookie`); it contains only
 * a stable machine code (e.g. "missing_token"), never user data or
 * secrets, and self-expires after 60 seconds.
 */
export const AUTHIO_SIGNIN_FLASH_COOKIE = "authio_signin_flash";

/** Legal shape for flash codes — locked down so a poisoned cookie can't
 * smuggle markup/URLs into customer sign-in pages that render the code. */
const SIGNIN_ERROR_CODE_RE = /^[a-z0-9_.-]{1,64}$/i;

/**
 * Read the sign-in error code left by an Authio handler bounce, if any.
 *
 * Checks the `authio_signin_flash` cookie first (v0.5+ default), then
 * falls back to the legacy `?error=` / `?err=` query params so pages
 * keep working against older SDK versions and older Authio deployments.
 *
 * Usage (App Router server component):
 *
 * ```ts
 * import { cookies } from "next/headers";
 * import { AUTHIO_SIGNIN_FLASH_COOKIE, readAuthioSignInError } from "@useauthio/nextjs/server";
 *
 * const jar = await cookies();
 * const error = readAuthioSignInError({
 *   cookieValue: jar.get(AUTHIO_SIGNIN_FLASH_COOKIE)?.value,
 *   searchParams: await searchParams, // legacy fallback
 * });
 * ```
 *
 * The cookie self-expires in 60 s; clear it eagerly from a client
 * component if you re-render the sign-in page without a navigation.
 */
export function readAuthioSignInError(source: {
  /** Value of the `authio_signin_flash` cookie, when present. */
  cookieValue?: string | null;
  /** Page `searchParams` (or a URLSearchParams) for the legacy fallback. */
  searchParams?:
    | URLSearchParams
    | Record<string, string | string[] | undefined>
    | null;
}): string | null {
  const candidates: Array<string | null | undefined> = [source.cookieValue];
  const sp = source.searchParams;
  if (sp instanceof URLSearchParams) {
    candidates.push(sp.get("error"), sp.get("err"));
  } else if (sp) {
    for (const key of ["error", "err"]) {
      const v = sp[key];
      candidates.push(Array.isArray(v) ? v[0] : v);
    }
  }
  for (const c of candidates) {
    const code = (c ?? "").trim();
    if (code && SIGNIN_ERROR_CODE_RE.test(code)) return code;
  }
  return null;
}

export interface AuthioCallbackTokenVerification {
  /** JWT issuer the token must declare. */
  issuer?: string;
  /** JWT audience the token must declare. */
  audience?: string;
  /**
   * JWKS URL. Defaults to `${apiUrl}/v1/auth/.well-known/jwks.json`.
   * Override only if your deployment serves the JWKS off a different
   * host than the auth-core API.
   */
  jwksUrl?: string;
}

interface AuthCoreRefreshEnvelope {
  access_token?: string;
  refresh_token?: string;
  expires_at?: string;
}

interface AuthCoreErrorBody {
  code?: string;
  error?: string;
  message?: string;
}

/**
 * Cookie shape used for every Authio cookie we set. The matrix
 * (`secure` flips in dev, `sameSite=lax` matches the default we
 * recommend for first-party BFFs) is locked in here so customers
 * can't accidentally weaken it.
 */
// Next.js exposes process.env on both Edge and Node runtimes, but
// @types/node is intentionally NOT a dependency of this package
// (we run in Edge too). Reference process via globalThis so the
// build doesn't need node typings.
function isProduction(): boolean {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = (globalThis as any).process as
    | { env?: Record<string, string | undefined> }
    | undefined;
  return p?.env?.NODE_ENV === "production";
}

/** Project ID from AUTHIO_PROJECT_ID (server env). Never stringifies undefined. */
function envProjectId(): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = (globalThis as any).process as
    | { env?: Record<string, string | undefined> }
    | undefined;
  const id = p?.env?.AUTHIO_PROJECT_ID?.trim();
  return id || undefined;
}

function envOrganizationId(): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = (globalThis as any).process as
    | { env?: Record<string, string | undefined> }
    | undefined;
  const id = p?.env?.AUTHIO_ORGANIZATION_ID?.trim();
  return id || undefined;
}

function rawEnvProjectId(): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = (globalThis as any).process as
    | { env?: Record<string, string | undefined> }
    | undefined;
  return p?.env?.AUTHIO_PROJECT_ID;
}

function cookieOptions(maxAge: number): {
  httpOnly: true;
  secure: boolean;
  sameSite: "lax";
  path: string;
  maxAge: number;
} {
  return {
    httpOnly: true,
    secure: isProduction(),
    sameSite: "lax",
    path: "/",
    maxAge,
  };
}

/**
 * Redirect to the sign-in page carrying `error` via the configured
 * channel. Default is the flash cookie (see AUTHIO_SIGNIN_FLASH_COOKIE);
 * `errorPassing: "query"` restores the legacy `?error=` URL param.
 */
function signInErrorRedirect(
  origin: string,
  signInPath: string,
  next: string,
  error: string,
  errorPassing: "flash" | "query",
): NextResponse {
  const target = new URL(`${origin}${signInPath}`);
  if (errorPassing === "query") target.searchParams.set("error", error);
  if (next !== "/") target.searchParams.set("next", next);
  const res = NextResponse.redirect(target);
  if (errorPassing === "flash") {
    res.cookies.set(AUTHIO_SIGNIN_FLASH_COOKIE, error, {
      httpOnly: false,
      secure: isProduction(),
      sameSite: "lax",
      path: "/",
      maxAge: 60,
    });
  }
  return res;
}

function clearAuthCookies(
  res: NextResponse,
  cfg: ResolvedAuthioCookieConfig,
): NextResponse {
  res.cookies.set(cfg.sessionCookieName, "", { maxAge: 0, path: "/" });
  res.cookies.set(cfg.refreshCookieName, "", { maxAge: 0, path: "/" });
  return res;
}

/** Public-facing origin behind Railway / Vercel / Cloudflare's edge. */
function publicOrigin(req: NextRequest | Request): string {
  const headers =
    req instanceof Request ? req.headers : (req as NextRequest).headers;
  const xfh = headers.get("x-forwarded-host");
  const xfp = headers.get("x-forwarded-proto");
  if (xfh) return `${xfp || "https"}://${xfh}`;
  return new URL(req.url).origin;
}

/**
 * Fold extra `apiHeaders` from the handler config onto the standard
 * `Content-Type: application/json` baseline. Used by every
 * auth-core fetch the handlers initiate. Caller-supplied keys win
 * — customers can override `Content-Type` if they need to.
 */
function authCoreHeaders(extras?: Record<string, string>): HeadersInit {
  return {
    "Content-Type": "application/json",
    "X-Authio-SDK": SDK_USER_AGENT,
    ...(extras ?? {}),
  };
}

let cachedCallbackJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let cachedCallbackJwksUrl: string | null = null;

/**
 * Resolve the JWKS handle for the callback verifier, with module-
 * scoped caching keyed by the URL. `createRemoteJWKSet` is itself
 * cache-aware (cooldown + cacheMaxAge) so a warm callback doesn't
 * re-fetch the JWKS on every invocation; we just want one handle
 * per distinct JWKS URL.
 */
function getCallbackJwks(jwksUrl: string) {
  if (cachedCallbackJwks && cachedCallbackJwksUrl === jwksUrl) {
    return cachedCallbackJwks;
  }
  cachedCallbackJwksUrl = jwksUrl;
  cachedCallbackJwks = createRemoteJWKSet(new URL(jwksUrl));
  return cachedCallbackJwks;
}

/**
 * Verify the access JWT carried in a callback URL against the
 * configured JWKS. Algorithm is pinned to EdDSA (auth-core's signer
 * key kind); issuer + audience are checked when configured. Any
 * verification failure returns `false` — the caller bounces to
 * `/sign-in?error=invalid_token` so an attacker can never plant a
 * forged token in the victim's cookie jar via a crafted callback URL.
 */
async function verifyCallbackToken(
  token: string,
  cfg: ResolvedAuthioCookieConfig,
  spec: AuthioCallbackTokenVerification | true,
): Promise<boolean> {
  const v: AuthioCallbackTokenVerification = spec === true ? {} : spec;
  const jwksUrl =
    v.jwksUrl ?? `${cfg.apiUrl}/v1/auth/.well-known/jwks.json`;
  try {
    await jwtVerify(token, getCallbackJwks(jwksUrl), {
      issuer: v.issuer,
      audience: v.audience,
      algorithms: ["EdDSA"],
    });
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------
// Sign-in start (login-CSRF nonce minting)
// ---------------------------------------------------------------------

export interface AuthioSignInHandlerOptions extends AuthioHandlerOptions {
  /**
   * Environment ID forwarded to Lobby (`proj_…`; API field `project_id`).
   * Defaults to `process.env.AUTHIO_PROJECT_ID` when set. Tests may override.
   */
  projectId?: string;
  /** Organization ID for org-scoped Lobby auth methods (`org_…`). */
  organizationId?: string;
  /**
   * Hosted-UI URL the user should be sent to. Defaults to
   * `https://auth.authio.com/`. Customers on a custom Authio domain
   * (e.g. `auth.acme.com`) pass their own host here. The handler
   * appends the sign-in query params (redirect_uri, client_state_nonce
   * and any forwarded `?next=`) to this URL.
   */
  hostedUiUrl?: string;
  /**
   * The path on the BFF that the magic-link callback / OAuth callback
   * eventually lands on. Defaults to `/api/auth/callback`. Combined
   * with the public origin to form the `redirect_uri` we ship to
   * auth-core / hosted-UI.
   */
  callbackPath?: string;
  /**
   * Forces a fresh interactive sign-in instead of allowing Lobby to resume a
   * warm browser session. Use `"login"` for explicit retry/recovery routes.
   */
  prompt?: "login";
  /**
   * When set, the sign-in handler starts a DCR/CIMD OAuth authorize flow
   * (`GET {apiUrl}/v1/auth/authorize`) instead of redirecting to Lobby.
   * Generates PKCE verifier/challenge, stores the verifier in an HttpOnly
   * cookie, and threads `state` (same value as `client_state_nonce`) for
   * login-CSRF defense on the callback.
   *
   * Pair with `createAuthioCallbackHandler({ acceptOAuthCode: true })`.
   */
  oauthAuthorize?: {
    /** DCR-registered client_id for the authorization request. */
    clientId: string;
    /** OAuth scope string. Defaults to `"openid"`. */
    scope?: string;
  };
}

const DEFAULT_HOSTED_UI_URL = "https://auth.authio.com/";

/**
 * GET /api/auth/sign-in
 *
 * The customer's "Sign in" link / button POSTs (or GETs, both work) to
 * this handler. The handler:
 *
 *   1. Generates a 32-byte random nonce.
 *   2. Writes it to an HttpOnly cookie (`authio_callback_state`) on
 *      the customer's own origin. `SameSite=Lax` so the cookie
 *      survives the cross-site redirect back from auth.authio.com
 *      (a `Strict` cookie would be stripped on the GET that comes
 *      back from the IdP / magic-link consume).
 *   3. Redirects (302) the user to the hosted-UI / auth-core with the
 *      same nonce threaded as `?client_state_nonce=…`. auth-core
 *      persists it on the magic-link / OAuth state row and echoes it
 *      back on the callback redirect.
 *
 * The matching createAuthioCallbackHandler then asserts cookie ⟷ URL
 * equality before persisting any token — closing the login-CSRF gap.
 *
 * This handler is brand-new in v0.3.0 — there's no v0.2 equivalent.
 * Customers who used to embed a raw `<a href="https://auth.authio.com/?…">`
 * link in their sign-in page should switch to `<a href="/api/auth/sign-in">`
 * (or a `<form action="/api/auth/sign-in">`) so the nonce gets minted.
 *
 * Backwards-compat for pre-v0.3 customers who continue to skip this
 * handler: createAuthioCallbackHandler degrades gracefully with a
 * console.warn rather than refusing the sign-in. Migration is
 * therefore opt-in but recommended urgently.
 */
export function createAuthioSignInHandler(
  opts: AuthioSignInHandlerOptions = {},
) {
  const cfg = resolveCookieConfig(opts);
  const hostedUiUrl = (opts.hostedUiUrl ?? DEFAULT_HOSTED_UI_URL).replace(
    /\/$/,
    "/",
  );
  const callbackPath = opts.callbackPath ?? "/api/auth/callback";
  const oauthAuthorize = opts.oauthAuthorize;

  async function handle(request: NextRequest): Promise<NextResponse> {
    const origin = publicOrigin(request);
    const next = safeNext(new URL(request.url).searchParams.get("next"));
    const nonce = generateCallbackStateNonce();

    const redirectUri = `${origin}${callbackPath}`;

    const oauthClientId = oauthAuthorize?.clientId?.trim();
    if (oauthClientId) {
      const codeVerifier = generatePkceVerifier();
      const codeChallenge = await pkceChallengeS256(codeVerifier);
      const authorizeUrl = new URL(`${cfg.apiUrl}/v1/auth/authorize`);
      authorizeUrl.searchParams.set("client_id", oauthClientId);
      authorizeUrl.searchParams.set("response_type", "code");
      authorizeUrl.searchParams.set("redirect_uri", redirectUri);
      authorizeUrl.searchParams.set("code_challenge", codeChallenge);
      authorizeUrl.searchParams.set("code_challenge_method", "S256");
      authorizeUrl.searchParams.set("state", nonce);
      if (opts.prompt === "login") {
        authorizeUrl.searchParams.set("prompt", "login");
      }
      authorizeUrl.searchParams.set(
        "scope",
        oauthAuthorize?.scope?.trim() || "openid",
      );

      const response = NextResponse.redirect(authorizeUrl);
      response.cookies.set(
        cfg.callbackStateCookieName,
        nonce,
        cookieOptions(cfg.callbackStateCookieMaxAge),
      );
      response.cookies.set(
        cfg.pkceVerifierCookieName,
        codeVerifier,
        cookieOptions(cfg.callbackStateCookieMaxAge),
      );
      response.cookies.set(
        cfg.oauthClientIdCookieName,
        oauthClientId,
        cookieOptions(cfg.callbackStateCookieMaxAge),
      );
      return response;
    }

    const projectId = opts.projectId?.trim() || envProjectId();
    const organizationId =
      opts.organizationId?.trim() || envOrganizationId();
    let target = new URL(hostedUiUrl);

    if (projectId) {
      const ctxBody: Record<string, string> = {
        project_id: projectId,
        redirect_uri: redirectUri,
        client_state_nonce: nonce,
      };
      if (next !== "/") {
        ctxBody.next = next;
      }
      if (organizationId) {
        ctxBody.organization_id = organizationId;
      }
      if (opts.prompt === "login") {
        ctxBody.prompt = "login";
      }
      const ctxRes = await fetch(
        `${cfg.apiUrl.replace(/\/$/, "")}/v1/auth/lobby-context`,
        {
          method: "POST",
          headers: authCoreHeaders(opts.apiHeaders),
          body: JSON.stringify(ctxBody),
        },
      );
      if (ctxRes.ok) {
        const ctxBody = (await ctxRes.json()) as { ctx?: unknown };
        if (typeof ctxBody.ctx === "string" && ctxBody.ctx.trim()) {
          target.searchParams.set("ctx", ctxBody.ctx.trim());
        }
      }
    }

    if (!target.searchParams.has("ctx")) {
      if (projectId) {
        target.searchParams.set("project_id", projectId);
      } else if (rawEnvProjectId() !== undefined) {
        console.warn(
          "[@useauthio/nextjs] AUTHIO_PROJECT_ID is set but empty — omitting project_id from the Lobby redirect. Set AUTHIO_PROJECT_ID=proj_… in your server env.",
        );
      }
      target.searchParams.set("redirect_uri", redirectUri);
      target.searchParams.set("client_state_nonce", nonce);
      if (next !== "/") {
        target.searchParams.set("next", next);
      }
      if (organizationId) {
        target.searchParams.set("organization_id", organizationId);
      }
      if (opts.prompt === "login") {
        target.searchParams.set("prompt", "login");
      }
    }

    const response = NextResponse.redirect(target);
    // SameSite=Lax — must survive the cross-site GET that comes back
    // from auth.authio.com → /api/auth/callback. Strict would strip
    // the cookie on that hop and the callback handler would 401 the
    // user. HttpOnly so JS on the page can't read it (defense vs. an
    // XSS that wants to forge a matching callback URL).
    response.cookies.set(
      cfg.callbackStateCookieName,
      nonce,
      cookieOptions(cfg.callbackStateCookieMaxAge),
    );
    return response;
  }

  return {
    GET: handle,
    POST: handle,
  };
}

// ---------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------

export interface AuthioCallbackHandlerOptions extends AuthioHandlerOptions {
  /**
   * DANGEROUS: restore the pre-0.5 callback behavior that accepted a
   * callback without a matching state cookie and did not verify its JWT
   * unless `verifyAccessToken` was separately enabled.
   *
   * This exists only to unblock staged migrations. It leaves the app open
   * to login CSRF and forged callback tokens and must not be used in new
   * integrations.
   */
  dangerouslyAllowInsecureLegacyCallback?: boolean;
  /**
   * Override how the handler logs the legacy (cookie-missing) path. The
   * default writes a single `console.warn` line so the gap is visible
   * to ops without breaking sign-in. Tests pass a spy to assert the
   * warning fires.
   */
  onLegacyCookieMissing?: (info: {
    reason: "no_cookie" | "no_nonce_on_url";
  }) => void;
  /**
   * Override how the handler logs the cookie ⟷ URL mismatch refusal.
   * Production callers don't need this; tests use it to assert the
   * refuse path took the right reason code.
   */
  onCsrfRefuse?: (info: {
    reason: "nonce_mismatch" | "nonce_missing_on_url";
  }) => void;
  /**
   * The callback verifies the access token against the
   * Authio JWKS before persisting it as a cookie. This is defense in
   * depth on top of the cookie-bound state nonce: the nonce check
   * proves the callback URL came back from a sign-in this same
   * browser initiated, and `verifyAccessToken` proves the token
   * itself was minted by Authio's signer.
   *
   * This defaults to `true`. Pass `true` to verify with `apiUrl`-derived JWKS / no claim
   * pinning, or pass `{ issuer, audience, jwksUrl? }` for an
   * explicit shape. `false` is honored only together with
   * `dangerouslyAllowInsecureLegacyCallback: true`.
   *
   * Verification failure surfaces as `?error=invalid_token` on the
   * sign-in page so customers can render a useful message.
   */
  verifyAccessToken?: boolean | AuthioCallbackTokenVerification;
  /**
   * When set, the callback also accepts the OAuth authorization-code
   * shape (`?code=…`). It exchanges the code against
   * `POST {apiUrl}/v1/auth/token` (grant_type=authorization_code) with
   * `redirect_uri` derived from the inbound request, then writes the
   * resulting access/refresh tokens as cookies — same path as the
   * magic-link `?access_token=` shape.
   *
   * Default: `false`. Customers using only magic-link / hosted-UI
   * redirects don't need this; customers wiring auth-core's OAuth
   * callbacks directly into their BFF do.
   */
  acceptOAuthCode?: boolean;
  /**
   * DCR client_id for the authorization-code token exchange. Used when
   * the sign-in handler did not set the oauth-client cookie (hand-rolled
   * BFF) or as a fallback after `AUTHIO_OAUTH_CLIENT_ID` env lookup.
   */
  oauthClientId?: string;
}

function envOAuthClientId(): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = (globalThis as any).process as
    | { env?: Record<string, string | undefined> }
    | undefined;
  const id = p?.env?.AUTHIO_OAUTH_CLIENT_ID?.trim();
  return id || undefined;
}

/**
 * GET /api/auth/callback
 *
 * Receives a short-lived `?code=…` from the hosted-UI redirect, exchanges
 * it server-to-server, and persists the returned tokens as
 * `authio_session` + `authio_refresh` cookies, then bounces the
 * browser to `signedInRedirect` (or the originally-requested
 * `?next=` path if present and same-origin).
 *
 * If neither a handoff code nor `access_token` can be resolved we bounce to `signInPath` with
 * `?error=missing_token` — the same code the dashboard surfaces so
 * customers can show a consistent message.
 *
 * **Login-CSRF defense**: before persisting any token, we
 * cross-check the `authio_callback_state` cookie (set by the v0.3
 * `createAuthioSignInHandler` BEFORE redirecting the user to
 * Authio) against the `?client_state_nonce=` URL param (or OAuth
 * `?state=`) that auth-core echoed back from the same value the SDK
 * threaded through the magic-link / OAuth start call.
 *
 *   - Cookie + URL both present and equal → proceed.
 *   - Cookie present, URL missing or mismatched → refuse with 401
 *     `csrf_state_mismatch`. This is the active-attack path.
 *   - Cookie missing → legacy (pre-v0.3) or hand-rolled BFF. We
 *     log a `console.warn` and proceed so customers who haven't
 *     migrated to the new sign-in handler don't see a hard break,
 *     but they don't get the protection either — the audit
 *     explicitly accepts this graceful-degradation posture for the
 *     v0.3.0 ship.
 *
 * After a successful validation the cookie is cleared (one-shot),
 * so a stale cookie left behind by an abandoned sign-in can't be
 * replayed against a future attacker-crafted callback URL.
 *
 * When `acceptOAuthCode` is enabled, the handler also exchanges
 * `?code=` at `POST /v1/auth/token` with the PKCE `code_verifier`
 * read from the HttpOnly cookie set by `createAuthioSignInHandler`
 * (`oauthAuthorize` option) or a hand-rolled BFF.
 */
export function createAuthioCallbackHandler(
  opts: AuthioCallbackHandlerOptions = {},
) {
  const cfg = resolveCookieConfig(opts);
  const signedInRedirect = opts.signedInRedirect ?? "/";
  const signInPath = opts.signInPath ?? "/sign-in";
  const errorPassing = opts.errorPassing ?? "flash";
  const insecureLegacyCallback =
    opts.dangerouslyAllowInsecureLegacyCallback === true;
  const verifySpec =
    opts.verifyAccessToken === false
      ? insecureLegacyCallback
        ? false
        : true
      : (opts.verifyAccessToken ?? !insecureLegacyCallback);
  const acceptOAuthCode = opts.acceptOAuthCode === true;
  const oauthClientIdOpt = opts.oauthClientId?.trim() || envOAuthClientId();
  const apiHeaders = opts.apiHeaders;
  const onLegacyCookieMissing =
    opts.onLegacyCookieMissing ??
    (({ reason }) => {
      // eslint-disable-next-line no-console
      console.warn(
        `[@useauthio/nextjs] callback handler: ${reason} — running in legacy ` +
          "(pre-v0.3) mode without cookie-bound CSRF protection. Upgrade " +
          "your sign-in page to use createAuthioSignInHandler from " +
          "@useauthio/nextjs/server to enable the login-CSRF defender. " +
          "See https://docs.authio.com/sdks/nextjs#login-csrf for details.",
      );
    });
  const onCsrfRefuse =
    opts.onCsrfRefuse ??
    (({ reason }) => {
      // eslint-disable-next-line no-console
      console.warn(
        `[@useauthio/nextjs] callback handler refused: ${reason}. This is the ` +
          "expected response to a login-CSRF attempt. If you're seeing " +
          "this for a legitimate user, check that your sign-in page sets " +
          "the authio_callback_state cookie BEFORE redirecting to Authio.",
      );
    });

  return async function GET(request: NextRequest): Promise<NextResponse> {
    const { searchParams } = new URL(request.url);
    // Lobby echoes client_state_nonce; OAuth authorize echoes state.
    const urlNonce =
      searchParams.get("client_state_nonce") ?? searchParams.get("state");
    const next = safeNext(searchParams.get("next"));
    const origin = publicOrigin(request);

    function bounce(error: string): NextResponse {
      return signInErrorRedirect(origin, signInPath, next, error, errorPassing);
    }

    function clearOAuthStateCookies(res: NextResponse): void {
      res.cookies.set(cfg.pkceVerifierCookieName, "", { maxAge: 0, path: "/" });
      res.cookies.set(cfg.oauthClientIdCookieName, "", { maxAge: 0, path: "/" });
    }

    let accessToken: string | null = searchParams.get("access_token");
    let refreshToken: string | null = searchParams.get("refresh_token");
    let pkceVerifierUsed = false;
    const callbackCode = searchParams.get("code");

    // Lobby and magic-link completions now return a 90-second, single-use
    // handoff code. Exchange it before considering the OAuth authorization-
    // code path: both use ?code=, but only OAuth requires the opt-in and PKCE
    // client cookies below.
    if (!accessToken && callbackCode) {
      try {
        const handoffRes = await fetch(
          `${cfg.apiUrl}/v1/auth/session-handoff/exchange`,
          {
            method: "POST",
            headers: authCoreHeaders(apiHeaders),
            body: JSON.stringify({
              code: callbackCode,
              redirect_uri: `${origin}${new URL(request.url).pathname}`,
              ...(urlNonce ? { client_state_nonce: urlNonce } : {}),
            }),
          },
        );
        if (handoffRes.ok) {
          const env = (await handoffRes.json().catch(() => ({}))) as {
            access_token?: string;
            refresh_token?: string;
          };
          accessToken = env.access_token ?? null;
          refreshToken = env.refresh_token ?? null;
        } else if (!acceptOAuthCode) {
          return bounce("handoff_exchange_failed");
        }
      } catch {
        if (!acceptOAuthCode) return bounce("handoff_network_error");
      }
    }

    // OAuth authorization-code shape — exchange the code for the
    // token envelope. Only attempted when `acceptOAuthCode` is on
    // AND we don't already have a magic-link `access_token`. Magic-
    // link is the primary happy path; OAuth is opt-in for customers
    // who wire auth-core's OAuth callbacks directly into their BFF.
    if (!accessToken && acceptOAuthCode) {
      const code = callbackCode;
      if (code) {
        const codeVerifier = request.cookies.get(
          cfg.pkceVerifierCookieName,
        )?.value;
        const clientId =
          request.cookies.get(cfg.oauthClientIdCookieName)?.value ??
          oauthClientIdOpt;
        if (!codeVerifier || !clientId) {
          const r = bounce("oauth_failed");
          clearOAuthStateCookies(r);
          return r;
        }
        try {
          const tokenRes = await fetch(`${cfg.apiUrl}/v1/auth/token`, {
            method: "POST",
            headers: authCoreHeaders(apiHeaders),
            body: JSON.stringify({
              grant_type: "authorization_code",
              code,
              client_id: clientId,
              redirect_uri: `${origin}${new URL(request.url).pathname}`,
              code_verifier: codeVerifier,
            }),
          });
          if (!tokenRes.ok) {
            const r = bounce("oauth_failed");
            clearOAuthStateCookies(r);
            return r;
          }
          pkceVerifierUsed = true;
          const env = (await tokenRes.json().catch(() => ({}))) as {
            access_token?: string;
            token?: string;
            refresh_token?: string;
          };
          accessToken = env.access_token ?? env.token ?? null;
          refreshToken = env.refresh_token ?? null;
        } catch {
          const r = bounce("oauth_network_error");
          clearOAuthStateCookies(r);
          return r;
        }
      }
    }

    if (!accessToken) return bounce("missing_token");

    // Cookie ⟷ URL cross-check. The cookie was set by
    // createAuthioSignInHandler on the customer's own origin, and the
    // URL param was echoed by auth-core from the same value the SDK
    // sent. A mismatch (or a missing URL value when the cookie is
    // set) is the login-CSRF attack signature.
    const cookieNonce = request.cookies.get(cfg.callbackStateCookieName)?.value;
    if (cookieNonce) {
      if (!urlNonce) {
        onCsrfRefuse({ reason: "nonce_missing_on_url" });
        return refuseCsrf(origin, signInPath, next, cfg, errorPassing);
      }
      if (!constantTimeEqual(cookieNonce, urlNonce)) {
        onCsrfRefuse({ reason: "nonce_mismatch" });
        return refuseCsrf(origin, signInPath, next, cfg, errorPassing);
      }
    } else if (insecureLegacyCallback) {
      // Legacy: pre-v0.3 customers who use only createAuthioCallback
      // Handler (without the matching createAuthioSignInHandler) end
      // up here. Warn loudly but don't break sign-in.
      onLegacyCookieMissing({
        reason: urlNonce ? "no_cookie" : "no_nonce_on_url",
      });
    } else {
      onCsrfRefuse({
        reason: urlNonce ? "nonce_mismatch" : "nonce_missing_on_url",
      });
      return refuseCsrf(origin, signInPath, next, cfg, errorPassing);
    }

    if (verifySpec) {
      const ok = await verifyCallbackToken(accessToken, cfg, verifySpec);
      if (!ok) {
        // One-shot: still clear the state-cookie so the abandoned
        // sign-in attempt can't be replayed.
        const r = bounce("invalid_token");
        if (cookieNonce) {
          r.cookies.set(cfg.callbackStateCookieName, "", {
            maxAge: 0,
            path: "/",
          });
        }
        return r;
      }
    }

    const destPath = next !== "/" ? next : signedInRedirect;
    const dest = new URL(`${origin}${destPath}`);
    const response = NextResponse.redirect(dest);
    response.cookies.set(
      cfg.sessionCookieName,
      accessToken,
      cookieOptions(cfg.accessCookieMaxAge),
    );
    if (refreshToken) {
      response.cookies.set(
        cfg.refreshCookieName,
        refreshToken,
        cookieOptions(cfg.refreshCookieMaxAge),
      );
    }
    // One-shot: clear the callback-state cookie so a leftover from an
    // abandoned sign-in cannot be replayed.
    if (cookieNonce) {
      response.cookies.set(cfg.callbackStateCookieName, "", {
        maxAge: 0,
        path: "/",
      });
    }
    if (pkceVerifierUsed) {
      clearOAuthStateCookies(response);
    }
    return response;
  };
}

/**
 * Refuse a login-CSRF attempt: bounce to the sign-in page with the
 * stable `csrf_state_mismatch` code (flash cookie by default, legacy
 * query param when `errorPassing: "query"`). Also clears the
 * callback-state cookie so the next sign-in attempt starts clean.
 */
function refuseCsrf(
  origin: string,
  signInPath: string,
  next: string,
  cfg: ResolvedAuthioCookieConfig,
  errorPassing: "flash" | "query",
): NextResponse {
  const res = signInErrorRedirect(
    origin,
    signInPath,
    next,
    "csrf_state_mismatch",
    errorPassing,
  );
  res.cookies.set(cfg.callbackStateCookieName, "", { maxAge: 0, path: "/" });
  return res;
}

/**
 * Length-independent equality check. Avoids leaking the cookie value
 * through a timing oracle even though the cookie is HttpOnly and the
 * attacker model here doesn't include sidechannels — defense in
 * depth, low cost.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ---------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------

/**
 * GET /api/auth/refresh?next=/wherever
 *
 * Silent BFF cookie auto-renewal. The middleware redirects here
 * when the short-lived access cookie is missing but the long-lived
 * refresh cookie is still present. We exchange the refresh token
 * against `POST {apiUrl}/v1/auth/refresh`, write rotated cookies,
 * and 302 the browser back to `next` (default "/").
 *
 * Failure modes auth-core enforces server-side and we surface to
 * `signInPath?error=<code>`:
 *   - idle-timeout exceeded (`policy_violation_session_idle`)
 *   - absolute-timeout exceeded (`policy_violation_session_absolute`)
 *   - refresh-window exceeded
 *   - refresh-token revoked / already-rotated (replay)
 *   - network-policy violation
 *
 * Transient network errors leave the cookies alone so the user can
 * retry on the next navigation — we never sacrifice a valid
 * refresh token to a 5-second outage.
 */
export function createAuthioRefreshHandler(opts: AuthioHandlerOptions = {}) {
  const cfg = resolveCookieConfig(opts);
  const signInPath = opts.signInPath ?? "/sign-in";
  const errorPassing = opts.errorPassing ?? "flash";
  const apiHeaders = opts.apiHeaders;

  return async function GET(request: NextRequest): Promise<NextResponse> {
    const url = new URL(request.url);
    const next = safeNext(url.searchParams.get("next"));
    const origin = publicOrigin(request);
    const refreshToken = request.cookies.get(cfg.refreshCookieName)?.value;

    function bounce(error: string): NextResponse {
      return signInErrorRedirect(origin, signInPath, next, error, errorPassing);
    }

    if (!refreshToken) {
      return clearAuthCookies(bounce("session_expired"), cfg);
    }

    let res: Response;
    try {
      res = await fetch(`${cfg.apiUrl}/v1/auth/refresh`, {
        method: "POST",
        headers: authCoreHeaders(apiHeaders),
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch {
      // DON'T clear cookies on network errors — the user will
      // retry, and a transient blip shouldn't burn the refresh.
      return bounce("refresh_network_error");
    }

    if (!res.ok) {
      let code = "refresh_failed";
      try {
        const body = (await res.json()) as AuthCoreErrorBody;
        code = body.code ?? body.error ?? code;
      } catch {
        /* body may be empty or non-JSON */
      }
      return clearAuthCookies(bounce(code), cfg);
    }

    const envelope = (await res
      .json()
      .catch(() => ({}))) as AuthCoreRefreshEnvelope;
    if (!envelope.access_token) {
      // Auth-core returned 200 OK but a malformed envelope. Treat
      // as transient — clearing cookies here would be worse than a
      // re-try on next navigation.
      return bounce("malformed_refresh_envelope");
    }

    const dest = new URL(`${origin}${next}`);
    const response = NextResponse.redirect(dest);
    response.cookies.set(
      cfg.sessionCookieName,
      envelope.access_token,
      cookieOptions(cfg.accessCookieMaxAge),
    );
    if (envelope.refresh_token) {
      response.cookies.set(
        cfg.refreshCookieName,
        envelope.refresh_token,
        cookieOptions(cfg.refreshCookieMaxAge),
      );
    }
    return response;
  };
}

// ---------------------------------------------------------------------
// Sign-out
// ---------------------------------------------------------------------

export interface AuthioSignOutOptions extends AuthioHandlerOptions {
  /**
   * Path to redirect to after sign-out. Defaults to "/sign-in".
   * Set to "/" if you want the user to land on the marketing
   * homepage instead.
   */
  signedOutRedirect?: string;
  /**
   * When true, also POST `{apiUrl}/v1/auth/sign-out` with the
   * access token so auth-core can revoke the underlying session
   * row server-side (idempotent — works even if the cookie is
   * already stale). Defaults to true.
   */
  revokeOnServer?: boolean;
  /**
   * Auth-core revoke endpoints to try in order. The first one that
   * accepts the Bearer token wins; on transient errors / unknown-
   * route 404s the helper falls back to the next entry. Defaults to
   * `["/v1/auth/sign-out"]`. Pre-2026-05-21 deployments that didn't
   * yet ship the `/v1/auth/sign-out` alias should pass
   * `["/v1/auth/sign-out", "/v1/sessions/revoke"]` so the handler
   * survives the rollout window.
   */
  signOutPaths?: string[];
}

const DEFAULT_SIGN_OUT_PATHS = ["/v1/auth/sign-out"];

/**
 * GET (or POST) /api/auth/sign-out
 *
 * Clears both Authio cookies and bounces to `signedOutRedirect`
 * (default "/sign-in"). Optionally fires a best-effort
 * `POST /v1/auth/sign-out` against auth-core to revoke the
 * underlying session row — that prevents a stale tab elsewhere
 * from continuing to use the refresh token.
 *
 * Customers who need the legacy `/v1/sessions/revoke` URL (pre
 * 2026-05-21 auth-core builds) can pass `signOutPaths` to walk
 * a fallback chain: the helper tries each path in order and
 * returns as soon as one accepts the Bearer or already-revoked.
 *
 * Returns 303 See Other so a form-POST sign-out button correctly
 * downgrades the method to GET on the redirect.
 */
export function createAuthioSignOutHandler(opts: AuthioSignOutOptions = {}) {
  const cfg = resolveCookieConfig(opts);
  const signedOutRedirect =
    opts.signedOutRedirect ?? opts.signInPath ?? "/sign-in";
  const revokeOnServer = opts.revokeOnServer ?? true;
  const signOutPaths =
    opts.signOutPaths && opts.signOutPaths.length > 0
      ? opts.signOutPaths
      : DEFAULT_SIGN_OUT_PATHS;
  const apiHeaders = opts.apiHeaders;

  async function revokeUpstream(accessToken: string): Promise<void> {
    for (const path of signOutPaths) {
      try {
        const res = await fetch(`${cfg.apiUrl}${path}`, {
          method: "POST",
          headers: {
            ...authCoreHeaders(apiHeaders),
            Authorization: `Bearer ${accessToken}`,
          },
          // Auth-core's handler reads session_id from the access JWT —
          // an empty body is fine, but Content-Type makes proxies happy.
          body: "{}",
        });
        if (res.ok || res.status === 204 || res.status === 401) {
          // 2xx = revoked. 401 = already revoked / expired token; treat
          // as success — we wanted the row gone, it's gone.
          return;
        }
      } catch {
        // Network-level failure on this path — try the next one.
      }
    }
  }

  async function handle(request: NextRequest): Promise<NextResponse> {
    const origin = publicOrigin(request);
    const accessToken = request.cookies.get(cfg.sessionCookieName)?.value;

    if (revokeOnServer && accessToken) {
      // Best-effort. If auth-core is unreachable we still clear the
      // local cookies — the worst case is the row outlives the
      // cookie, which is the pre-revocation behaviour anyway.
      await revokeUpstream(accessToken);
    }

    const response = NextResponse.redirect(
      new URL(`${origin}${signedOutRedirect}`),
      { status: 303 },
    );
    return clearAuthCookies(response, cfg);
  }

  return {
    GET: handle,
    POST: handle,
  };
}
