import { cookies } from "next/headers";
import { createRemoteJWKSet, jwtVerify } from "jose";

export {
  createAuthioCallbackHandler,
  createAuthioRefreshHandler,
  createAuthioSignOutHandler,
  createAuthioSignInHandler,
  AUTHIO_SIGNIN_FLASH_COOKIE,
  readAuthioSignInError,
  type AuthioHandlerOptions,
  type AuthioCallbackHandlerOptions,
  type AuthioCallbackTokenVerification,
  type AuthioSignInHandlerOptions,
  type AuthioSignOutOptions,
} from "./handlers";
export type { AuthioCookieConfig } from "./config";

export interface AuthResult {
  userId: string | null;
  orgId: string | null;
  role: string | null;
  sessionId: string | null;
}

export interface AuthOptions {
  apiUrl?: string;
  issuer?: string;
  audience?: string;
}

export interface VerifyTokenOptions extends AuthOptions {
  /** Time in ms between forced JWKS refetches when a kid is missing. Default 30s. */
  cooldownDuration?: number;
  /** Time in ms the JWKS document is reused without refetch. Default 10m. */
  cacheMaxAge?: number;
}

let cachedJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let cachedJwksKey: string | null = null;

function getJwks(
  apiUrl: string,
  cooldownDuration: number,
  cacheMaxAge: number,
) {
  // Key the cache by apiUrl + cache parameters so different consumers
  // can request different freshness without stepping on each other.
  const key = `${apiUrl}|${cooldownDuration}|${cacheMaxAge}`;
  if (cachedJwks && cachedJwksKey === key) return cachedJwks;
  cachedJwksKey = key;
  cachedJwks = createRemoteJWKSet(
    new URL(apiUrl.replace(/\/$/, "") + "/v1/auth/.well-known/jwks.json"),
    { cooldownDuration, cacheMaxAge },
  );
  return cachedJwks;
}

const EMPTY: AuthResult = {
  userId: null,
  orgId: null,
  role: null,
  sessionId: null,
};

/**
 * Verify a raw access JWT against the auth-core JWKS. Returns the decoded
 * `AuthResult` on success or the empty shape on any failure.
 *
 * Use this from BFF callbacks (e.g. `/api/auth/callback`) where the token
 * arrives in the URL or request body rather than in the `authio_session`
 * cookie.
 */
export async function verifyToken(
  token: string,
  opts: VerifyTokenOptions = {},
): Promise<AuthResult> {
  if (!token) return EMPTY;
  const apiUrl = opts.apiUrl ?? "https://api.authio.com";
  const cooldownDuration = opts.cooldownDuration ?? 30_000;
  const cacheMaxAge = opts.cacheMaxAge ?? 600_000;
  try {
    const { payload } = await jwtVerify(
      token,
      getJwks(apiUrl, cooldownDuration, cacheMaxAge),
      {
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms: ["EdDSA"],
      },
    );
    return {
      userId: typeof payload.sub === "string" ? payload.sub : null,
      orgId: typeof payload.act_org === "string" ? payload.act_org : null,
      role: typeof payload.act_role === "string" ? payload.act_role : null,
      sessionId: typeof payload.sid === "string" ? payload.sid : null,
    };
  } catch {
    return EMPTY;
  }
}

/**
 * Read the current Authio session inside a Server Component, Route Handler,
 * or Server Action. Verifies the JWT in the `authio_session` cookie against
 * the JWKS endpoint.
 *
 * Returns `{ userId: null, … }` if no session is present or the token is
 * invalid. `orgId` may be null even when `userId` is set — that's a user
 * who has authenticated but not yet selected an organization.
 *
 * The cookie name can be overridden via `opts.cookieName`. Defaults to
 * `authio_session`. BFF dashboards typically use a different name (e.g.
 * `authio_dashboard_session`) so they don't collide with the auth-core
 * cookie when both are scoped to the same parent domain.
 */
export async function auth(
  opts: VerifyTokenOptions & { cookieName?: string } = {},
): Promise<AuthResult> {
  const store = await cookies();
  const cookie = store.get(opts.cookieName ?? "authio_session");
  if (!cookie?.value) return EMPTY;
  return verifyToken(cookie.value, opts);
}
