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
export {
  generateDPoPKey,
  createDPoPProof,
  sealDPoPKey,
  unsealDPoPKey,
  type DPoPKey,
} from "./dpop";
export {
  createAuthioWebhookHandler,
  verifyAuthioWebhookSignature,
  MemorySessionDenylist,
  getDefaultSessionDenylist,
  type SessionDenylist,
  type AuthioWebhookEvent,
  type AuthioWebhookHandlerOptions,
} from "./webhook";
import { getDefaultSessionDenylist, type SessionDenylist } from "./webhook";

export interface AuthResult {
  userId: string | null;
  orgId: string | null;
  role: string | null;
  sessionId: string | null;
  tokenKind: string | null;
  staffEmail: string | null;
}

/**
 * Security audit 2026-09-06/07 (SDK-1/SDK-3): auth-core mints every
 * customer, developer, platform, widget, and m2m token from the same
 * signing keys and the same fixed issuer/audience — `project_id` (and,
 * for non-customer tokens, `kind`) is the ONLY claim that tells them
 * apart. `issuer`/`audience` here default to production's real values
 * instead of `undefined` (which made jose skip the check entirely), and
 * `projectId`, once set, is enforced: a token minted in a DIFFERENT
 * project, or one that carries no project_id at all (a platform/widget/
 * m2m token, or a customer token from a build that predates this claim),
 * is refused rather than silently accepted. Without this, anyone who
 * signs up for their own Authio project could mint a token there and
 * have it accepted as an authenticated user of a completely different
 * app built on this SDK.
 */
const DEFAULT_ISSUER = "https://identity.authio.com";
const DEFAULT_AUDIENCE = "authio";

export interface AuthOptions {
  apiUrl?: string;
  issuer?: string;
  audience?: string;
  /**
   * Your Authio project ID (e.g. `AUTHIO_PROJECT_ID`). Strongly
   * recommended: without it, a token minted in ANY Authio project — not
   * just yours — verifies successfully. See the security note above.
   */
  projectId?: string;
}

export interface VerifyTokenOptions extends AuthOptions {
  /** Time in ms between forced JWKS refetches when a kid is missing. Default 30s. */
  cooldownDuration?: number;
  /** Time in ms the JWKS document is reused without refetch. Default 10m. */
  cacheMaxAge?: number;
  /**
   * Session denylist fed by `createAuthioWebhookHandler` (session.revoked
   * webhooks). Defaults to the process-wide memory denylist, so wiring
   * the webhook handler is enough on single-instance deploys. Pass your
   * shared adapter (Redis/KV) here on serverless/multi-instance deploys.
   */
  sessionDenylist?: SessionDenylist;
}

let cachedJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let cachedJwksKey: string | null = null;

function getJwks(
  apiUrl: string,
  cooldownDuration: number,
  cacheMaxAge: number,
) {
  return createAuthioJwks(apiUrl, cooldownDuration, cacheMaxAge);
}

/** Cached JWKS fetcher keyed by apiUrl + cache parameters. */
export function createAuthioJwks(
  apiUrl: string,
  cooldownDuration: number,
  cacheMaxAge: number,
) {
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
  tokenKind: null,
  staffEmail: null,
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
        issuer: opts.issuer ?? DEFAULT_ISSUER,
        audience: opts.audience ?? DEFAULT_AUDIENCE,
        algorithms: ["EdDSA"],
      },
    );
    if (opts.projectId) {
      if (payload.project_id !== opts.projectId) return EMPTY;
    }
    // Revocation-signals Phase 1: a structurally valid JWT whose session
    // was revoked (session.revoked webhook → denylist) is refused. The
    // default is the process-wide memory denylist fed by
    // createAuthioWebhookHandler — empty unless the app wired the
    // webhook, so this is a no-op for apps that haven't opted in.
    if (typeof payload.sid === "string" && payload.sid) {
      const denylist = opts.sessionDenylist ?? getDefaultSessionDenylist();
      if (await denylist.has(payload.sid)) return EMPTY;
    }
    return {
      userId: typeof payload.sub === "string" ? payload.sub : null,
      orgId: typeof payload.act_org === "string" ? payload.act_org : null,
      role: typeof payload.act_role === "string" ? payload.act_role : null,
      sessionId: typeof payload.sid === "string" ? payload.sid : null,
      tokenKind: typeof payload.kind === "string" ? payload.kind : null,
      staffEmail:
        typeof payload.staff_email === "string" ? payload.staff_email : null,
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
