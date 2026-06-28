/**
 * Shared config shape across the v0.2 middleware + route handlers.
 *
 * The defaults are the public Authio cookie-name convention. Customers
 * who run multiple BFFs under the same parent domain (e.g. the Authio
 * dashboard alongside a customer app) should rename them to avoid
 * collisions — the dashboard uses `authio_dashboard_session` /
 * `authio_dashboard_refresh` for that reason.
 */
export interface AuthioCookieConfig {
  /**
   * Authio API base URL. Defaults to the production auth-api host
   * (`https://auth-api.authio.com`). For self-hosted deployments,
   * point this at your auth-core ingress.
   */
  apiUrl?: string;
  /** Cookie name for the access JWT. Defaults to "authio_session". */
  sessionCookieName?: string;
  /** Cookie name for the refresh token. Defaults to "authio_refresh". */
  refreshCookieName?: string;
  /**
   * Access-cookie TTL in seconds. Matches auth-core's access-JWT TTL
   * (15 minutes) by default; you almost never want to change this.
   * The cookie ages out roughly when the JWT does — silent renewal
   * via the middleware takes over from there.
   */
  accessCookieMaxAge?: number;
  /**
   * Refresh-cookie TTL in seconds. Defaults to 30 days. Auth-core
   * enforces the per-org `refresh_window_min` on every refresh
   * exchange, so a longer local cookie just decays into
   * "auth-core says no" on the next refresh — you don't need to
   * mirror org policy here.
   */
  refreshCookieMaxAge?: number;
  /**
   * Cookie name for the login-CSRF nonce that the sign-in handler
   * writes and the callback handler reads. Defaults to
   * `authio_callback_state`. Multi-BFF deployments under the same
   * parent domain should rename this alongside the session/refresh
   * cookies to avoid collisions.
   */
  callbackStateCookieName?: string;
  /**
   * TTL for the callback-state cookie in seconds. Defaults to 5
   * minutes — long enough for the user to complete the sign-in
   * ceremony (open mail client, click magic-link, return; or click
   * "Sign in with Google", auth at the IdP, return) but short enough
   * that an attacker who plants the cookie has a tight clock to
   * exploit it.
   */
  callbackStateCookieMaxAge?: number;
  /**
   * Cookie name for the PKCE code_verifier written during an OAuth
   * authorize sign-in and read by the callback handler on `?code=`
   * exchange. Defaults to `authio_pkce_verifier`.
   */
  pkceVerifierCookieName?: string;
  /**
   * Cookie name for the DCR client_id written during OAuth authorize
   * sign-in. Defaults to `authio_oauth_client_id`.
   */
  oauthClientIdCookieName?: string;
}

export interface ResolvedAuthioCookieConfig {
  apiUrl: string;
  sessionCookieName: string;
  refreshCookieName: string;
  accessCookieMaxAge: number;
  refreshCookieMaxAge: number;
  callbackStateCookieName: string;
  callbackStateCookieMaxAge: number;
  pkceVerifierCookieName: string;
  oauthClientIdCookieName: string;
}

export const DEFAULT_API_URL = "https://auth-api.authio.com";
export const DEFAULT_SESSION_COOKIE = "authio_session";
export const DEFAULT_REFRESH_COOKIE = "authio_refresh";
export const DEFAULT_ACCESS_COOKIE_MAX_AGE = 15 * 60;
export const DEFAULT_REFRESH_COOKIE_MAX_AGE = 30 * 24 * 60 * 60;
export const DEFAULT_CALLBACK_STATE_COOKIE = "authio_callback_state";
export const DEFAULT_CALLBACK_STATE_COOKIE_MAX_AGE = 5 * 60;
export const DEFAULT_PKCE_VERIFIER_COOKIE = "authio_pkce_verifier";
export const DEFAULT_OAUTH_CLIENT_ID_COOKIE = "authio_oauth_client_id";

export function resolveCookieConfig(
  opts: AuthioCookieConfig = {},
): ResolvedAuthioCookieConfig {
  return {
    apiUrl: (opts.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, ""),
    sessionCookieName: opts.sessionCookieName ?? DEFAULT_SESSION_COOKIE,
    refreshCookieName: opts.refreshCookieName ?? DEFAULT_REFRESH_COOKIE,
    accessCookieMaxAge: opts.accessCookieMaxAge ?? DEFAULT_ACCESS_COOKIE_MAX_AGE,
    refreshCookieMaxAge:
      opts.refreshCookieMaxAge ?? DEFAULT_REFRESH_COOKIE_MAX_AGE,
    callbackStateCookieName:
      opts.callbackStateCookieName ?? DEFAULT_CALLBACK_STATE_COOKIE,
    callbackStateCookieMaxAge:
      opts.callbackStateCookieMaxAge ?? DEFAULT_CALLBACK_STATE_COOKIE_MAX_AGE,
    pkceVerifierCookieName:
      opts.pkceVerifierCookieName ?? DEFAULT_PKCE_VERIFIER_COOKIE,
    oauthClientIdCookieName:
      opts.oauthClientIdCookieName ?? DEFAULT_OAUTH_CLIENT_ID_COOKIE,
  };
}

/**
 * Constrains the `?next=` redirect target to same-origin paths so
 * /api/auth/refresh and /api/auth/callback can't be turned into open
 * redirects (`?next=https://evil`).
 */
export function safeNext(raw: string | null | undefined): string {
  if (!raw) return "/";
  if (!raw.startsWith("/")) return "/";
  if (raw.startsWith("//")) return "/";
  return raw;
}
