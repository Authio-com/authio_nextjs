# Changelog

All notable changes to `@useauthio/nextjs` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **PKCE for authorization-code callbacks.** `createAuthioCallbackHandler({
  acceptOAuthCode: true })` now sends `code_verifier` and `client_id` on
  `POST /v1/auth/token`, reading them from HttpOnly cookies set during sign-in.
- **`createAuthioSignInHandler({ oauthAuthorize })`** — opt-in DCR/CIMD OAuth
  authorize start with S256 PKCE (`GET {apiUrl}/v1/auth/authorize`). Pair with
  `acceptOAuthCode` on the callback handler.

### Fixed
- OAuth `?code=` exchange no longer omits PKCE params required by auth-core.

## [0.4.2] — 2026-06-17

### Added
- **Signed lobby context tokens.** `createAuthioSignInHandler()` now POSTs to
  `/v1/auth/lobby-context` and redirects with a short-lived `?ctx=…` param
  when auth-core supports it, so `project_id` and `redirect_uri` are not
  exposed in the browser URL. Falls back to legacy query params when minting
  fails.

### Changed
- README documents `AUTHIO_PROJECT_ID` as the dashboard environment ID,
  `hostedUiUrl` for branded auth hosts, and `cname.authiodns.com` as the
  DNS CNAME target (docs-only; runtime default hosted UI URL unchanged).

## [0.4.1] — 2026-06-13

### Fixed
- **`createAuthioMiddleware` `publicPaths` no longer treats `"/"` as a
  prefix.** Because matching used `pathname.startsWith(p)`, a
  `publicPaths` entry of `"/"` matched every path and silently turned the
  whole auth gate into a no-op. `"/"` is now exact-match only, so the
  landing page can stay public without disabling gating for protected
  routes. Other entries keep their prefix semantics.

## [0.4.0] — 2026-06-12

### Changed
- **Renamed npm package `@authio/nextjs` → `@useauthio/nextjs`.** The
  original `@authio` scope could not be claimed on npm, so every Authio
  SDK now publishes under the organization scope `@useauthio`. Install
  with `npm install @useauthio/nextjs` and update imports accordingly.
  The old `@authio/nextjs` name is retired; releases below this entry were
  published (or prepared) under the old name and are kept for history.

## [0.3.2] — 2026-06-06

### Fixed
- `createAuthioSignInHandler()` forwards `project_id` to Lobby when
  `AUTHIO_PROJECT_ID` is set in the server environment (or via the
  optional `projectId` handler option for tests).

## [0.3.1] — 2026-05-22

Hardening pass that moves off hand-rolled `jose`. All additions are
opt-in and existing 0.3.0 call sites continue to work without changes.

### Added

- **`createAuthioMiddleware({ proactiveRefreshThreshold })`** — when
  set to a number in `(0, 1]`, the middleware decodes the access JWT
  (unauthenticated, just to read `exp`/`iat`) and routes safe-method
  navigations through `/api/auth/refresh` once the JWT is in its
  last `proactiveRefreshThreshold` of life. Smooths the boundary
  navigation for customers running long-lived (24h+) access cookies
  — they never see the one-extra-redirect of reactive refresh on the
  navigation that happens to land in the last sliver of the JWT's
  life. No-op on JWTs without `iat`, on unsafe methods, or when the
  refresh cookie is missing. The middleware never trusts the decode
  for authorization; verification still happens in the RSC `auth()`
  helper and downstream APIs.
- **`createAuthioCallbackHandler({ verifyAccessToken })`** — when
  set, the callback verifies the access JWT against the Authio JWKS
  (EdDSA pinned, optional `issuer`/`audience`/`jwksUrl` claims)
  before persisting any cookies. Defense in depth on top of the
  cookie-bound state nonce: stops an attacker from planting a forged
  token in the victim's cookie jar even if they could craft a
  callback URL. Pass `true` for apiUrl-derived defaults or the full
  `AuthioCallbackTokenVerification` shape for explicit pinning.
- **`createAuthioCallbackHandler({ acceptOAuthCode })`** — when on,
  the callback also accepts the OAuth authorization-code shape
  (`?code=…`), exchanging it against `POST {apiUrl}/v1/auth/token`
  with `grant_type=authorization_code` and `redirect_uri` derived
  from the inbound request. Magic-link `?access_token=` still wins
  when both are present.
- **`createAuthioSignOutHandler({ signOutPaths })`** — array of
  revoke endpoints the handler walks in order. Defaults to
  `["/v1/auth/sign-out"]`. Pre-2026-05-21 auth-core deployments that
  didn't yet ship the `/v1/auth/sign-out` alias should pass
  `["/v1/auth/sign-out", "/v1/sessions/revoke"]` so the handler
  survives the rollout window. 401 (already revoked) and 2xx are
  both treated as success.
- **`apiHeaders`** option on every handler — extra headers folded
  onto every fetch into auth-core. Used by customers whose project
  resolution depends on a header (`X-Authio-Project: proj_…`)
  instead of host-mapped lookup, e.g. customers that haven't yet
  moved to a custom domain.

### Why

Some production deployments were hand-rolling `middleware.ts`, four
`app/api/auth/*` route handlers, and `lib/auth-cookies.ts` against
`jose` directly because 0.3.0 didn't expose three knobs they needed:
a proactive-refresh threshold (24h JWT TTL with no boundary-navigation
hiccup), an OAuth `?code=` callback (e.g. Google sign-in), and a
sign-out fallback chain (for projects that didn't yet have the
`/v1/auth/sign-out` alias). All three are generic capabilities every
Authio customer benefits from, so they ship in the SDK rather than
as per-app hand-rolling.

[0.3.1]: https://github.com/authio-com/authio_nextjs/releases/tag/v0.3.1

## [0.3.0] — 2026-05-22

### Added

- **`createAuthioSignInHandler()`** (`@authio/nextjs/server`) —
  drop-in `app/api/auth/sign-in/route.ts` handler. Generates a 32-byte
  random nonce, writes it to an HttpOnly `authio_callback_state`
  cookie (`SameSite=Lax`, 5-minute TTL), and 302s the browser to the
  hosted-UI (or a custom Authio domain) with the same value threaded
  as `?client_state_nonce=…`. The matching cookie ⟷ URL check in
  `createAuthioCallbackHandler` then closes the login-CSRF gap.

### Changed

- **`createAuthioCallbackHandler()` is now CSRF-aware.** When the
  `authio_callback_state` cookie is present, the handler refuses
  any callback whose `?client_state_nonce=` URL param is missing or
  doesn't match — the canonical defense against an attacker who
  crafts `/api/auth/callback?access_token=<their JWT>` and lures the
  victim. Refusals 307-redirect to `signInPath?error=csrf_state_mismatch`
  and clear the callback-state cookie. The constant-time string
  comparison keeps the same-length matching path free of timing
  side-channels.
- **Backwards-compatible degradation for legacy customers.** Apps
  that upgrade to v0.3 but keep their pre-v0.3 sign-in page (no
  `createAuthioSignInHandler`) continue to sign in users with a single
  `console.warn` line surfacing the gap to ops. They lose the
  login-CSRF protection but don't experience a hard break. Migration to the new sign-in
  handler is opt-in but **strongly recommended** — without it the
  login-CSRF vector remains open.
- **`AuthioCookieConfig`** grows two optional fields:
  `callbackStateCookieName` (default `authio_callback_state`) and
  `callbackStateCookieMaxAge` (default 300 seconds). Multi-BFF
  deployments under the same parent domain should rename the cookie
  to avoid collisions, exactly like `sessionCookieName` /
  `refreshCookieName` today.

### Compatibility

- Existing 0.2.x apps continue to work without changes; the new
  sign-in handler is opt-in. Calling `createAuthioCallbackHandler`
  without the cookie set is identical to the v0.2 behaviour modulo
  a single `console.warn` per request. Auth-core treats the
  `client_state_nonce` field as optional on the wire, so a v0.3
  callback handler still works against a v0.2-era auth-core if your
  customer pins their auth-core deployment (Authio Cloud is always
  on the latest).

### Migration

```ts
// app/api/auth/sign-in/route.ts — new in v0.3.
import { createAuthioSignInHandler } from "@authio/nextjs/server";
export const { GET, POST } = createAuthioSignInHandler();
export const dynamic = "force-dynamic";
```

Then change your sign-in `<a href="https://auth.authio.com/?…">` to
`<a href="/api/auth/sign-in">` (or a `<form action="/api/auth/sign-in">`
if you prefer a POST). The same `next` query param you used to
forward to auth.authio.com now goes to `/api/auth/sign-in?next=/dash`
and is round-tripped back via the embedded `redirect_uri` query.

[0.3.0]: https://github.com/authio-com/authio_nextjs/releases/tag/v0.3.0

## [0.2.0] — 2026-05-21

### Added

- **`createAuthioMiddleware()`** — drop-in Next.js middleware that
  handles the Authio session-refresh flow end-to-end. When the
  short-lived access cookie expires, the middleware silently routes
  the user through `/api/auth/refresh` to mint a fresh pair without
  ever showing the sign-in page. Configurable cookie names, paths,
  and public-route allowlist.
- **`createAuthioCallbackHandler()`** (`@authio/nextjs/server`) —
  drop-in `app/api/auth/callback/route.ts` handler. Persists
  `access_token` and `refresh_token` from the hosted-UI redirect to
  `authio_session` + `authio_refresh` cookies and bounces to a
  configurable post-sign-in path.
- **`createAuthioRefreshHandler()`** (`@authio/nextjs/server`) —
  drop-in `app/api/auth/refresh/route.ts` handler. Exchanges the
  refresh cookie against `POST {apiUrl}/v1/auth/refresh`, rotates
  both cookies, and 302s back to the original URL. Surfaces
  auth-core's policy-violation error codes (idle-timeout,
  absolute-timeout, refresh-window) so the UI can render a useful
  message.
- **`createAuthioSignOutHandler()`** (`@authio/nextjs/server`) —
  drop-in `app/api/auth/sign-out/route.ts` handler. Clears both
  cookies and (best-effort) revokes the underlying session row via
  `POST {apiUrl}/v1/auth/sign-out`.

### Why

The 0.1.x line shipped `authMiddleware()` which only checked for the
access cookie's presence. When the 15-minute access JWT aged out the
user was bounced to `/sign-in` — even though their refresh window
hadn't elapsed. Customers were rolling the refresh dance by hand.
v0.2 moves it into the SDK: a fresh-scaffolded
Next.js app now gets a full session lifecycle (sign-in, silent
renewal, sign-out) in roughly fifteen lines.

### Compatibility

`authMiddleware()` from 0.1.x is unchanged and still exported. Existing
apps continue to work without changes; the new helpers are opt-in.

[0.2.0]: https://github.com/authio-com/authio_nextjs/releases/tag/v0.2.0
