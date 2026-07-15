<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# @useauthio/nextjs

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Next.js 14/15/16 adapter for Authio. Ships:

- **`createAuthioMiddleware()`** — drop-in Edge middleware with silent session refresh.
- **`createAuthioSignInHandler()`** — drop-in `app/api/auth/sign-in` handler that mints the cookie-bound login-CSRF nonce (v0.3+).
- **`createAuthioCallbackHandler()` / `createAuthioRefreshHandler()` / `createAuthioSignOutHandler()`** — drop-in `app/api/auth/*` route handlers.
- **`auth()`** — RSC helper that returns the verified session (`{ userId, orgId, role }`) inside Server Components and Route Handlers.
- **`authMiddleware()`** — the original v0.1 JWKS-verifying middleware. Still exported for backward compat.

## Recent additions

- **Embed `@useauthio/widgets` in App Router pages.** Mint the widget
  JWT in a Server Component (or Server Action) using the existing
  `auth()` accessToken; render the widget inside a `"use client"`
  component. Full snippet on
  [`/sdks/nextjs`](https://docs.authio.com/sdks/nextjs#embedding-authiowidgets-in-a-nextjs-app).
- **Kind-aware route gating.** Widget JWTs (`kind: "widget"`) are
  refused on every customer-session surface by the data plane, but
  if you ever embed your own JWKS verify in middleware (e.g. for a
  proxied admin tool), reject `kind === "widget"` with
  `widget_token_not_allowed_here` — the canonical refusal.
- **Roles + permissions on the session.** `auth()` exposes
  `session.claims.roles` (string in single-role mode, array in
  multi-role mode) and `session.claims.permissions` (always an
  array). Both are reserved-claim names; the only override path is
  the Pattern 3 Actions hook
  ([`/actions/pattern-3-customer-roles`](https://docs.authio.com/actions/pattern-3-customer-roles)).
- **MCP / DCR.** Customers turning their product into an OAuth
  provider can now flip `dcr_mode` and `cimd_enabled` in the
  dashboard. The Next.js adapter is unchanged — the
  `/.well-known/oauth-authorization-server` advertisements are
  served by `auth-core` and the new `/oauth2/register` /
  `/oauth2/cimd/resolve` endpoints are reachable directly with any
  HTTP client. See
  [`/guides/mcp-integration`](https://docs.authio.com/guides/mcp-integration).

## Install

```bash
pnpm add @useauthio/nextjs @useauthio/react
```

## Full session lifecycle in twenty lines

```ts
// src/middleware.ts
import { createAuthioMiddleware } from "@useauthio/nextjs";
export default createAuthioMiddleware();
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

```ts
// app/api/auth/sign-in/route.ts  (new in v0.3 — closes the login-CSRF gap)
import { createAuthioSignInHandler } from "@useauthio/nextjs/server";
export const { GET, POST } = createAuthioSignInHandler();
export const dynamic = "force-dynamic";
```

```ts
// app/api/auth/callback/route.ts
import { createAuthioCallbackHandler } from "@useauthio/nextjs/server";
export const GET = createAuthioCallbackHandler();
```

```ts
// app/api/auth/refresh/route.ts
import { createAuthioRefreshHandler } from "@useauthio/nextjs/server";
export const GET = createAuthioRefreshHandler();
```

```ts
// app/api/auth/sign-out/route.ts
import { createAuthioSignOutHandler } from "@useauthio/nextjs/server";
export const { GET, POST } = createAuthioSignOutHandler();
```

Point your "Sign in" link at the new handler — `<a href="/api/auth/sign-in">Sign in</a>`
— instead of the hosted-UI URL directly. The handler mints a CSRF nonce, sets
the `authio_callback_state` cookie on your origin, and redirects to Authio with
the same value as `?client_state_nonce=…`. The callback handler then verifies
cookie ⟷ URL match before persisting any session.

That's it. You now have sign-in, silent refresh, sign-out, and login-CSRF
defense — and your users stay signed in for the full org-policy refresh window
(default 30 days) even though the underlying access JWT rotates every 15
minutes.

## Login-CSRF defense

The v0.3 release closes a login-CSRF gap: an attacker who legitimately obtains an Authio access token
could otherwise craft `/api/auth/callback?access_token=<their JWT>` and trick a
victim into silently signing in as the attacker on the victim's browser.

The defense is the OAuth-style cookie-bound state nonce. The sign-in handler
mints a 32-byte random nonce, sets it as an HttpOnly cookie on your origin,
and forwards the same value to Authio. Auth-core persists it on the magic-link
/ OAuth state row and echoes it back on the callback redirect. The callback
handler refuses any callback where cookie and URL disagree.

### Upgrading an older integration

Callbacks now fail closed by default: the state cookie must match the callback
nonce and the access token must verify against Authio's JWKS. Add
`createAuthioSignInHandler` and point your sign-in link at
`/api/auth/sign-in` before upgrading.

If a staged migration is unavoidable, the temporary
`dangerouslyAllowInsecureLegacyCallback: true` callback option restores the old
fail-open behavior. Its name is intentional: this disables the state
requirement and default JWT verification, leaving the app open to login CSRF
and forged callback tokens. Remove it as soon as the sign-in-start route is
deployed. Passing `verifyAccessToken: false` alone does not weaken the secure
default.

## In a Server Component

```tsx
import { auth } from "@useauthio/nextjs/server";

export default async function Page() {
  const { userId, orgId } = await auth();
  return <div>User {userId} in org {orgId ?? "(none selected)"}</div>;
}
```

## Environment ID and custom auth domains

`AUTHIO_PROJECT_ID` is your dashboard **environment ID** (`proj_…`). The env
var name is legacy; the API field is still `project_id`. Set it in server
env so `createAuthioSignInHandler()` can forward it to Lobby (via a signed
`ctx` token when auth-core supports it, or legacy query params as fallback).

The sign-in handler's default hosted UI URL is `https://auth.authio.com/`.
Customers on the platform Lobby or a branded auth host pass `hostedUiUrl`:

```ts
createAuthioSignInHandler({
  hostedUiUrl: process.env.AUTHIO_HOSTED_UI_URL ?? "https://lobby.authio.com/",
});
```

For an explicit retry route that must show the sign-in panel even when Lobby
has a warm session, configure that route's handler with `prompt: "login"`.
The prompt is included in signed Lobby context and does not put callback
errors or tokens in the redirect URL.

DNS for a vanity auth hostname (e.g. `auth.acme.com`) is dashboard-side: CNAME
to **`cname.authiodns.com`**. The SDK never references that CNAME at runtime —
only your `hostedUiUrl` / end-user sign-in URL changes. See
[Custom domains](https://docs.authio.com/guides/custom-domains).

## Configuring cookie names

Multiple BFFs under the same parent domain need distinct cookie names so they
don't collide. Pass the same names to every helper:

```ts
const opts = {
  sessionCookieName: "myapp_session",
  refreshCookieName: "myapp_refresh",
  apiUrl: process.env.AUTHIO_API_URL,
};

export default createAuthioMiddleware(opts);
export const GET = createAuthioCallbackHandler(opts);
```

## License

MIT
