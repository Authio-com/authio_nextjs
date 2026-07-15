import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import {
  AUTHIO_SIGNIN_FLASH_COOKIE,
  createAuthioCallbackHandler as createSecureAuthioCallbackHandler,
  createAuthioRefreshHandler,
  createAuthioSignInHandler,
  createAuthioSignOutHandler,
  readAuthioSignInError,
} from "../src/handlers";

// Most tests below predate the secure-by-default migration and exercise
// unrelated callback behavior with synthetic (non-JWT) tokens. Keep those
// fixtures on the explicit compatibility path; dedicated tests below pin the
// production defaults.
const createAuthioCallbackHandler: typeof createSecureAuthioCallbackHandler = (
  options = {},
) =>
  createSecureAuthioCallbackHandler({
    dangerouslyAllowInsecureLegacyCallback: true,
    ...options,
  });

function makeReq(
  url: string,
  init: {
    cookies?: Record<string, string>;
    method?: string;
    headers?: Record<string, string>;
  } = {},
): NextRequest {
  const cookieHeader = Object.entries(init.cookies ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  const headers = new Headers(init.headers ?? {});
  if (cookieHeader) headers.set("cookie", cookieHeader);
  return new NextRequest(new URL(url), {
    method: init.method ?? "GET",
    headers,
  });
}

function setCookieMap(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  // NextResponse aggregates set-cookies via headers.getSetCookie() on
  // newer runtimes; fall back to a manual scan when unavailable.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getSetCookie = (res.headers as any).getSetCookie?.bind(res.headers);
  const cookies: string[] = getSetCookie
    ? getSetCookie()
    : res.headers.get("set-cookie")?.split(/,(?=[^ ]+=)/) ?? [];
  for (const c of cookies) {
    const [pair] = c.split(";");
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    out[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  return out;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// -------------------------------------------------------------------------
// Callback handler
// -------------------------------------------------------------------------

describe("createAuthioCallbackHandler", () => {
  it("rejects a callback without a pending state cookie by default", async () => {
    const handler = createSecureAuthioCallbackHandler();
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=unverified&client_state_nonce=state",
      ),
    );

    expect(res.headers.get("location")).toBe("https://app.test/sign-in");
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
      "csrf_state_mismatch",
    );
    expect(setCookieMap(res).authio_session).toBeUndefined();
  });

  it("verifies callback JWTs by default after state validation", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("no jwks")));
    const handler = createSecureAuthioCallbackHandler();
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=forged&client_state_nonce=state",
        { cookies: { authio_callback_state: "state" } },
      ),
    );

    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe("invalid_token");
    expect(setCookieMap(res).authio_session).toBeUndefined();
  });

  it("requires the deliberately dangerous option for legacy callbacks", async () => {
    const handler = createSecureAuthioCallbackHandler({
      dangerouslyAllowInsecureLegacyCallback: true,
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?access_token=legacy-token"),
    );

    expect(res.headers.get("location")).toBe("https://app.test/");
    expect(setCookieMap(res).authio_session).toBe("legacy-token");
  });

  it("sets both cookies and redirects to signedInRedirect on happy path", async () => {
    const handler = createAuthioCallbackHandler({ signedInRedirect: "/home" });
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=at&refresh_token=rt",
      ),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://app.test/home");
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("at");
    expect(cookies.authio_refresh).toBe("rt");
  });

  it("only sets the access cookie when refresh_token is missing", async () => {
    const handler = createAuthioCallbackHandler();
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?access_token=only-access"),
    );
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("only-access");
    expect(cookies.authio_refresh).toBeUndefined();
  });

  it("bounces to /sign-in with a missing_token flash cookie when access_token absent (default)", async () => {
    const handler = createAuthioCallbackHandler();
    const res = await handler(makeReq("https://app.test/api/auth/callback"));
    expect(res.headers.get("location")).toContain("/sign-in");
    // Platform mandate: error codes never travel in the query string.
    expect(res.headers.get("location")).not.toContain("error=");
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe("missing_token");
  });

  it("exchanges a Lobby handoff code and sets session cookies", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        access_token: "at-from-handoff",
        refresh_token: "rt-from-handoff",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler({
      apiUrl: "https://auth.test",
      apiHeaders: { "X-Authio-Project": "proj_x" },
    });
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?code=handoff-1&client_state_nonce=state",
        { cookies: { authio_callback_state: "state" } },
      ),
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.test/v1/auth/session-handoff/exchange",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          code: "handoff-1",
          redirect_uri: "https://app.test/api/auth/callback",
          client_state_nonce: "state",
        }),
      }),
    );
    expect(setCookieMap(res).authio_session).toBe("at-from-handoff");
    expect(setCookieMap(res).authio_refresh).toBe("rt-from-handoff");
  });

  it('errorPassing: "query" restores the legacy ?error= bounce', async () => {
    const handler = createAuthioCallbackHandler({ errorPassing: "query" });
    const res = await handler(makeReq("https://app.test/api/auth/callback"));
    expect(res.headers.get("location")).toContain("error=missing_token");
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBeUndefined();
  });

  it("uses ?next= path when present and same-origin", async () => {
    const handler = createAuthioCallbackHandler({ signedInRedirect: "/home" });
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=at&next=%2Fdeep%2Flink",
      ),
    );
    expect(res.headers.get("location")).toBe("https://app.test/deep/link");
  });

  it("refuses to honour an off-origin ?next= (open-redirect prevention)", async () => {
    const handler = createAuthioCallbackHandler({ signedInRedirect: "/home" });
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=at&next=https%3A%2F%2Fevil%2Fpwn",
      ),
    );
    expect(res.headers.get("location")).toBe("https://app.test/home");
  });

  // -----------------------------------------------------------------------
  // Cookie-bound login-CSRF nonce
  //
  // An attacker who lures a victim to a crafted
  //   /api/auth/callback?access_token=<attacker's JWT>&refresh_token=<…>
  // could silently log the victim into the attacker's account. The fix:
  // tie the callback to a cookie the customer's sign-in page set BEFORE
  // redirecting to Authio. Cookie ⟷ URL must match. These tests pin the
  // mismatch refusal, the matched happy path, the legacy-cookie-missing
  // graceful-degrade, and the one-shot cookie clear.
  // -----------------------------------------------------------------------

  describe("login-CSRF (client_state_nonce)", () => {
    it("accepts the callback when cookie ⟷ URL nonce match (happy path)", async () => {
      const onLegacyCookieMissing = vi.fn();
      const onCsrfRefuse = vi.fn();
      const handler = createAuthioCallbackHandler({
        onLegacyCookieMissing,
        onCsrfRefuse,
      });
      const res = await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=at&refresh_token=rt&client_state_nonce=abc123",
          { cookies: { authio_callback_state: "abc123" } },
        ),
      );
      expect(res.headers.get("location")).toBe("https://app.test/");
      const cookies = setCookieMap(res);
      expect(cookies.authio_session).toBe("at");
      expect(cookies.authio_refresh).toBe("rt");
      // One-shot: callback-state cookie cleared on success so a stale
      // cookie left behind by an abandoned sign-in can't be replayed.
      expect(cookies.authio_callback_state).toBe("");
      // Neither logger fired — happy path is silent.
      expect(onLegacyCookieMissing).not.toHaveBeenCalled();
      expect(onCsrfRefuse).not.toHaveBeenCalled();
    });

    it("refuses with csrf_state_mismatch when cookie and URL nonce differ", async () => {
      const onCsrfRefuse = vi.fn();
      const handler = createAuthioCallbackHandler({ onCsrfRefuse });
      const res = await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=at&client_state_nonce=attacker-value",
          { cookies: { authio_callback_state: "victim-value" } },
        ),
      );
      // Refuse → bounce to /sign-in with the stable code in the flash
      // cookie (never the query string).
      expect(res.headers.get("location")).toContain("/sign-in");
      expect(res.headers.get("location")).not.toContain("error=");
      expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
        "csrf_state_mismatch",
      );
      // No session cookie was set.
      const cookies = setCookieMap(res);
      expect(cookies.authio_session).toBeUndefined();
      expect(cookies.authio_refresh).toBeUndefined();
      // The callback-state cookie itself is cleared so the next attempt
      // starts clean.
      expect(cookies.authio_callback_state).toBe("");
      expect(onCsrfRefuse).toHaveBeenCalledWith({ reason: "nonce_mismatch" });
    });

    it("refuses when cookie is set but URL omits the nonce (attacker stripped it)", async () => {
      const onCsrfRefuse = vi.fn();
      const handler = createAuthioCallbackHandler({ onCsrfRefuse });
      const res = await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=attackers-jwt",
          { cookies: { authio_callback_state: "victim-value" } },
        ),
      );
      expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
        "csrf_state_mismatch",
      );
      const cookies = setCookieMap(res);
      expect(cookies.authio_session).toBeUndefined();
      expect(onCsrfRefuse).toHaveBeenCalledWith({
        reason: "nonce_missing_on_url",
      });
    });

    it("allows + warns when cookie is missing (legacy / pre-v0.3 customer)", async () => {
      // Pre-v0.3 customers used createAuthioCallbackHandler without the
      // matching createAuthioSignInHandler. We must NOT break sign-in for
      // them — but the warning surfaces the gap in their ops logs.
      const onLegacyCookieMissing = vi.fn();
      const handler = createAuthioCallbackHandler({ onLegacyCookieMissing });
      const res = await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=at&refresh_token=rt",
        ),
      );
      expect(res.headers.get("location")).toBe("https://app.test/");
      const cookies = setCookieMap(res);
      expect(cookies.authio_session).toBe("at");
      expect(cookies.authio_refresh).toBe("rt");
      // No callback-state cookie to clear — and we don't set a fresh one.
      expect(cookies.authio_callback_state).toBeUndefined();
      expect(onLegacyCookieMissing).toHaveBeenCalledWith({
        reason: "no_nonce_on_url",
      });
    });

    it("logs a different reason when URL has a nonce but cookie is missing", async () => {
      // Browser stripped the cookie (Brave shields / Firefox Strict ETP)
      // or the user hit the URL from a fresh browser. Same legacy path —
      // we warn but don't refuse, since the cookie absence is the
      // signal we use to detect "no protection wired".
      const onLegacyCookieMissing = vi.fn();
      const handler = createAuthioCallbackHandler({ onLegacyCookieMissing });
      await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=at&client_state_nonce=n_1",
        ),
      );
      expect(onLegacyCookieMissing).toHaveBeenCalledWith({
        reason: "no_cookie",
      });
    });

    it("works with renamed callbackStateCookieName for multi-BFF setups", async () => {
      const handler = createAuthioCallbackHandler({
        callbackStateCookieName: "myapp_callback_state",
      });
      const res = await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=at&client_state_nonce=n_1",
          { cookies: { myapp_callback_state: "n_1" } },
        ),
      );
      expect(res.headers.get("location")).toBe("https://app.test/");
      const cookies = setCookieMap(res);
      expect(cookies.authio_session).toBe("at");
      expect(cookies.myapp_callback_state).toBe("");
    });

    it("accepts OAuth ?state= as login-CSRF nonce when client_state_nonce absent", async () => {
      const handler = createAuthioCallbackHandler();
      const res = await handler(
        makeReq(
          "https://app.test/api/auth/callback?access_token=at&state=oauth-state-nonce",
          { cookies: { authio_callback_state: "oauth-state-nonce" } },
        ),
      );
      expect(res.headers.get("location")).toBe("https://app.test/");
      const cookies = setCookieMap(res);
      expect(cookies.authio_session).toBe("at");
      expect(cookies.authio_callback_state).toBe("");
    });
  });
});

// -------------------------------------------------------------------------
// Sign-in handler (issues the cookie-bound nonce and redirects to
// the hosted-UI with the matching client_state_nonce query param)
// -------------------------------------------------------------------------

describe("createAuthioSignInHandler", () => {
  it("mints a nonce, sets the cookie, and redirects to the hosted UI with the same value", async () => {
    const handlers = createAuthioSignInHandler();
    const res = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in"),
    );
    expect(res.status).toBe(307);
    const location = res.headers.get("location")!;
    const target = new URL(location);
    expect(target.origin).toBe("https://auth.authio.com");
    expect(target.searchParams.get("redirect_uri")).toBe(
      "https://app.test/api/auth/callback",
    );
    const urlNonce = target.searchParams.get("client_state_nonce");
    expect(urlNonce).toBeTruthy();
    expect(urlNonce!.length).toBeGreaterThan(20);
    const cookies = setCookieMap(res);
    // The cookie value must equal what we shipped in the URL — that's
    // the equality the callback handler checks.
    expect(cookies.authio_callback_state).toBe(urlNonce);
  });

  it("passes next in lobby ctx mint body when mint succeeds", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({ ctx: "signed.ctx.token" }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handlers = createAuthioSignInHandler({ projectId: "proj_test" });
    const res = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in?next=%2Fdash"),
    );
    const target = new URL(res.headers.get("location")!);
    expect(target.searchParams.get("ctx")).toBe("signed.ctx.token");
    const mintCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/v1/auth/lobby-context"),
    );
    expect(mintCall).toBeTruthy();
    const body = JSON.parse(mintCall![1]?.body as string) as {
      redirect_uri?: string;
      next?: string;
    };
    expect(body.redirect_uri).toBe("https://app.test/api/auth/callback");
    expect(body.next).toBe("/dash");
  });

  it("passes ?next= separately from redirect_uri for legacy lobby URLs", async () => {
    const handlers = createAuthioSignInHandler();
    const res = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in?next=%2Fdash"),
    );
    const target = new URL(res.headers.get("location")!);
    const ru = new URL(target.searchParams.get("redirect_uri")!);
    expect(ru.searchParams.get("next")).toBeNull();
    expect(target.searchParams.get("next")).toBe("/dash");
  });

  it("rejects off-origin ?next= (open-redirect prevention)", async () => {
    const handlers = createAuthioSignInHandler();
    const res = await handlers.GET(
      makeReq(
        "https://app.test/api/auth/sign-in?next=https%3A%2F%2Fevil%2Fpwn",
      ),
    );
    const target = new URL(res.headers.get("location")!);
    // safeNext("https://evil") → "/", so no `next` param.
    const ru = new URL(target.searchParams.get("redirect_uri")!);
    expect(ru.searchParams.get("next")).toBeNull();
    expect(target.searchParams.get("next")).toBeNull();
  });

  it("uses a custom hostedUiUrl + callbackPath", async () => {
    const handlers = createAuthioSignInHandler({
      hostedUiUrl: "https://auth.acme.com",
      callbackPath: "/auth/cb",
    });
    const res = await handlers.POST(
      makeReq("https://app.acme.com/api/auth/sign-in", { method: "POST" }),
    );
    const target = new URL(res.headers.get("location")!);
    expect(target.origin).toBe("https://auth.acme.com");
    expect(target.searchParams.get("redirect_uri")).toBe(
      "https://app.acme.com/auth/cb",
    );
  });

  it("each invocation mints a fresh nonce", async () => {
    const handlers = createAuthioSignInHandler();
    const a = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in"),
    );
    const b = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in"),
    );
    const nonceA = new URL(a.headers.get("location")!).searchParams.get(
      "client_state_nonce",
    );
    const nonceB = new URL(b.headers.get("location")!).searchParams.get(
      "client_state_nonce",
    );
    expect(nonceA).toBeTruthy();
    expect(nonceB).toBeTruthy();
    expect(nonceA).not.toBe(nonceB);
  });

  it("forwards project_id when AUTHIO_PROJECT_ID is set", async () => {
    const prev = process.env.AUTHIO_PROJECT_ID;
    process.env.AUTHIO_PROJECT_ID = "proj_jb";
    try {
      const handlers = createAuthioSignInHandler();
      const res = await handlers.GET(
        makeReq("https://app.test/api/auth/sign-in"),
      );
      const target = new URL(res.headers.get("location")!);
      expect(target.searchParams.get("project_id")).toBe("proj_jb");
    } finally {
      if (prev === undefined) delete process.env.AUTHIO_PROJECT_ID;
      else process.env.AUTHIO_PROJECT_ID = prev;
    }
  });

  it("forwards projectId opt override for tests", async () => {
    const handlers = createAuthioSignInHandler({ projectId: "proj_opt" });
    const res = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in"),
    );
    const target = new URL(res.headers.get("location")!);
    expect(target.searchParams.get("project_id")).toBe("proj_opt");
  });

  it("starts OAuth authorize with PKCE when oauthAuthorize is set", async () => {
    const handlers = createAuthioSignInHandler({
      apiUrl: "https://auth.test",
      oauthAuthorize: { clientId: "client_dcr_1", scope: "openid profile" },
    });
    const res = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-in"),
    );
    expect(res.status).toBe(307);
    const target = new URL(res.headers.get("location")!);
    expect(target.origin + target.pathname).toBe(
      "https://auth.test/v1/auth/authorize",
    );
    expect(target.searchParams.get("client_id")).toBe("client_dcr_1");
    expect(target.searchParams.get("response_type")).toBe("code");
    expect(target.searchParams.get("redirect_uri")).toBe(
      "https://app.test/api/auth/callback",
    );
    expect(target.searchParams.get("code_challenge_method")).toBe("S256");
    expect(target.searchParams.get("code_challenge")).toBeTruthy();
    expect(target.searchParams.get("scope")).toBe("openid profile");
    const state = target.searchParams.get("state");
    expect(state).toBeTruthy();
    const cookies = setCookieMap(res);
    expect(cookies.authio_callback_state).toBe(state);
    expect(cookies.authio_pkce_verifier).toBeTruthy();
    expect(cookies.authio_oauth_client_id).toBe("client_dcr_1");
  });
});

// -------------------------------------------------------------------------
// Callback handler — OAuth ?code= exchange
// -------------------------------------------------------------------------

describe("createAuthioCallbackHandler — acceptOAuthCode", () => {
  it("exchanges ?code= against /v1/auth/token with PKCE and sets cookies on success", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("{}", { status: 400 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "at-from-code",
            refresh_token: "rt-from-code",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler({
      apiUrl: "https://auth.test",
      acceptOAuthCode: true,
      apiHeaders: { "X-Authio-Project": "proj_x" },
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?code=oauth-code-1", {
        cookies: {
          authio_pkce_verifier: "pkce-verifier-abc",
          authio_oauth_client_id: "client_dcr_1",
        },
      }),
    );
    expect(res.headers.get("location")).toBe("https://app.test/");
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("at-from-code");
    expect(cookies.authio_refresh).toBe("rt-from-code");
    expect(cookies.authio_pkce_verifier).toBe("");
    expect(cookies.authio_oauth_client_id).toBe("");
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://auth.test/v1/auth/token",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-Authio-Project": "proj_x",
        }),
        body: JSON.stringify({
          grant_type: "authorization_code",
          code: "oauth-code-1",
          client_id: "client_dcr_1",
          redirect_uri: "https://app.test/api/auth/callback",
          code_verifier: "pkce-verifier-abc",
        }),
      }),
    );
  });

  it("bounces with oauth_failed when PKCE verifier cookie is missing", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 400 }));
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler({
      acceptOAuthCode: true,
      oauthClientId: "client_dcr_1",
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?code=oauth-code-1"),
    );
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe("oauth_failed");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("surfaces a failed handoff when OAuth code exchange is off", async () => {
    const fetchMock = vi.fn(async () => new Response("nope", { status: 400 }));
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler();
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?code=oauth-code-1"),
    );
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
      "handoff_exchange_failed",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("bounces with oauth_failed when auth-core returns non-2xx on token exchange", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 400 })),
    );
    const handler = createAuthioCallbackHandler({
      acceptOAuthCode: true,
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?code=bad-code", {
        cookies: {
          authio_pkce_verifier: "verifier",
          authio_oauth_client_id: "client_1",
        },
      }),
    );
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe("oauth_failed");
  });

  it("magic-link ?access_token= path takes precedence over ?code=", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 500 }));
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler({ acceptOAuthCode: true });
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=at&code=should-be-ignored",
      ),
    );
    expect(res.headers.get("location")).toBe("https://app.test/");
    expect(fetchMock).not.toHaveBeenCalled();
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("at");
  });
});

// -------------------------------------------------------------------------
// Callback handler — JWT verification (defense in depth on top of the nonce check)
// -------------------------------------------------------------------------

describe("createAuthioCallbackHandler — verifyAccessToken", () => {
  it("bounces with invalid_token when verification fails", async () => {
    // Stub fetch so the JWKS fetch returns a known-non-matching key set
    // — any JWT verification against this will fail.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ keys: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    const handler = createAuthioCallbackHandler({
      apiUrl: "https://auth.test",
      verifyAccessToken: true,
    });
    const res = await handler(
      makeReq(
        "https://app.test/api/auth/callback?access_token=not-a-real-jwt",
      ),
    );
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe("invalid_token");
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBeUndefined();
  });

  it("does not call the JWKS endpoint when verifyAccessToken is off (default)", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler();
    await handler(
      makeReq("https://app.test/api/auth/callback?access_token=at"),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// -------------------------------------------------------------------------
// Refresh handler — apiHeaders forwarding
// -------------------------------------------------------------------------

describe("createAuthioRefreshHandler — apiHeaders", () => {
  it("forwards apiHeaders on the auth-core fetch", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({ access_token: "new-at", refresh_token: "new-rt" }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioRefreshHandler({
      apiUrl: "https://auth.test",
      apiHeaders: { "X-Authio-Project": "proj_xyz" },
    });
    await handler(
      makeReq("https://app.test/api/auth/refresh", {
        cookies: { authio_refresh: "rt" },
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.test/v1/auth/refresh",
      expect.objectContaining({
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-Authio-Project": "proj_xyz",
        }),
      }),
    );
  });
});

// -------------------------------------------------------------------------
// Sign-out handler — signOutPaths fallback chain + apiHeaders
// -------------------------------------------------------------------------

describe("createAuthioSignOutHandler — signOutPaths", () => {
  it("walks the fallback chain when the first path returns 404", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const handlers = createAuthioSignOutHandler({
      apiUrl: "https://auth.test",
      signOutPaths: ["/v1/auth/sign-out", "/v1/sessions/revoke"],
    });
    await handlers.POST(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "the-token" },
        method: "POST",
      }),
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://auth.test/v1/auth/sign-out",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://auth.test/v1/sessions/revoke",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("treats 401 (already revoked) as success and stops at the first path", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);
    const handlers = createAuthioSignOutHandler({
      signOutPaths: ["/v1/auth/sign-out", "/v1/sessions/revoke"],
    });
    await handlers.POST(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "stale-token" },
        method: "POST",
      }),
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("forwards apiHeaders on the revoke fetch", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const handlers = createAuthioSignOutHandler({
      apiHeaders: { "X-Authio-Project": "proj_h" },
    });
    await handlers.GET(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "at" },
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({
          "X-Authio-Project": "proj_h",
          Authorization: "Bearer at",
        }),
      }),
    );
  });
});

// -------------------------------------------------------------------------
// Refresh handler
// -------------------------------------------------------------------------

describe("createAuthioRefreshHandler", () => {
  it("redirects to /sign-in with a session_expired flash and clears cookies when refresh cookie missing", async () => {
    const handler = createAuthioRefreshHandler();
    const res = await handler(
      makeReq("https://app.test/api/auth/refresh?next=%2Fdash"),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toContain("/sign-in");
    expect(res.headers.get("location")).not.toContain("error=");
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe("session_expired");
    expect(res.headers.get("location")).toContain("next=%2Fdash");
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("");
    expect(cookies.authio_refresh).toBe("");
  });

  it("exchanges the refresh cookie, sets new cookies, and redirects to next", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({ access_token: "new-at", refresh_token: "new-rt" }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const handler = createAuthioRefreshHandler({
      apiUrl: "https://auth.test",
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/refresh?next=%2Fdash", {
        cookies: { authio_refresh: "old-rt" },
      }),
    );
    expect(res.headers.get("location")).toBe("https://app.test/dash");
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("new-at");
    expect(cookies.authio_refresh).toBe("new-rt");
    expect(fetch).toHaveBeenCalledWith(
      "https://auth.test/v1/auth/refresh",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("surfaces auth-core error codes and clears cookies on 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ code: "policy_violation_session_idle" }), {
          status: 401,
        }),
      ),
    );
    const handler = createAuthioRefreshHandler();
    const res = await handler(
      makeReq("https://app.test/api/auth/refresh", {
        cookies: { authio_refresh: "old" },
      }),
    );
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
      "policy_violation_session_idle",
    );
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("");
    expect(cookies.authio_refresh).toBe("");
  });

  it("leaves cookies intact on a network error (transient)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("network down");
      }),
    );
    const handler = createAuthioRefreshHandler();
    const res = await handler(
      makeReq("https://app.test/api/auth/refresh", {
        cookies: { authio_refresh: "still-valid" },
      }),
    );
    expect(setCookieMap(res)[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
      "refresh_network_error",
    );
    const cookies = setCookieMap(res);
    // No Set-Cookie clearing the refresh token — we'd lose access
    // to a perfectly good refresh just because of a 5-second blip.
    expect(cookies.authio_refresh).toBeUndefined();
  });

  it("treats a 200 OK with no access_token as transient (does not clear)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })),
    );
    const handler = createAuthioRefreshHandler();
    const res = await handler(
      makeReq("https://app.test/api/auth/refresh", {
        cookies: { authio_refresh: "x" },
      }),
    );
    const cookies = setCookieMap(res);
    expect(cookies[AUTHIO_SIGNIN_FLASH_COOKIE]).toBe(
      "malformed_refresh_envelope",
    );
    expect(cookies.authio_refresh).toBeUndefined();
  });
});

// -------------------------------------------------------------------------
// Sign-out handler
// -------------------------------------------------------------------------

describe("createAuthioSignOutHandler", () => {
  it("clears both cookies and redirects to signedOutRedirect (303)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    const handlers = createAuthioSignOutHandler();
    const res = await handlers.POST(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "at" },
        method: "POST",
      }),
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("https://app.test/sign-in");
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("");
    expect(cookies.authio_refresh).toBe("");
  });

  it("calls auth-core /v1/auth/sign-out with the access token when present", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const handlers = createAuthioSignOutHandler({
      apiUrl: "https://auth.test",
    });
    await handlers.GET(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "the-access-token" },
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.test/v1/auth/sign-out",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer the-access-token",
        }),
      }),
    );
  });

  it("still clears cookies when auth-core revocation fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("down");
    }));
    const handlers = createAuthioSignOutHandler();
    const res = await handlers.POST(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "at" },
        method: "POST",
      }),
    );
    const cookies = setCookieMap(res);
    expect(cookies.authio_session).toBe("");
    expect(cookies.authio_refresh).toBe("");
  });
});

// -------------------------------------------------------------------------
// readAuthioSignInError
// -------------------------------------------------------------------------

describe("readAuthioSignInError", () => {
  it("prefers the flash cookie", () => {
    expect(
      readAuthioSignInError({
        cookieValue: "missing_token",
        searchParams: { error: "stale_query_code" },
      }),
    ).toBe("missing_token");
  });

  it("falls back to legacy ?error= then ?err= params", () => {
    expect(
      readAuthioSignInError({ searchParams: { error: "oauth_failed" } }),
    ).toBe("oauth_failed");
    expect(
      readAuthioSignInError({ searchParams: { err: "missing_token" } }),
    ).toBe("missing_token");
    expect(
      readAuthioSignInError({
        searchParams: new URLSearchParams("err=invalid_token"),
      }),
    ).toBe("invalid_token");
  });

  it("returns null when nothing is present", () => {
    expect(readAuthioSignInError({})).toBeNull();
    expect(readAuthioSignInError({ searchParams: {} })).toBeNull();
  });

  it("rejects codes that don't look like machine codes", () => {
    expect(
      readAuthioSignInError({ cookieValue: "<img src=x onerror=alert(1)>" }),
    ).toBeNull();
    expect(
      readAuthioSignInError({ searchParams: { error: "https://evil.example" } }),
    ).toBeNull();
  });
});
