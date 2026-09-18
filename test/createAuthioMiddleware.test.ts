import { beforeEach, describe, it, expect, vi } from "vitest";
import { NextRequest } from "next/server";

// The middleware now verifies the access cookie against the JWKS
// (security audit 2026-09-18, SDK-5). Mock jose so the suite never
// touches the network and each test can choose the verification outcome.
const { jwtVerify, createRemoteJWKSet } = vi.hoisted(() => ({
  jwtVerify: vi.fn(),
  createRemoteJWKSet: vi.fn(() => "jwks-stub"),
}));

vi.mock("jose", async () => {
  const actual = await vi.importActual<typeof import("jose")>("jose");
  return { ...actual, jwtVerify, createRemoteJWKSet };
});

import { createAuthioMiddleware } from "../src/createAuthioMiddleware";

/** A token that verifies cleanly and belongs to `proj_test`. */
function verifies(payload: Record<string, unknown> = {}) {
  jwtVerify.mockResolvedValue({
    payload: { sub: "user_1", project_id: "proj_test", ...payload },
    protectedHeader: { alg: "EdDSA" },
  });
}

/** A token jose refuses. `code` drives expired-vs-structural handling. */
function fails(code?: string) {
  jwtVerify.mockRejectedValue(Object.assign(new Error("nope"), { code }));
}

beforeEach(() => {
  jwtVerify.mockReset();
  verifies();
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

describe("createAuthioMiddleware", () => {
  it("returns NextResponse.next() for the default public paths", async () => {
    const mw = createAuthioMiddleware();
    for (const path of ["/sign-in", "/api/auth/refresh", "/_next/abc", "/favicon.ico"]) {
      const res = await mw(makeReq(`https://app.test${path}`));
      expect(res.status).toBe(200);
      expect(res.headers.get("location")).toBeNull();
    }
  });

  it("passes through when the session cookie VERIFIES", async () => {
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "jwt-here" },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("redirects to /api/auth/refresh when only the refresh cookie is present (GET)", async () => {
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects?team=a", {
        cookies: { authio_refresh: "rt-here" },
      }),
    );
    expect(res.status).toBe(307);
    const loc = res.headers.get("location")!;
    expect(loc).toContain("/api/auth/refresh");
    expect(loc).toContain("next=%2Fprojects%3Fteam%3Da");
  });

  it("redirects to /sign-in when neither cookie is present", async () => {
    const mw = createAuthioMiddleware();
    const res = await mw(makeReq("https://app.test/projects"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/sign-in");
    expect(res.headers.get("location")!).toContain("next=%2Fprojects");
  });

  it("bounces a refresh-cookie POST to /sign-in (silent renewal is GET-only)", async () => {
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_refresh: "rt-here" },
        method: "POST",
      }),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/sign-in");
  });

  it("respects custom cookie names + signInPath + refreshPath", async () => {
    const mw = createAuthioMiddleware({
      sessionCookieName: "myapp_session",
      refreshCookieName: "myapp_refresh",
      signInPath: "/login",
      refreshPath: "/auth/renew",
    });
    const noSession = await mw(makeReq("https://app.test/x"));
    expect(noSession.headers.get("location")!).toContain("/login");

    const haveRefresh = await mw(
      makeReq("https://app.test/x", {
        cookies: { myapp_refresh: "rt" },
      }),
    );
    expect(haveRefresh.headers.get("location")!).toContain("/auth/renew");
  });

  it("omits next= for root path requests", async () => {
    const mw = createAuthioMiddleware();
    const res = await mw(makeReq("https://app.test/"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).not.toContain("next=");
  });

  it("treats publicPaths with startsWith semantics", async () => {
    const mw = createAuthioMiddleware({
      publicPaths: ["/marketing"],
    });
    const res = await mw(makeReq("https://app.test/marketing/pricing"));
    expect(res.status).toBe(200);
  });

  it("does NOT let a publicPaths entry of \"/\" disable gating for every route", async () => {
    // Regression: startsWith("/") matches every pathname, so a naive
    // prefix match on "/" would make the whole middleware a no-op. "/"
    // must be exact-match only.
    const mw = createAuthioMiddleware({
      publicPaths: ["/", "/sign-in"],
    });

    // The landing page itself stays public.
    const root = await mw(makeReq("https://app.test/"));
    expect(root.status).toBe(200);
    expect(root.headers.get("location")).toBeNull();

    // But a protected route with no cookies is still gated to /sign-in.
    const gated = await mw(makeReq("https://app.test/dashboard"));
    expect(gated.status).toBe(307);
    expect(gated.headers.get("location")!).toContain("/sign-in");
  });
});

// -------------------------------------------------------------------------
// proactiveRefreshThreshold — when the JWT is close to expiring, route
// the navigation through /api/auth/refresh now (saving one redirect on
// the boundary) instead of waiting for reactive refresh.
//
// Proactive refresh reads `exp`/`iat` off the UNVERIFIED body purely for
// lifetime math; the security decision is the jwtVerify call that has
// already passed by the time this runs.
// -------------------------------------------------------------------------

function makeJwt(payload: { exp: number; iat: number }): string {
  // Edge-runtime safe base64url. Tests run in Node so Buffer is available,
  // but we prefer the same shape the middleware uses to dogfood our own
  // contract.
  const enc = (obj: object) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return [enc({ alg: "EdDSA", typ: "JWT" }), enc(payload), "sig"].join(".");
}

describe("createAuthioMiddleware — proactiveRefreshThreshold", () => {
  it("redirects to refresh when JWT is past the threshold and refresh cookie present", async () => {
    const now = Math.floor(Date.now() / 1000);
    // 24h JWT; 90% used → 10% remaining; threshold 0.25 → trigger.
    const iat = now - 24 * 3600 * 0.9;
    const exp = now + 24 * 3600 * 0.1;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/api/auth/refresh");
    expect(res.headers.get("location")!).toContain("next=%2Fprojects");
  });

  it("passes through when JWT is fresh (more than threshold remaining)", async () => {
    const now = Math.floor(Date.now() / 1000);
    // 24h JWT; 10% used → 90% remaining; threshold 0.25 → no trigger.
    const iat = now - 24 * 3600 * 0.1;
    const exp = now + 24 * 3600 * 0.9;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("no-op when proactiveRefreshThreshold is unset (default behaviour)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 24 * 3600 * 0.99;
    const exp = now + 24 * 3600 * 0.01;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op when refresh cookie is missing (we have nothing to spend)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 24 * 3600 * 0.99;
    const exp = now + 24 * 3600 * 0.01;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op for unsafe methods (POST/PUT/etc — would lose body across the redirect)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 24 * 3600 * 0.99;
    const exp = now + 24 * 3600 * 0.01;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = await mw(
      makeReq("https://app.test/api/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
        method: "POST",
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op when JWT lacks iat (can't compute lifetime)", async () => {
    const now = Math.floor(Date.now() / 1000);
    // Fabricate a JWT with only `exp` and no `iat`.
    const enc = (obj: object) =>
      btoa(JSON.stringify(obj))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const session = [
      enc({ alg: "EdDSA" }),
      enc({ exp: now + 60 }),
      "sig",
    ].join(".");
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op when JWT is structurally malformed", async () => {
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "not.a.jwt", authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
  });
});


// -------------------------------------------------------------------------
// Security audit 2026-09-18 (SDK-5). This middleware used to gate on
// cookie PRESENCE alone, so `document.cookie = "authio_session=x"` walked
// through it. These tests pin the verification that replaced that.
// -------------------------------------------------------------------------

describe("createAuthioMiddleware — access-cookie verification", () => {
  it("refuses a forged session cookie instead of passing it through", async () => {
    fails();
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "totally-made-up" },
      }),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/sign-in");
  });

  it("does NOT bounce a forged cookie through the refresh handler (no ping-pong)", async () => {
    // A structural failure cannot be fixed by minting a new token, so
    // sending it to /api/auth/refresh would loop between the two routes.
    fails();
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "forged", authio_refresh: "rt" },
      }),
    );
    expect(res.headers.get("location")!).toContain("/sign-in");
    expect(res.headers.get("location")!).not.toContain("/api/auth/refresh");
  });

  it("routes an EXPIRED access cookie through refresh rather than serving the page", async () => {
    // Regression: the presence-only gate waved expired cookies through,
    // so the user got a page whose auth() returned null.
    fails("ERR_JWT_EXPIRED");
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "expired", authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/api/auth/refresh");
  });

  it("refuses a valid token minted in a DIFFERENT project", async () => {
    verifies({ project_id: "proj_someone_else" });
    const mw = createAuthioMiddleware({ projectId: "proj_test" });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "cross-tenant" },
      }),
    );
    expect(res.headers.get("location")!).toContain("/sign-in");
  });

  it("accepts a valid token for the configured project", async () => {
    verifies({ project_id: "proj_test" });
    const mw = createAuthioMiddleware({ projectId: "proj_test" });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "ours" },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("defaults projectId from AUTHIO_PROJECT_ID", async () => {
    const prev = process.env.AUTHIO_PROJECT_ID;
    process.env.AUTHIO_PROJECT_ID = "proj_from_env";
    try {
      verifies({ project_id: "proj_someone_else" });
      const mw = createAuthioMiddleware();
      const res = await mw(
        makeReq("https://app.test/projects", {
          cookies: { authio_session: "cross-tenant" },
        }),
      );
      expect(res.headers.get("location")!).toContain("/sign-in");
    } finally {
      if (prev === undefined) delete process.env.AUTHIO_PROJECT_ID;
      else process.env.AUTHIO_PROJECT_ID = prev;
    }
  });

  it("refuses a token with no sub claim", async () => {
    verifies({ sub: undefined });
    const mw = createAuthioMiddleware();
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "subless" },
      }),
    );
    expect(res.headers.get("location")!).toContain("/sign-in");
  });

  it("verify:false restores presence-only gating and never calls jwtVerify", async () => {
    const mw = createAuthioMiddleware({ verify: false });
    const res = await mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "unchecked" },
      }),
    );
    expect(res.status).toBe(200);
    expect(jwtVerify).not.toHaveBeenCalled();
  });
});
