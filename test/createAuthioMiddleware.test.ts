import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import { createAuthioMiddleware } from "../src/createAuthioMiddleware";

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
  it("returns NextResponse.next() for the default public paths", () => {
    const mw = createAuthioMiddleware();
    for (const path of ["/sign-in", "/api/auth/refresh", "/_next/abc", "/favicon.ico"]) {
      const res = mw(makeReq(`https://app.test${path}`));
      expect(res.status).toBe(200);
      expect(res.headers.get("location")).toBeNull();
    }
  });

  it("passes through when a session cookie is present", () => {
    const mw = createAuthioMiddleware();
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "jwt-here" },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("redirects to /api/auth/refresh when only the refresh cookie is present (GET)", () => {
    const mw = createAuthioMiddleware();
    const res = mw(
      makeReq("https://app.test/projects?team=a", {
        cookies: { authio_refresh: "rt-here" },
      }),
    );
    expect(res.status).toBe(307);
    const loc = res.headers.get("location")!;
    expect(loc).toContain("/api/auth/refresh");
    expect(loc).toContain("next=%2Fprojects%3Fteam%3Da");
  });

  it("redirects to /sign-in when neither cookie is present", () => {
    const mw = createAuthioMiddleware();
    const res = mw(makeReq("https://app.test/projects"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/sign-in");
    expect(res.headers.get("location")!).toContain("next=%2Fprojects");
  });

  it("bounces a refresh-cookie POST to /sign-in (silent renewal is GET-only)", () => {
    const mw = createAuthioMiddleware();
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_refresh: "rt-here" },
        method: "POST",
      }),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/sign-in");
  });

  it("respects custom cookie names + signInPath + refreshPath", () => {
    const mw = createAuthioMiddleware({
      sessionCookieName: "myapp_session",
      refreshCookieName: "myapp_refresh",
      signInPath: "/login",
      refreshPath: "/auth/renew",
    });
    const noSession = mw(makeReq("https://app.test/x"));
    expect(noSession.headers.get("location")!).toContain("/login");

    const haveRefresh = mw(
      makeReq("https://app.test/x", {
        cookies: { myapp_refresh: "rt" },
      }),
    );
    expect(haveRefresh.headers.get("location")!).toContain("/auth/renew");
  });

  it("omits next= for root path requests", () => {
    const mw = createAuthioMiddleware();
    const res = mw(makeReq("https://app.test/"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).not.toContain("next=");
  });

  it("treats publicPaths with startsWith semantics", () => {
    const mw = createAuthioMiddleware({
      publicPaths: ["/marketing"],
    });
    const res = mw(makeReq("https://app.test/marketing/pricing"));
    expect(res.status).toBe(200);
  });
});

// -------------------------------------------------------------------------
// proactiveRefreshThreshold — when the JWT is close to expiring, route
// the navigation through /api/auth/refresh now (saving one redirect on
// the boundary) instead of waiting for reactive refresh.
//
// The middleware does NOT verify the JWT — it decodes the unauth body to
// read `exp`/`iat`. This is for UX, not security; verification still
// happens in the RSC `auth()` helper and downstream APIs.
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
  it("redirects to refresh when JWT is past the threshold and refresh cookie present", () => {
    const now = Math.floor(Date.now() / 1000);
    // 24h JWT; 90% used → 10% remaining; threshold 0.25 → trigger.
    const iat = now - 24 * 3600 * 0.9;
    const exp = now + 24 * 3600 * 0.1;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(307);
    expect(res.headers.get("location")!).toContain("/api/auth/refresh");
    expect(res.headers.get("location")!).toContain("next=%2Fprojects");
  });

  it("passes through when JWT is fresh (more than threshold remaining)", () => {
    const now = Math.floor(Date.now() / 1000);
    // 24h JWT; 10% used → 90% remaining; threshold 0.25 → no trigger.
    const iat = now - 24 * 3600 * 0.1;
    const exp = now + 24 * 3600 * 0.9;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("no-op when proactiveRefreshThreshold is unset (default behaviour)", () => {
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 24 * 3600 * 0.99;
    const exp = now + 24 * 3600 * 0.01;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware();
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op when refresh cookie is missing (we have nothing to spend)", () => {
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 24 * 3600 * 0.99;
    const exp = now + 24 * 3600 * 0.01;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op for unsafe methods (POST/PUT/etc — would lose body across the redirect)", () => {
    const now = Math.floor(Date.now() / 1000);
    const iat = now - 24 * 3600 * 0.99;
    const exp = now + 24 * 3600 * 0.01;
    const session = makeJwt({ iat, exp });
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = mw(
      makeReq("https://app.test/api/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
        method: "POST",
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op when JWT lacks iat (can't compute lifetime)", () => {
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
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: session, authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("no-op when JWT is structurally malformed", () => {
    const mw = createAuthioMiddleware({ proactiveRefreshThreshold: 0.25 });
    const res = mw(
      makeReq("https://app.test/projects", {
        cookies: { authio_session: "not.a.jwt", authio_refresh: "rt" },
      }),
    );
    expect(res.status).toBe(200);
  });
});
