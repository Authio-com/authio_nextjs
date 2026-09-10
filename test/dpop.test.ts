import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { jwtVerify, EmbeddedJWK, calculateJwkThumbprint, type JWK } from "jose";
import {
  generateDPoPKey,
  createDPoPProof,
  sealDPoPKey,
  unsealDPoPKey,
  publicJWK,
} from "../src/dpop";
import {
  createAuthioCallbackHandler,
  createAuthioRefreshHandler,
  createAuthioSignOutHandler,
} from "../src/handlers";

const SEAL_SECRET = "test-seal-secret-32-bytes-or-so!";

function makeReq(
  url: string,
  init: {
    cookies?: Record<string, string>;
    method?: string;
  } = {},
): NextRequest {
  const cookieHeader = Object.entries(init.cookies ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  const headers = new Headers();
  if (cookieHeader) headers.set("cookie", cookieHeader);
  return new NextRequest(new URL(url), {
    method: init.method ?? "GET",
    headers,
  });
}

function setCookieMap(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getSetCookie = (res.headers as any).getSetCookie?.bind(res.headers);
  const cookies: string[] = getSetCookie
    ? getSetCookie()
    : (res.headers.get("set-cookie")?.split(/,(?=[^ ]+=)/) ?? []);
  for (const c of cookies) {
    const [pair] = c.split(";");
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    out[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  return out;
}

/** Verify a proof the way auth-core does: signature by the embedded key. */
async function verifyProof(proof: string) {
  const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
    typ: "dpop+jwt",
  });
  return { payload, protectedHeader };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("dpop primitives", () => {
  it("generates a P-256 private JWK", async () => {
    const key = await generateDPoPKey();
    expect(key.kty).toBe("EC");
    expect(key.crv).toBe("P-256");
    expect(key.d).toBeTruthy();
    expect(key.x).toBeTruthy();
    expect(key.y).toBeTruthy();
  });

  it("mints a verifiable RFC 9449 proof with htm/htu/iat/jti", async () => {
    const key = await generateDPoPKey();
    const proof = await createDPoPProof(
      key,
      "post",
      "https://auth.test/v1/auth/refresh?next=%2F",
    );
    const { payload, protectedHeader } = await verifyProof(proof);
    expect(protectedHeader.alg).toBe("ES256");
    expect(protectedHeader.typ).toBe("dpop+jwt");
    // Public JWK only — the private scalar must never appear in a proof.
    expect((protectedHeader.jwk as JWK).d).toBeUndefined();
    expect(payload.htm).toBe("POST");
    // htu strips the query per RFC 9449 §4.3.
    expect(payload.htu).toBe("https://auth.test/v1/auth/refresh");
    expect(typeof payload.jti).toBe("string");
    expect(typeof payload.iat).toBe("number");
  });

  it("seals and unseals the private key", async () => {
    const key = await generateDPoPKey();
    const sealed = await sealDPoPKey(key, SEAL_SECRET);
    // Compact JWE, not plaintext: the private scalar must not be
    // recoverable from the cookie value.
    expect(sealed).not.toContain(key.d);
    const back = await unsealDPoPKey(sealed, SEAL_SECRET);
    expect(back).toEqual(key);
  });

  it("returns null on wrong secret or garbage", async () => {
    const key = await generateDPoPKey();
    const sealed = await sealDPoPKey(key, SEAL_SECRET);
    expect(await unsealDPoPKey(sealed, "some-other-secret")).toBeNull();
    expect(await unsealDPoPKey("not-a-jwe", SEAL_SECRET)).toBeNull();
  });
});

describe("createAuthioRefreshHandler — dpop", () => {
  it("throws at construction when dpop is on without a seal secret", () => {
    expect(() => createAuthioRefreshHandler({ dpop: true })).toThrow(
      /dpopSealSecret/,
    );
  });

  it("attaches a valid DPoP proof bound to the refresh URL", async () => {
    const key = await generateDPoPKey();
    const sealed = await sealDPoPKey(key, SEAL_SECRET);
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ access_token: "new-at", refresh_token: "new-rt" }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioRefreshHandler({
      apiUrl: "https://auth.test",
      dpop: true,
      dpopSealSecret: SEAL_SECRET,
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/refresh", {
        cookies: { authio_refresh: "rt", authio_dpop_key: sealed },
      }),
    );
    expect(res.status).toBe(307);
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const proof = (init.headers as Record<string, string>).DPoP;
    expect(proof).toBeTruthy();
    const { payload, protectedHeader } = await verifyProof(proof);
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://auth.test/v1/auth/refresh");
    // Proof is signed by the sealed cookie's key.
    expect(await calculateJwkThumbprint(protectedHeader.jwk as JWK)).toBe(
      await calculateJwkThumbprint(publicJWK(key) as JWK),
    );
    // Key cookie TTL slides with the rotated refresh cookie.
    const cookies = setCookieMap(res);
    expect(cookies.authio_dpop_key).toBe(sealed);
    expect(cookies.authio_refresh).toBe("new-rt");
  });

  it("degrades to an unbound refresh when the key cookie is missing", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ access_token: "new-at" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioRefreshHandler({
      apiUrl: "https://auth.test",
      dpop: true,
      dpopSealSecret: SEAL_SECRET,
    });
    await handler(
      makeReq("https://app.test/api/auth/refresh", {
        cookies: { authio_refresh: "rt" },
      }),
    );
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect(
      (init.headers as Record<string, string>).DPoP,
    ).toBeUndefined();
  });
});

describe("createAuthioCallbackHandler — dpop", () => {
  it("sends a proof on the handoff exchange and seals the key cookie", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ access_token: "at", refresh_token: "rt" }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler({
      apiUrl: "https://auth.test",
      dpop: true,
      dpopSealSecret: SEAL_SECRET,
      verifyAccessToken: false,
      dangerouslyAllowInsecureLegacyCallback: true,
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?code=handoff-code"),
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.test/v1/auth/session-handoff/exchange",
      expect.anything(),
    );
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const proof = (init.headers as Record<string, string>).DPoP;
    expect(proof).toBeTruthy();
    const { payload, protectedHeader } = await verifyProof(proof);
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://auth.test/v1/auth/session-handoff/exchange");

    // The sealed cookie holds the SAME key the proof was signed with.
    const cookies = setCookieMap(res);
    const unsealed = await unsealDPoPKey(cookies.authio_dpop_key!, SEAL_SECRET);
    expect(unsealed).not.toBeNull();
    expect(await calculateJwkThumbprint(protectedHeader.jwk as JWK)).toBe(
      await calculateJwkThumbprint(publicJWK(unsealed!) as JWK),
    );
    expect(cookies.authio_refresh).toBe("rt");
  });

  it("does not seal a key when dpop is off", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ access_token: "at", refresh_token: "rt" }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const handler = createAuthioCallbackHandler({
      apiUrl: "https://auth.test",
      verifyAccessToken: false,
      dangerouslyAllowInsecureLegacyCallback: true,
    });
    const res = await handler(
      makeReq("https://app.test/api/auth/callback?code=handoff-code"),
    );
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).DPoP).toBeUndefined();
    expect(setCookieMap(res).authio_dpop_key).toBeUndefined();
  });
});

describe("createAuthioSignOutHandler — dpop", () => {
  it("clears the key cookie on sign-out", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 204 })),
    );
    const handlers = createAuthioSignOutHandler({
      apiUrl: "https://auth.test",
      dpop: true,
      dpopSealSecret: SEAL_SECRET,
    });
    const res = await handlers.GET(
      makeReq("https://app.test/api/auth/sign-out", {
        cookies: { authio_session: "at", authio_dpop_key: "sealed" },
      }),
    );
    const cookies = setCookieMap(res);
    expect(cookies.authio_dpop_key).toBe("");
  });
});
