import { beforeEach, describe, expect, it, vi } from "vitest";

const { jwtVerify } = vi.hoisted(() => ({
  jwtVerify: vi.fn(),
}));

vi.mock("jose", async () => {
  const actual = await vi.importActual<typeof import("jose")>("jose");
  return {
    ...actual,
    jwtVerify,
  };
});

import { verifyToken } from "../src/server";

describe("verifyToken", () => {
  beforeEach(() => {
    jwtVerify.mockReset();
  });

  it("returns empty claims for blank token", async () => {
    const result = await verifyToken("", { apiUrl: "https://api.example.com" });
    expect(result).toEqual({
      userId: null,
      orgId: null,
      role: null,
      sessionId: null,
      tokenKind: null,
      staffEmail: null,
    });
    expect(jwtVerify).not.toHaveBeenCalled();
  });

  it("extracts session and platform claims from a verified JWT payload", async () => {
    jwtVerify.mockResolvedValue({
      payload: {
        sub: "user_123",
        act_org: "org_abc",
        act_role: "admin",
        sid: "sess_xyz",
        kind: "platform",
        staff_email: "ops@authio.com",
      },
      protectedHeader: { alg: "EdDSA" },
    });

    const result = await verifyToken("fake.jwt.token", {
      apiUrl: "https://api.example.com",
    });
    expect(result).toEqual({
      userId: "user_123",
      orgId: "org_abc",
      role: "admin",
      sessionId: "sess_xyz",
      tokenKind: "platform",
      staffEmail: "ops@authio.com",
    });
    expect(jwtVerify).toHaveBeenCalledOnce();
  });
});
