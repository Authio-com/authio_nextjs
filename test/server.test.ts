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

  // Security audit 2026-09-06/07 (SDK-1): auth-core mints every token —
  // customer, developer, platform, widget, m2m — from the same keys and
  // the same issuer/audience. Without a default issuer/audience, jose
  // skipped that check entirely; without projectId enforcement, a token
  // minted in a DIFFERENT Authio project verified successfully here.
  it("passes production's real issuer/audience to jose by default", async () => {
    jwtVerify.mockResolvedValue({ payload: { sub: "user_1" } });
    await verifyToken("fake.jwt.token", { apiUrl: "https://api.example.com" });
    expect(jwtVerify.mock.calls[0]![2]).toMatchObject({
      issuer: "https://identity.authio.com",
      audience: "authio",
    });
  });

  it("honours explicit issuer/audience overrides", async () => {
    jwtVerify.mockResolvedValue({ payload: { sub: "user_1" } });
    await verifyToken("fake.jwt.token", {
      apiUrl: "https://api.example.com",
      issuer: "https://issuer.example.test",
      audience: "custom-aud",
    });
    expect(jwtVerify.mock.calls[0]![2]).toMatchObject({
      issuer: "https://issuer.example.test",
      audience: "custom-aud",
    });
  });

  it("refuses a token minted in a different project when projectId is configured", async () => {
    jwtVerify.mockResolvedValue({
      payload: { sub: "user_1", project_id: "proj_attacker_owned" },
    });
    const result = await verifyToken("fake.jwt.token", {
      apiUrl: "https://api.example.com",
      projectId: "proj_mine",
    });
    expect(result.userId).toBeNull();
  });

  it("refuses a token with no project_id claim at all when projectId is configured", async () => {
    // No project_id claim is exactly the shape of a widget/platform/m2m
    // token, or a legacy customer token minted before this claim existed.
    jwtVerify.mockResolvedValue({ payload: { sub: "user_1" } });
    const result = await verifyToken("fake.jwt.token", {
      apiUrl: "https://api.example.com",
      projectId: "proj_mine",
    });
    expect(result.userId).toBeNull();
  });

  it("accepts a token whose project_id matches the configured projectId", async () => {
    jwtVerify.mockResolvedValue({
      payload: { sub: "user_1", project_id: "proj_mine" },
    });
    const result = await verifyToken("fake.jwt.token", {
      apiUrl: "https://api.example.com",
      projectId: "proj_mine",
    });
    expect(result.userId).toBe("user_1");
  });

  it("does not enforce project_id when projectId is left unconfigured (back-compat)", async () => {
    jwtVerify.mockResolvedValue({
      payload: { sub: "user_1", project_id: "proj_whatever" },
    });
    const result = await verifyToken("fake.jwt.token", {
      apiUrl: "https://api.example.com",
    });
    expect(result.userId).toBe("user_1");
  });
});
