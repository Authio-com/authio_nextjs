import { afterEach, describe, expect, it, vi } from "vitest";
import { publicOrigin } from "../src/handlers";

const req = (headers: Record<string, string>, url = "https://app.example.com/api/auth/callback") =>
  new Request(url, { headers });

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("publicOrigin with allowedHosts", () => {
  const opts = { allowedHosts: ["app.example.com", "www.example.com"] };

  it("honours a listed forwarded host", () => {
    expect(publicOrigin(req({ "x-forwarded-host": "www.example.com", "x-forwarded-proto": "https" }), opts))
      .toBe("https://www.example.com");
  });

  it("ignores a forged forwarded host (open redirect)", () => {
    for (const bad of ["evil.example", "app.example.com.evil.example", "app.example.com@evil.example", "evil.example, app.example.com"]) {
      expect(publicOrigin(req({ "x-forwarded-host": bad }), opts), bad).toBe("https://app.example.com");
    }
  });

  it("falls back to the first allowed host when the request host is foreign", () => {
    expect(publicOrigin(req({}, "http://10.0.0.5:3000/api/auth/callback"), opts)).toBe("https://app.example.com");
  });

  it("reads AUTHIO_ALLOWED_HOSTS when the option is unset", () => {
    vi.stubEnv("AUTHIO_ALLOWED_HOSTS", "app.example.com");
    expect(publicOrigin(req({ "x-forwarded-host": "evil.example" }))).toBe("https://app.example.com");
  });
});

describe("publicOrigin without allowedHosts (pre-0.9 compatible)", () => {
  it("still honours a well-formed forwarded host, with a one-time warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(publicOrigin(req({ "x-forwarded-host": "proxy.example.com" }))).toBe("https://proxy.example.com");
    expect(warn.mock.calls.length).toBeLessThanOrEqual(1);
  });

  it("rejects malformed hosts and non-http(s) protos", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(publicOrigin(req({ "x-forwarded-host": "evil.example/x" }))).toBe("https://app.example.com");
    expect(publicOrigin(req({ "x-forwarded-host": "app.example.com", "x-forwarded-proto": "javascript" })))
      .toBe("https://app.example.com");
  });
});
