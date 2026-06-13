import { NextResponse, type NextRequest } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";

export interface AuthMiddlewareOptions {
  /** Auth-core base URL (e.g. https://api.authio.com). */
  apiUrl?: string;
  /** Expected JWT issuer (matches AUTHIO_JWT_ISSUER on the server). */
  issuer?: string;
  /** Expected JWT audience. */
  audience?: string;
  /** Routes that don't require a session (string equality or regex). */
  publicRoutes?: (string | RegExp)[];
  signInUrl?: string;
}

const DEFAULT_API_URL = "https://api.authio.com";

/**
 * Next.js Edge middleware that verifies the Authio session JWT against the
 * remote JWKS, gates protected routes, and exposes claims to the request
 * via response headers `x-authio-user-id`, `x-authio-org-id`, and
 * `x-authio-role` so downstream Server Components can read them via
 * `headers().get(...)`.
 */
export function authMiddleware(opts: AuthMiddlewareOptions = {}) {
  const apiUrl = (opts.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, "");
  const jwks = createRemoteJWKSet(
    new URL(apiUrl + "/v1/auth/.well-known/jwks.json"),
  );
  const { publicRoutes = [], signInUrl = "/sign-in" } = opts;

  return async function middleware(req: NextRequest) {
    const { pathname } = req.nextUrl;
    if (isPublic(pathname, publicRoutes)) return NextResponse.next();

    const cookie = req.cookies.get("authio_session")?.value;
    if (!cookie) return redirectToSignIn(req, signInUrl, pathname);

    try {
      const { payload } = await jwtVerify(cookie, jwks, {
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms: ["EdDSA"],
      });
      const res = NextResponse.next();
      if (typeof payload.sub === "string") {
        res.headers.set("x-authio-user-id", payload.sub);
      }
      if (typeof payload.act_org === "string") {
        res.headers.set("x-authio-org-id", payload.act_org);
      }
      if (typeof payload.act_role === "string") {
        res.headers.set("x-authio-role", payload.act_role);
      }
      return res;
    } catch {
      return redirectToSignIn(req, signInUrl, pathname);
    }
  };
}

function isPublic(pathname: string, publicRoutes: (string | RegExp)[]) {
  for (const r of publicRoutes) {
    if (typeof r === "string" ? pathname === r : r.test(pathname)) return true;
  }
  return false;
}

function redirectToSignIn(
  req: NextRequest,
  signInUrl: string,
  pathname: string,
) {
  const url = req.nextUrl.clone();
  url.pathname = signInUrl;
  url.searchParams.set("redirect_url", pathname);
  return NextResponse.redirect(url);
}
