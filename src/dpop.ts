/**
 * DPoP (RFC 9449) support for the BFF handlers: sender-constrained
 * refresh tokens.
 *
 * When `dpop: true` is set on the handler config, the callback handler
 * generates a per-session P-256 keypair, sends a DPoP proof on the
 * session-handoff exchange (binding the key's RFC 7638 thumbprint to
 * the session server-side), and stores the private JWK in an
 * encrypted HttpOnly cookie next to the refresh cookie. Every
 * subsequent refresh attaches a fresh proof signed by the same key —
 * so a refresh token leaked through logs, URLs, or backups is
 * useless without the key that never leaves the sealed cookie.
 *
 * Sealing uses compact JWE (dir + A256GCM) with a key derived from
 * the deployment's `dpopSealSecret` (or the `AUTHIO_DPOP_SEAL_SECRET`
 * env var), so a leaked cookie jar exposes only ciphertext.
 *
 * Everything here is Edge-safe: jose + Web Crypto only.
 */

import {
  SignJWT,
  EncryptJWT,
  jwtDecrypt,
  generateKeyPair,
  exportJWK,
  importJWK,
  type JWK,
} from "jose";

/** The subset of an EC private JWK we persist. `d` is the private scalar. */
export interface DPoPKey {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d: string;
}

/** Generate a fresh extractable P-256 keypair for one session. */
export async function generateDPoPKey(): Promise<DPoPKey> {
  const { privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const jwk = await exportJWK(privateKey);
  return {
    kty: jwk.kty!,
    crv: jwk.crv!,
    x: jwk.x!,
    y: jwk.y!,
    d: jwk.d!,
  };
}

/** The public half of the key, as embedded in every proof's header. */
export function publicJWK(key: DPoPKey): JWK {
  return { kty: key.kty, crv: key.crv, x: key.x, y: key.y };
}

/**
 * Mint a DPoP proof JWT for one HTTP request (RFC 9449 §4):
 * `typ: dpop+jwt`, ES256, public JWK in the header, htm/htu/iat/jti
 * claims. Auth-core canonicalises htu as scheme://host/path (no query,
 * trailing-slash tolerant), so pass the full request URL — we strip
 * the query here.
 */
export async function createDPoPProof(
  key: DPoPKey,
  htm: string,
  url: string,
): Promise<string> {
  const u = new URL(url);
  const htu = `${u.protocol}//${u.host}${u.pathname}`;
  const privateKey = await importJWK(key as JWK, "ES256");
  return await new SignJWT({
    htm: htm.toUpperCase(),
    htu,
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: publicJWK(key),
    })
    .setIssuedAt()
    .sign(privateKey);
}

// ---------------------------------------------------------------------
// Cookie sealing
// ---------------------------------------------------------------------

/**
 * Derive the AES-256-GCM content-encryption key from the deployment
 * secret. SHA-256 gives exactly 32 bytes; the secret is a long-lived
 * random string, not a low-entropy password, so a KDF with stretching
 * would add latency without a threat-model gain.
 */
async function sealKey(secret: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(secret),
  );
  return new Uint8Array(digest);
}

/** Seal the private JWK into a compact JWE string for the cookie. */
export async function sealDPoPKey(
  key: DPoPKey,
  secret: string,
): Promise<string> {
  return await new EncryptJWT({ dpop_jwk: key })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .encrypt(await sealKey(secret));
}

/**
 * Unseal a cookie value back into the private JWK. Returns null on any
 * failure (tampered, wrong secret, legacy garbage) — callers treat
 * that the same as "no key": the refresh proceeds unbound and
 * auth-core decides whether that is acceptable for the session.
 */
export async function unsealDPoPKey(
  sealed: string,
  secret: string,
): Promise<DPoPKey | null> {
  try {
    const { payload } = await jwtDecrypt(sealed, await sealKey(secret));
    const jwk = payload.dpop_jwk as DPoPKey | undefined;
    if (!jwk || jwk.kty !== "EC" || !jwk.d || !jwk.x || !jwk.y) return null;
    return jwk;
  } catch {
    return null;
  }
}
