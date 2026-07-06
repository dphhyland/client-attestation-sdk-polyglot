/**
 * Signing keys for attestation-based client authentication.
 */
import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
  type CryptoKey,
  type JWK,
} from "jose";

/**
 * A signing key pair (public + private) with its JWS `alg` and RFC 7638 thumbprint `kid`.
 *
 * Used both as the client instance key — which signs PoP / DPoP proofs and is bound into an
 * attestation's `cnf` — and as a Client Attester's issuing key.
 *
 * jose's crypto operations are async, so instances are created via the static async
 * factories {@link SigningKeyPair.generate} and {@link SigningKeyPair.fromJwk}.
 */
export class SigningKeyPair {
  /** The JWS algorithm (e.g. `ES256`). */
  readonly algorithm: string;
  /** The RFC 7638 JWK thumbprint (SHA-256, base64url) — this key's `kid`. */
  readonly keyId: string;

  readonly #privateKey: CryptoKey;
  readonly #publicJwk: JWK;

  private constructor(privateKey: CryptoKey, algorithm: string, publicJwk: JWK, keyId: string) {
    this.#privateKey = privateKey;
    this.algorithm = algorithm;
    // Store the public JWK with its kid stamped, so publicJwk() hands out a copy including kid.
    this.#publicJwk = { ...publicJwk, kid: keyId };
    this.keyId = keyId;
  }

  /**
   * Generate a fresh extractable key pair for the given JWS algorithm (currently `ES256`, EC P-256).
   */
  static async generate(algorithm: string): Promise<SigningKeyPair> {
    if (algorithm !== "ES256") {
      throw new Error(`unsupported signing algorithm: ${algorithm}`);
    }
    const { privateKey, publicKey } = await generateKeyPair(algorithm, { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const keyId = await calculateJwkThumbprint(publicJwk, "sha256");
    return new SigningKeyPair(privateKey, algorithm, publicJwk, keyId);
  }

  /**
   * Wrap an existing JWK (which must contain the private component `d`) for the given algorithm.
   */
  static async fromJwk(jwk: JWK, algorithm: string): Promise<SigningKeyPair> {
    if (!jwk.d) {
      throw new Error("JWK does not contain a private key");
    }
    if (algorithm !== "ES256") {
      throw new Error(`unsupported signing algorithm: ${algorithm}`);
    }
    const privateKey = (await importJWK(jwk, algorithm)) as CryptoKey;
    // Derive the public-only JWK from the supplied members (drop the private `d`).
    const publicJwk: JWK = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const keyId = await calculateJwkThumbprint(publicJwk, "sha256");
    return new SigningKeyPair(privateKey, algorithm, publicJwk, keyId);
  }

  /** The private CryptoKey — package-internal; used by the JWS signer. */
  get privateKey(): CryptoKey {
    return this.#privateKey;
  }

  /**
   * The public-only JWK (including `kid`) as a fresh object — suitable as an attestation
   * `cnf.jwk` or a DPoP header value (from which callers strip `kid`).
   */
  publicJwk(): JWK {
    return { ...this.#publicJwk };
  }
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) over the required members only. */
export async function thumbprint(publicJwk: JWK): Promise<string> {
  return calculateJwkThumbprint(publicJwk, "sha256");
}

/**
 * Sign claims into a compact JWS with an explicit `typ` header, keyed by `key`.
 *
 * When `embedJwk` is set the public key travels in a `jwk` header (as DPoP requires); otherwise
 * the key's thumbprint `kid` is set.
 */
export async function signCompact(
  claims: Record<string, unknown>,
  key: SigningKeyPair,
  typ: string,
  embedJwk: boolean,
): Promise<string> {
  const header: Record<string, unknown> = { alg: key.algorithm, typ };
  if (embedJwk) {
    const publicJwk = key.publicJwk();
    delete publicJwk.kid;
    header.jwk = publicJwk;
  } else {
    header.kid = key.keyId;
  }
  return new SignJWT(claims).setProtectedHeader(header as never).sign(key.privateKey);
}

export function requireText(value: string | null | undefined, field: string): string {
  if (value == null || String(value).trim() === "") {
    throw new Error(`${field} is required`);
  }
  return value;
}
