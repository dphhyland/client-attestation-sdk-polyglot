/**
 * Resolves issuer signing keys — from a static JWKS or a `jwksUri` (fetched and cached, refreshed on an
 * unknown `kid`).
 */
import { importJWK, type CryptoKey, type JSONWebKeySet, type JWK } from "jose";

/** An imported verification key, as returned by jose's `importJWK`. */
export type VerificationKey = CryptoKey | Uint8Array;

/** Fetch a URL and return its body text. Injectable so tests can avoid real network I/O. */
export type HttpGet = (url: string) => Promise<string>;

const defaultGet: HttpGet = async (url) => {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`GET ${url} failed: ${resp.status}`);
  }
  return resp.text();
};

/** Best-effort JWS `alg` for a JWK that omits `alg`, from its key type / curve. */
function algorithmFor(jwk: JWK): string {
  if (jwk.kty === "EC") {
    return { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" }[jwk.crv ?? ""] ?? "ES256";
  }
  if (jwk.kty === "RSA") {
    return "RS256";
  }
  if (jwk.kty === "OKP") {
    return "EdDSA";
  }
  return "RS256";
}

export class JwksProvider {
  readonly #static: boolean;
  readonly #jwksUri?: string;
  readonly #httpGet: HttpGet;
  #keys = new Map<string | undefined, VerificationKey>();
  #loaded: Promise<void> | null = null;

  constructor(opts: { jwks?: JSONWebKeySet; jwksUri?: string; httpGet?: HttpGet }) {
    this.#static = opts.jwks != null;
    this.#jwksUri = opts.jwksUri;
    this.#httpGet = opts.httpGet ?? defaultGet;
    if (opts.jwks != null) {
      this.#loaded = this.#load(opts.jwks);
    }
  }

  async #load(jwks: JSONWebKeySet): Promise<void> {
    const keys = new Map<string | undefined, VerificationKey>();
    for (const jwk of jwks.keys ?? []) {
      const alg = jwk.alg ?? algorithmFor(jwk);
      try {
        keys.set(jwk.kid, await importJWK(jwk, alg));
      } catch {
        continue;
      }
    }
    this.#keys = keys;
  }

  /**
   * Resolve the verification key for a header `kid`. Falls back to the single configured key when the
   * header carries no `kid`, and refreshes from `jwksUri` on an unknown `kid`. Returns `undefined`
   * when no key can be found.
   */
  async resolve(kid: string | undefined): Promise<VerificationKey | undefined> {
    if (this.#loaded) {
      await this.#loaded;
    }
    if (kid != null && this.#keys.has(kid)) {
      return this.#keys.get(kid);
    }
    if (kid == null && this.#keys.size === 1) {
      return this.#keys.values().next().value;
    }
    if (!this.#static && this.#jwksUri) {
      await this.#load(JSON.parse(await this.#httpGet(this.#jwksUri)) as JSONWebKeySet);
      return this.#keys.get(kid);
    }
    return undefined;
  }
}
