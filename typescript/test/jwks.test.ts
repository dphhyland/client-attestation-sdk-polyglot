import { afterEach, describe, expect, it, vi } from "vitest";
import type { JSONWebKeySet, JWK } from "jose";

import { SigningKeyPair } from "../src/index.js";
import { JwksProvider } from "../src/validator/jwks.js";

async function realKey(): Promise<JWK> {
  return (await SigningKeyPair.generate("ES256")).publicJwk();
}

describe("JwksProvider", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("falls back to the single configured key when the header has no kid", async () => {
    const jwk = await realKey();
    delete jwk.kid;
    const provider = new JwksProvider({ jwks: { keys: [jwk] } });
    expect(await provider.resolve(undefined)).toBeDefined();
  });

  it("returns undefined without a kid when multiple keys are configured", async () => {
    const provider = new JwksProvider({ jwks: { keys: [await realKey(), await realKey()] } });
    expect(await provider.resolve(undefined)).toBeUndefined();
  });

  it("returns undefined for an unknown kid on a static JWKS", async () => {
    const provider = new JwksProvider({ jwks: { keys: [await realKey()] } });
    expect(await provider.resolve("no-such-kid")).toBeUndefined();
  });

  it("tolerates a JWKS document without a keys array", async () => {
    const provider = new JwksProvider({ jwks: {} as JSONWebKeySet });
    expect(await provider.resolve(undefined)).toBeUndefined();
  });

  it("skips unimportable JWKs but keeps the good ones", async () => {
    const good = await realKey();
    const bad: JWK = { kty: "EC", crv: "P-256", x: "!!not-base64url!!", y: "!!", kid: "bad" };
    const provider = new JwksProvider({ jwks: { keys: [bad, good] } });
    expect(await provider.resolve(good.kid)).toBeDefined();
    expect(await provider.resolve("bad")).toBeUndefined();
  });

  it("infers an alg for JWKs that omit it, across key types", async () => {
    const p256 = await realKey();
    delete p256.alg;
    const keys: JWK[] = [
      p256,
      { kty: "EC", crv: "P-384", x: "AA", y: "AA", kid: "p384" },
      { kty: "EC", crv: "P-521", x: "AA", y: "AA", kid: "p521" },
      { kty: "EC", crv: "P-999", x: "AA", y: "AA", kid: "weird-crv" },
      { kty: "EC", kid: "no-crv" },
      { kty: "RSA", n: "AA", e: "AQAB", kid: "rsa" },
      { kty: "OKP", crv: "Ed25519", x: "AA", kid: "okp" },
      { kty: "oct", k: "AA", kid: "oct" },
    ];
    const provider = new JwksProvider({ jwks: { keys } });
    // The real P-256 key imports; the placeholder JWKs exercise alg inference and are skipped.
    expect(await provider.resolve(p256.kid)).toBeDefined();
  });

  it("fetches from jwksUri and refreshes on an unknown kid", async () => {
    const a = await realKey();
    const b = await realKey();
    const responses = [{ keys: [a] }, { keys: [a, b] }, { keys: [a, b] }];
    const httpGet = vi.fn(async () => JSON.stringify(responses.shift()));
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet });

    expect(await provider.resolve(a.kid)).toBeDefined();
    expect(httpGet).toHaveBeenCalledTimes(1);
    // Unknown kid triggers a refresh that now includes key b.
    expect(await provider.resolve(b.kid)).toBeDefined();
    expect(httpGet).toHaveBeenCalledTimes(2);
    // Still-unknown kid refreshes again and resolves to undefined.
    expect(await provider.resolve("missing")).toBeUndefined();
    expect(httpGet).toHaveBeenCalledTimes(3);
  });

  it("default HTTP GET fetches the JWKS body", async () => {
    const jwk = await realKey();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, text: async () => JSON.stringify({ keys: [jwk] }) })),
    );
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks" });
    expect(await provider.resolve(jwk.kid)).toBeDefined();
  });

  it("default HTTP GET fails on a non-2xx status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 500 })));
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks" });
    await expect(provider.resolve("any")).rejects.toThrow(
      "GET https://as.example.com/jwks failed: 500",
    );
  });
});
