import { describe, expect, it } from "vitest";
import { exportJWK, importJWK, jwtVerify, type JWK } from "jose";

import { SigningKeyPair } from "../src/index.js";
import { requireText, signCompact, thumbprint } from "../src/signing-key-pair.js";

describe("SigningKeyPair", () => {
  it("rejects unsupported algorithms in generate", async () => {
    await expect(SigningKeyPair.generate("RS256")).rejects.toThrow(
      "unsupported signing algorithm: RS256",
    );
  });

  it("fromJwk restores the same key (matching kid) and signs verifiably", async () => {
    const original = await SigningKeyPair.generate("ES256");
    const privateJwk = (await exportJWK(original.privateKey)) as JWK;
    const restored = await SigningKeyPair.fromJwk(privateJwk, "ES256");

    expect(restored.algorithm).toBe("ES256");
    expect(restored.keyId).toBe(original.keyId);
    const publicJwk = restored.publicJwk();
    expect(publicJwk.d).toBeUndefined();
    expect(publicJwk.kid).toBe(original.keyId);

    const jws = await signCompact({ ping: "pong" }, restored, "test+jwt", false);
    const { payload } = await jwtVerify(jws, await importJWK(original.publicJwk(), "ES256"));
    expect(payload.ping).toBe("pong");
  });

  it("fromJwk rejects a JWK without the private component", async () => {
    const original = await SigningKeyPair.generate("ES256");
    await expect(SigningKeyPair.fromJwk(original.publicJwk(), "ES256")).rejects.toThrow(
      "JWK does not contain a private key",
    );
  });

  it("fromJwk rejects unsupported algorithms", async () => {
    const original = await SigningKeyPair.generate("ES256");
    const privateJwk = (await exportJWK(original.privateKey)) as JWK;
    await expect(SigningKeyPair.fromJwk(privateJwk, "ES384")).rejects.toThrow(
      "unsupported signing algorithm: ES384",
    );
  });

  it("thumbprint matches the key's RFC 7638 kid", async () => {
    const key = await SigningKeyPair.generate("ES256");
    expect(await thumbprint(key.publicJwk())).toBe(key.keyId);
  });
});

describe("requireText", () => {
  it("returns non-blank values unchanged", () => {
    expect(requireText("value", "field")).toBe("value");
  });

  it.each([null, undefined, "", "   "])("rejects %j", (value) => {
    expect(() => requireText(value as string | null | undefined, "field")).toThrow(
      "field is required",
    );
  });
});
