import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SignJWT, type JSONWebKeySet } from "jose";

import { SigningKeyPair } from "../src/index.js";
import {
  AccessTokenValidator,
  DEFAULT_ALGORITHMS,
  errors,
  resolveConfig,
  type ValidatorConfig,
} from "../src/validator/index.js";
import { failure, success } from "../src/validator/result.js";

const ISSUER = "https://issuer.example.com";
const AUDIENCE = "https://api.example.com";
const INTROSPECTION = {
  endpoint: "https://issuer.example.com/introspect",
  clientId: "rs-1",
  clientSecret: "s3cret",
};

let pair: SigningKeyPair;
let jwks: JSONWebKeySet;

beforeAll(async () => {
  pair = await SigningKeyPair.generate("ES256");
  jwks = { keys: [pair.publicJwk()] };
});

function newValidator(overrides: Partial<ValidatorConfig> = {}, opts = {}) {
  return new AccessTokenValidator(
    { issuer: ISSUER, audiences: [AUDIENCE], jwks, ...overrides },
    opts,
  );
}

async function sign(claims: Record<string, unknown>, kid?: string): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: kid ?? pair.keyId })
    .sign(pair.privateKey);
}

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

describe("token validator edge cases", () => {
  it("reports a malformed token", async () => {
    const result = await newValidator().validate("not-a-jwt");
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INVALID_TOKEN);
    expect(result.errorDescription).toContain("malformed token");
  });

  it("rejects a header without an alg", async () => {
    const token = `${b64url(JSON.stringify({ typ: "JWT" }))}.${b64url("{}")}.AAAA`;
    const result = await newValidator().validate(token);
    expect(result.error).toBe(errors.UNSUPPORTED_ALGORITHM);
  });

  it("rejects an alg outside the accepted list", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE });
    const result = await newValidator({ acceptedAlgorithms: ["RS256"] }).validate(token);
    expect(result.error).toBe(errors.UNSUPPORTED_ALGORITHM);
  });

  it("reports key_not_found for an unknown kid", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE }, "unknown-kid");
    const result = await newValidator().validate(token);
    expect(result.error).toBe(errors.KEY_NOT_FOUND);
  });

  it("accepts an audience list and normalizes it", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ iss: ISSUER, aud: [AUDIENCE, "https://other.example.com"], exp: now + 300 });
    const result = await newValidator().validate(token);
    expect(result.valid).toBe(true);
    expect(result.audience).toEqual([AUDIENCE, "https://other.example.com"]);
  });

  it("reads scopes from an scp array", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp: now + 300, scp: ["read", "write"] });
    const result = await newValidator().validate(token, ["read"]);
    expect(result.valid).toBe(true);
    expect(result.scopes).toEqual(["read", "write"]);
  });

  it("treats a token without scope/scp/exp as having none", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE });
    const result = await newValidator().validate(token);
    expect(result.valid).toBe(true);
    expect(result.scopes).toEqual([]);
    expect(result.expiresAt).toBeNull();
  });
});

describe("introspection edge cases", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("introspect throws when no endpoint is configured", async () => {
    await expect(newValidator().introspect("token")).rejects.toThrow(
      "no introspection endpoint configured",
    );
  });

  it("client_secret_post puts credentials in the form body", async () => {
    let captured: { body: string; headers: Record<string, string> } | null = null;
    const httpPost = async (_url: string, body: string, headers: Record<string, string>) => {
      captured = { body, headers };
      return { active: true };
    };
    const validator = newValidator(
      { introspection: { ...INTROSPECTION, authMethod: "client_secret_post" } },
      { httpPost },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(true);
    expect(captured!.headers.Authorization).toBeUndefined();
    expect(captured!.body).toContain("client_id=rs-1");
    expect(captured!.body).toContain("client_secret=s3cret");
  });

  it("validateActive enforces required scopes", async () => {
    const validator = newValidator(
      { introspection: INTROSPECTION },
      { httpPost: async () => ({ active: true, scope: "read" }) },
    );
    const result = await validator.validateActive("opaque-token", ["read", "admin"]);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INSUFFICIENT_SCOPE);
  });

  it("validateActive enforces the audience when the response carries one", async () => {
    const validator = newValidator(
      { introspection: INTROSPECTION },
      { httpPost: async () => ({ active: true, aud: ["https://other.example.com"] }) },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INVALID_AUDIENCE);
  });

  it("validateActive leaves the subject null for a non-string sub", async () => {
    const validator = newValidator(
      { introspection: INTROSPECTION },
      { httpPost: async () => ({ active: true, sub: 123 }) },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(true);
    expect(result.subject).toBeNull();
  });

  it("default POST transport posts the form and parses JSON", async () => {
    const fetchMock = vi.fn(async () => ({ json: async () => ({ active: true }) }));
    vi.stubGlobal("fetch", fetchMock);
    const validator = newValidator({ introspection: INTROSPECTION });
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      INTROSPECTION.endpoint,
      expect.objectContaining({ method: "POST" }),
    );
  });
});

describe("config resolution", () => {
  it("wraps a string audience into a list", () => {
    const resolved = resolveConfig({ issuer: ISSUER, audiences: AUDIENCE });
    expect(resolved.audiences).toEqual([AUDIENCE]);
  });

  it("defaults absent audiences to an empty list and applies other defaults", () => {
    const resolved = resolveConfig({
      issuer: ISSUER,
      audiences: undefined as unknown as string[],
    });
    expect(resolved.audiences).toEqual([]);
    expect(resolved.requiredScopes).toEqual([]);
    expect(resolved.acceptedAlgorithms).toEqual([...DEFAULT_ALGORITHMS]);
    expect(resolved.leewaySeconds).toBe(60);
  });
});

describe("validation results", () => {
  it("failure without a description leaves errorDescription null", () => {
    const result = failure(errors.EXPIRED);
    expect(result.valid).toBe(false);
    expect(result.errorDescription).toBeNull();
  });

  it("success with a non-string sub leaves subject null", () => {
    const result = success({ sub: 42, exp: 100 }, [], []);
    expect(result.subject).toBeNull();
    expect(result.expiresAt).toBe(100);
  });
});
