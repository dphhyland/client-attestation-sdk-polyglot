/**
 * Builders for the attestation, PoP and DPoP JWTs (draft-ietf-oauth-attestation-based-client-auth).
 */
import { randomUUID } from "node:crypto";
import type { JWK } from "jose";

import { SigningKeyPair, requireText, signCompact } from "./signing-key-pair.js";
import { type JwsSigner, signExternal } from "./signer.js";

export const ATTESTATION_TYP = "oauth-client-attestation+jwt";
export const POP_TYP = "oauth-client-attestation-pop+jwt";
export const DPOP_TYP = "dpop+jwt";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Builds a Client Attestation JWT — the credential a Client Attester issues to name a client
 * (`sub`) and bind its instance key via `cnf.jwk`. Attester side; sign with the attester's key.
 */
export class ClientAttestationBuilder {
  readonly #attesterKey: SigningKeyPair | JwsSigner;
  readonly #issuer: string;
  #clientId: string | null = null;
  #cnfJwk: JWK | null = null;
  #issuedAt: number | null = null;
  #expiresAt: number | null = null;
  #ttl: number | null = null;
  #authorizationDetails: unknown[] | null = null;
  #workload: Record<string, unknown> | null = null;

  constructor(attesterKey: SigningKeyPair | JwsSigner, issuer: string) {
    this.#attesterKey = attesterKey;
    this.#issuer = requireText(issuer, "issuer");
  }

  /** The client being attested — becomes the attestation `sub` (= `client_id`). */
  clientId(clientId: string): this {
    this.#clientId = clientId;
    return this;
  }

  /** Binds the client instance key as `cnf.jwk`. Must be a public JWK. */
  confirmationJwk(publicInstanceJwk: JWK): this {
    this.#cnfJwk = publicInstanceJwk;
    return this;
  }

  /** Convenience: binds the public half of the given instance key as `cnf.jwk`. */
  confirmationKey(instanceKey: SigningKeyPair): this {
    return this.confirmationJwk(instanceKey.publicJwk());
  }

  issuedAt(epochSeconds: number): this {
    this.#issuedAt = epochSeconds;
    return this;
  }

  /** Sets an absolute `exp`. */
  expiresAt(epochSeconds: number): this {
    this.#expiresAt = epochSeconds;
    return this;
  }

  /** Sets `exp` to `iat + seconds`. */
  expiresIn(seconds: number): this {
    this.#ttl = seconds;
    return this;
  }

  /** The optional RFC 9396 `authorization_details` entitlement the attester asserts. */
  authorizationDetails(details: unknown[]): this {
    this.#authorizationDetails = details;
    return this;
  }

  /** Optional attester-asserted `workload` attributes. */
  workload(workload: Record<string, unknown>): this {
    this.#workload = workload;
    return this;
  }

  async build(): Promise<string> {
    const sub = requireText(this.#clientId, "client_id");
    if (this.#cnfJwk === null) {
      throw new Error("confirmation key (cnf.jwk) is required");
    }
    const iat = this.#issuedAt !== null ? this.#issuedAt : nowSeconds();
    const exp = this.#resolveExpiry(iat);
    const claims: Record<string, unknown> = {
      iss: this.#issuer,
      sub,
      iat,
      exp,
      cnf: { jwk: this.#cnfJwk },
    };
    if (this.#authorizationDetails && this.#authorizationDetails.length > 0) {
      claims.authorization_details = this.#authorizationDetails;
    }
    if (this.#workload && Object.keys(this.#workload).length > 0) {
      claims.workload = this.#workload;
    }
    if (this.#attesterKey instanceof SigningKeyPair) {
      return signCompact(claims, this.#attesterKey, ATTESTATION_TYP, false);
    }
    return signExternal(claims, this.#attesterKey, ATTESTATION_TYP);
  }

  #resolveExpiry(iat: number): number {
    if (this.#expiresAt !== null) {
      return this.#expiresAt;
    }
    if (this.#ttl !== null) {
      return iat + this.#ttl;
    }
    throw new Error("expiry is required: call expiresAt(...) or expiresIn(...)");
  }
}

/**
 * Builds a Client Attestation PoP JWT proving possession of the instance key. Client side of
 * `attest_jwt_client_auth`; mint a fresh one per token request.
 */
export class PopBuilder {
  readonly #instanceKey: SigningKeyPair;
  #clientId: string | null = null;
  #audience: string | null = null;
  #challenge: string | null = null;
  #jwtId: string | null = null;
  #issuedAt: number | null = null;

  constructor(instanceKey: SigningKeyPair) {
    this.#instanceKey = instanceKey;
  }

  /** Sets the optional `iss`; when present the verifier requires it to equal the attestation `sub`. */
  clientId(clientId: string | null): this {
    this.#clientId = clientId;
    return this;
  }

  /** The AS identifier this PoP is bound to (`aud`) — required. */
  audience(audience: string): this {
    this.#audience = audience;
    return this;
  }

  challenge(challenge: string | null): this {
    this.#challenge = challenge;
    return this;
  }

  jwtId(jwtId: string): this {
    this.#jwtId = jwtId;
    return this;
  }

  issuedAt(epochSeconds: number): this {
    this.#issuedAt = epochSeconds;
    return this;
  }

  async build(): Promise<string> {
    if (!this.#audience) {
      throw new Error("audience (aud) is required");
    }
    const claims: Record<string, unknown> = {
      aud: this.#audience,
      jti: this.#jwtId ?? randomUUID(),
      iat: this.#issuedAt !== null ? this.#issuedAt : nowSeconds(),
    };
    if (this.#clientId) {
      claims.iss = this.#clientId;
    }
    if (this.#challenge) {
      claims.challenge = this.#challenge;
    }
    return signCompact(claims, this.#instanceKey, POP_TYP, false);
  }
}

/**
 * Builds a DPoP proof JWT (RFC 9449) for attestation combined mode
 * (`attest_jwt_client_auth_dpop`): the embedded `jwk` header MUST be the attestation's `cnf` key.
 */
export class DpopProofBuilder {
  readonly #instanceKey: SigningKeyPair;
  #htm = "POST";
  #htu: string | null = null;
  #nonce: string | null = null;
  #jwtId: string | null = null;
  #issuedAt: number | null = null;

  constructor(instanceKey: SigningKeyPair) {
    this.#instanceKey = instanceKey;
  }

  /** The token request's HTTP method (`htm`); defaults to `POST`. */
  method(htm: string | null | undefined): this {
    if (htm) {
      this.#htm = htm;
    }
    return this;
  }

  /** The token endpoint URL (`htu`) — required. */
  uri(htu: string): this {
    this.#htu = htu;
    return this;
  }

  /** The server challenge, carried in DPoP `nonce`. */
  nonce(nonce: string | null): this {
    this.#nonce = nonce;
    return this;
  }

  jwtId(jwtId: string): this {
    this.#jwtId = jwtId;
    return this;
  }

  issuedAt(epochSeconds: number): this {
    this.#issuedAt = epochSeconds;
    return this;
  }

  async build(): Promise<string> {
    if (!this.#htu) {
      throw new Error("uri (htu) is required");
    }
    const claims: Record<string, unknown> = {
      htm: this.#htm,
      htu: this.#htu,
      jti: this.#jwtId ?? randomUUID(),
      iat: this.#issuedAt !== null ? this.#issuedAt : nowSeconds(),
    };
    if (this.#nonce) {
      claims.nonce = this.#nonce;
    }
    return signCompact(claims, this.#instanceKey, DPOP_TYP, true);
  }
}
