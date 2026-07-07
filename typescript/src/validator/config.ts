/**
 * Validator configuration.
 */
import type { JSONWebKeySet } from "jose";

/** Default accepted JWS algorithms: EC / RSA / RSA-PSS at 256/384/512. */
export const DEFAULT_ALGORITHMS: readonly string[] = [
  "ES256",
  "ES384",
  "ES512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
];

/** How the resource server authenticates to the AS when introspecting. */
export type IntrospectionAuthMethod = "client_secret_basic" | "client_secret_post";

/**
 * RFC 7662 introspection endpoint + client credentials (the resource server authenticating to the AS).
 */
export interface IntrospectionConfig {
  endpoint: string;
  clientId: string;
  clientSecret: string;
  /** Defaults to `"client_secret_basic"`. */
  authMethod?: IntrospectionAuthMethod;
}

/**
 * What this resource server accepts: the trusted issuer, its own audience identifier(s), the signing
 * keys (static `jwks` or a `jwksUri` to fetch), required scopes, accepted algorithms, clock leeway,
 * and optional introspection.
 */
export interface ValidatorConfig {
  issuer: string;
  audiences: string | string[];
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  requiredScopes?: string[];
  /** Defaults to {@link DEFAULT_ALGORITHMS}. */
  acceptedAlgorithms?: string[];
  /** Clock skew allowed on `exp` / `nbf`, in seconds. Defaults to 60. */
  leewaySeconds?: number;
  introspection?: IntrospectionConfig;
}

/** A {@link ValidatorConfig} with every optional field defaulted. */
export interface ResolvedConfig {
  issuer: string;
  audiences: string[];
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  requiredScopes: string[];
  acceptedAlgorithms: string[];
  leewaySeconds: number;
  introspection?: IntrospectionConfig;
}

/** Normalize a caller-supplied config, applying defaults (mirrors Python's `ValidatorConfig`). */
export function resolveConfig(config: ValidatorConfig): ResolvedConfig {
  const audiences =
    typeof config.audiences === "string" ? [config.audiences] : [...(config.audiences ?? [])];
  return {
    issuer: config.issuer,
    audiences,
    jwks: config.jwks,
    jwksUri: config.jwksUri,
    requiredScopes: [...(config.requiredScopes ?? [])],
    acceptedAlgorithms: [...(config.acceptedAlgorithms ?? DEFAULT_ALGORITHMS)],
    leewaySeconds: config.leewaySeconds ?? 60,
    introspection: config.introspection,
  };
}
