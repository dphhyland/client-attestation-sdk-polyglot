/**
 * Client-side builder SDK for OAuth Attestation-Based Client Authentication.
 */
export { SigningKeyPair } from "./signing-key-pair.js";
export {
  ClientAttestationBuilder,
  DpopProofBuilder,
  PopBuilder,
  ATTESTATION_TYP,
  POP_TYP,
  DPOP_TYP,
} from "./builders.js";
export {
  ClientAttestationCredential,
  ATTESTATION_HEADER,
  POP_HEADER,
  DPOP_HEADER,
} from "./credential.js";

export const VERSION = "0.1.0";
