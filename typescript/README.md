# client-attestation-sdk (TypeScript)

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
(`draft-ietf-oauth-attestation-based-client-auth`). Mints the three artifacts a client
presents at the token endpoint:

- **Client Attestation JWT** (`typ=oauth-client-attestation+jwt`) — issued by a Client Attester,
  names the client (`sub` = `client_id`) and binds its instance key via `cnf.jwk`.
- **Client Attestation PoP JWT** (`typ=oauth-client-attestation-pop+jwt`) — proves possession of
  the instance key (PoP method `attestation_pop_jwt`).
- **DPoP proof JWT** (`typ=dpop+jwt`) — combined mode (PoP method `dpop_combined`); its embedded
  `jwk` header is the instance key bound in the attestation's `cnf`.

This is one port of a polyglot SDK; it emits byte-compatible artifacts with the Java and Python
ports and is judged by a shared Java verifier. Built on [panva `jose`](https://github.com/panva/jose).
`kid` values are RFC 7638 JWK thumbprints (SHA-256, base64url); `iat`/`exp` are integer epoch seconds.

## Install / build

```bash
npm install
npm run build   # tsc -> dist/
```

## Usage

jose's crypto is async, so key factories and `build()` return promises.

```ts
import {
  ClientAttestationBuilder,
  ClientAttestationCredential,
  SigningKeyPair,
} from "client-attestation-sdk";

// Attester side: issue the attestation.
const attester = await SigningKeyPair.generate("ES256");     // or SigningKeyPair.fromJwk(jwk, "ES256")
const instance = await SigningKeyPair.generate("ES256");     // the client's instance key
const attestation = await new ClientAttestationBuilder(attester, "https://attester.example.com")
  .clientId("https://rp.example.com")
  .confirmationKey(instance)
  .expiresIn(300)
  .build();

// Client side: produce token-request headers.
const cred = new ClientAttestationCredential(attestation, instance);

const popHeaders = await cred.popHeaders("https://rp.example.com", "https://as.example.com");
// { "OAuth-Client-Attestation": "...", "OAuth-Client-Attestation-PoP": "..." }

const dpopHeaders = await cred.dpopHeaders("POST", "https://as.example.com/as/token.oauth2");
// { "OAuth-Client-Attestation": "...", "DPoP": "..." }
```

## Test & interop

```bash
npm test        # vitest — self-verifies each artifact with jose
npm run emit    # writes ../vectors/out/typescript.json for the cross-language Java verifier
```
