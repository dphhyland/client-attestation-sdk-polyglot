# client-attestation-sdk

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)).

It mints the artifacts a client (and its attester) present at the token endpoint:

- the **Client Attestation JWT** — issued by a Client Attester, naming the client and binding its
  instance key (`cnf.jwk`);
- the **PoP JWT** (`attest_jwt_client_auth`) or **DPoP proof** (`attest_jwt_client_auth_dpop`) — signed
  by the client instance key to prove possession;
- the request **headers** to send.

Built on [`oidf-jose`](https://github.com/dphhyland/oidf-jose). The AS-side counterpart that *verifies*
these artifacts is [`client-attestation`](https://github.com/dphhyland/client-attestation) — this SDK is
round-trip tested against it.

## Install

```xml
<dependency>
  <groupId>com.pingidentity.ps.oidf</groupId>
  <artifactId>client-attestation-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Attester: issue an attestation

The attester names the client and binds the client's public instance key. Sign with the attester's
issuing key.

```java
SigningKeyPair attesterKey = SigningKeyPair.generate("ES256");   // the attester's key
Map<String, Object> clientInstancePublicJwk = /* the client's public cnf key */;

String attestation = new ClientAttestationBuilder(attesterKey, "https://attester.example.com")
        .clientId("https://rp.example.com")
        .confirmationJwk(clientInstancePublicJwk)
        .expiresIn(Duration.ofMinutes(5))
        // optional: .authorizationDetails(...) / .workload(...)
        .build();
```

## Client: present the attestation + proof of possession

The client holds its instance key and the attestation, and mints a fresh proof per token request.

```java
SigningKeyPair instanceKey = /* the client's own key (private held by the client) */;
ClientAttestationCredential cred = new ClientAttestationCredential(attestation, instanceKey);

// Dedicated PoP-JWT mode:
Map<String, String> headers = cred.popHeaders(
        "https://rp.example.com",          // client_id (PoP iss)
        "https://as.example.com",          // AS identifier (PoP aud)
        challenge);                        // server challenge, or null

// ...or DPoP combined mode:
Map<String, String> headers = cred.dpopHeaders(
        "POST",
        "https://as.example.com/as/token.oauth2",   // htu
        challenge);                                  // DPoP nonce, or null

// headers -> OAuth-Client-Attestation + (OAuth-Client-Attestation-PoP | DPoP)
```

Add `headers` to the token request. The lower-level builders (`ClientAttestationBuilder`, `PopBuilder`,
`DpopProofBuilder`) are available directly when you need finer control (explicit `jti`, `iat`, etc.).

## Keys

`SigningKeyPair` wraps a JWK key pair with its JWS `alg` and RFC 7638 thumbprint `kid`:

```java
SigningKeyPair k = SigningKeyPair.generate("ES256");   // ES256/384/512, RS256/384/512, PS256/384/512
Map<String, Object> publicJwk = k.publicJwk();          // e.g. to publish or hand to an attester
SigningKeyPair imported = SigningKeyPair.fromJwk(existingJose4jJwk, "ES256");
```

## Build

```bash
mvn -o clean install     # offline; requires oidf-jose + client-attestation 0.1.0 in ~/.m2
```

`RoundTripTest` builds each artifact and verifies it through the real AS-side
`ClientAttestationVerifier`, for both PoP and DPoP modes and both EC and RSA instance keys.

## Not yet included

SD-JWT-encoded attestation presentations (selective disclosure + key binding) — the verifier accepts
them (`oauth-client-attestation+sd-jwt`); a builder for them is a planned addition on top of
`oidf-jose`'s `SdJwt`.
