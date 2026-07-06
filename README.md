# client-attestation-sdk-polyglot

Client-side builder SDKs for **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/))
in **Python, TypeScript, and Go** — for authenticating agents and workloads on common runtimes (Bedrock
AgentCore, LangChain, Node/edge, Go services) as OAuth clients.

Every port has the same API and produces the same wire artifacts:

- the **Client Attestation JWT** — issued by a Client Attester, binding the client's instance key (`cnf.jwk`);
- the **PoP JWT** (`attest_jwt_client_auth`) or **DPoP proof** (`attest_jwt_client_auth_dpop`), signed by
  the instance key;
- the request **headers** to send to the token endpoint.

The reference implementation and the AS-side verifier are the Java
[client-attestation-sdk](https://github.com/dphhyland/client-attestation-sdk) /
[client-attestation](https://github.com/dphhyland/client-attestation).

## Proven interoperable

Every port is checked against the **real Java AS-side verifier**. Each builds credentials from the shared
[`vectors/inputs.json`](vectors/inputs.json) (fixed throwaway test keys) into `vectors/out/<lang>.json`, and
[`interop/VerifyInterop.java`](interop/VerifyInterop.java) runs each through `ClientAttestationVerifier` in
both PoP and DPoP modes. A Python-, TypeScript-, or Go-built credential is accepted by exactly the same AS
as a Java-built one. Reproduce with [`./verify-interop.sh`](verify-interop.sh).

## Layout

```
python/       PyJWT + cryptography              pip install client-attestation-sdk
typescript/   panva jose (Node + edge)          npm i client-attestation-sdk
go/           lestrrat-go/jwx                    go get .../client-attestation-sdk-polyglot/go
vectors/      shared inputs + generated outputs
interop/      Java cross-language verifier
```

See each subdirectory's README for language-specific install and usage. Representative flow (Python):

```python
attester = SigningKeyPair.generate("ES256")
attestation = (ClientAttestationBuilder(attester, "https://attester.example.com")
               .client_id("https://rp.example.com").confirmation_jwk(instance_pub).expires_in(300).build())
headers = ClientAttestationCredential(attestation, instance).pop_headers(
    "https://rp.example.com", "https://as.example.com")
```

## Contract

All ports emit the same shapes (ES256; `kid` = RFC 7638 thumbprint; `iat`/`exp` integer epoch seconds):

| Artifact | `typ` | key in header | key claims |
|---|---|---|---|
| Attestation | `oauth-client-attestation+jwt` | `kid` (attester) | `iss, sub, iat, exp, cnf.jwk` (instance pub, +kid) |
| PoP | `oauth-client-attestation-pop+jwt` | `kid` (instance) | `aud, jti, iat` (+ optional `iss`, `challenge`) |
| DPoP | `dpop+jwt` | `jwk` (instance pub, −kid) | `htm, htu, jti, iat` (+ optional `nonce`) |

## Not production keys

`vectors/inputs.json` holds fixed EC keys **only** so the ports build identical, comparable artifacts for
the interop check. They are throwaway test-vector keys — never use them for anything real.
