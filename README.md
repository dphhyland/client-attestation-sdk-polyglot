# client-attestation-sdk-polyglot

Agent-side OAuth SDKs in **Python, TypeScript, and Go** — for authenticating agents and workloads on common
runtimes (Bedrock AgentCore, LangChain, Node/edge, Go services). Two complementary sides, the same API shape
in every language:

1. **Client attestation builder** — build the credential a client presents to *get* a token
   ([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)):
   the Client Attestation JWT + a PoP JWT (`attest_jwt_client_auth`) or DPoP proof
   (`attest_jwt_client_auth_dpop`), plus the request headers.
2. **Token validator** — the resource-server side: *validate* a token it receives — JWT signature via the
   issuer's JWKS, `iss`/`exp`/`nbf`, audience and scope — with optional RFC 7662 introspection and
   AS-metadata discovery.

The reference implementation and the AS-side verifier are the Java
[client-attestation-sdk](https://github.com/dphhyland/client-attestation-sdk) /
[client-attestation](https://github.com/dphhyland/client-attestation).

## Proven interoperable

Every port is checked against the **real Java AS-side verifier**. Each builds credentials from the shared
[`vectors/inputs.json`](vectors/inputs.json) (fixed throwaway test keys) into `vectors/out/<lang>.json`, and
[`interop/VerifyInterop.java`](interop/VerifyInterop.java) runs each through `ClientAttestationVerifier` in
both PoP and DPoP modes. A Python-, TypeScript-, or Go-built credential is accepted by exactly the same AS
as a Java-built one. Reproduce with [`./verify-interop.sh`](verify-interop.sh).

**Validator** — every port validates the shared [`validation/tokens.json`](validation/tokens.json)
(pre-signed tokens: valid, expired, not-yet-valid, wrong issuer/audience, missing scope, bad signature) and
must return the **identical verdict** for every case. [`validation/check.py`](validation/check.py) confirms
all three agree with the expected verdicts. Reproduce with [`./verify-validation.sh`](verify-validation.sh).

## Layout

```
python/       client_attestation_sdk + token_validator   (PyJWT + cryptography)
typescript/   src/ builder + src/validator/               (panva jose; Node + edge)
go/           builder package + tokenvalidator/           (lestrrat-go/jwx)
vectors/      client-builder shared vectors + outputs
validation/   token-validator shared vectors + agreement checker
interop/      Java cross-language verifier (builder side)
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

## Token validation (resource server)

The validator side mirrors the same config→act shape. Representative flow (Python):

```python
from token_validator import AccessTokenValidator, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://issuer.example.com", audiences=["https://api.example.com"],
    jwks_uri="https://issuer.example.com/jwks", required_scopes=["read"]))

result = validator.validate(access_token)          # local: signature + iss/exp/nbf + audience + scope
if result.valid:
    print(result.subject, result.scopes)
# optional RFC 7662 revocation / opaque-token check:
result = validator.validate_active(access_token)   # introspection
```

`validate` runs a fixed error-precedence order — identical across all ports so their verdicts match:
algorithm → key → signature → `iss` → `exp` → `nbf` → audience → scope, returning the first failure's stable
code (`invalid_signature`, `invalid_issuer`, `expired`, `not_yet_valid`, `invalid_audience`,
`insufficient_scope`, …).

## Not production keys

The fixed keys in `vectors/inputs.json` and `validation/tokens.json` exist **only** so the ports produce
identical, comparable artifacts for the interop checks. They are throwaway test-vector keys — never use them
for anything real.
