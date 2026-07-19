# client-attestation-sdk-polyglot

Agent-side OAuth SDKs in **Java, Python, TypeScript, and Go** — for authenticating agents and workloads on
common runtimes (Bedrock AgentCore, LangChain, Node/edge, JVM and Go services). Two capabilities:

1. **Client attestation builder** *(all four languages)* — build the credential a client presents to *get* a
   token ([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)):
   the Client Attestation JWT plus the proof of possession for auth method `attest_jwt_client_auth` —
   a dedicated PoP JWT (PoP method `attestation_pop_jwt`) or a DPoP proof (PoP method `dpop_combined`,
   draft -10 naming; formerly the separate `attest_jwt_client_auth_dpop` method) — and the request
   headers. Any of them can sign with a key held in a vault (`OpenBaoTransitSigner`).
2. **Token validator + MCP/A2A resource helper** *(Python / TypeScript / Go)* — the resource-server side:
   *validate* a token it receives — JWT signature via the issuer's JWKS, `iss`/`exp`/`nbf`, audience and
   scope — with optional RFC 7662 introspection, AS-metadata discovery, and RFC 9728 protected-resource
   metadata.

`java/` is the reference builder (formerly the standalone `client-attestation-sdk` repo). The **AS-side
verifier** that accepts these credentials is separate:
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
java/         client builder only                         (jose4j; depends on oidf-jose)
python/       client_attestation_sdk + token_validator    (PyJWT + cryptography)
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

## Signing keys outside the process (Vault / HSM)

The attester's issuing key doesn't have to live in the client. `OpenBaoTransitSigner` signs the attestation
inside an OpenBao / HashiCorp Vault transit engine (`marshaling_algorithm=jws`), so the private key never
leaves the vault — pass it to the builder in place of a local key:

```python
signer = OpenBaoTransitSigner("http://openbao:8200", vault_token, "attestation-es256")
attestation = (ClientAttestationBuilder(signer, "https://attester.example.com")
               .client_id("https://rp.example.com").confirmation_key(instance).expires_in(300).build())
# a verifier registers signer.public_jwk() (kid = the key's RFC 7638 thumbprint)
```

Same in every language — TS: `await OpenBaoTransitSigner.create(addr, token, key)`; Go:
`NewClientAttestationBuilderWithSigner(signer, issuer)`. Any key store fits the `JwsSigner` interface:
implement `sign(signingInput) → raw r‖s` and plug it in.

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

## Resource server for MCP / A2A

The validator is protocol-neutral OAuth resource-server validation, so it already does what an **MCP server**
or **A2A agent** must — verify the token and enforce audience + scope. `ProtectedResource` adds the HTTP
conventions on top: RFC 9728 protected-resource metadata, RFC 6750 bearer extraction + `WWW-Authenticate`
challenges, and a request guard that binds the token to this resource (RFC 8707) and maps failures to 401/403.

```python
from token_validator import AccessTokenValidator, ProtectedResource, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://as.example.com", audiences=["https://mcp.example.com/mcp"],  # audience = this server
    jwks_uri="https://as.example.com/jwks", required_scopes=["mcp:call"]))
resource = ProtectedResource("https://mcp.example.com/mcp", ["https://as.example.com"], validator)

# serve resource.metadata() at resource.metadata_path()  →  /.well-known/oauth-protected-resource
decision = resource.authenticate(authorization_header)          # or .authenticate(hdr, ["extra:scope"])
if decision.authorized:
    handle(decision.result.subject, decision.result.scopes)
else:
    reply(decision.status, {"WWW-Authenticate": decision.www_authenticate})   # 401 or 403
```

Per the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
that's the entire resource-server duty (OAuth 2.1 + RFC 9728 / 8414 / 8707); only the last-mile middleware
wiring into a given server framework is platform-specific — a runnable, dependency-free example ships in each
language's `examples/`. The same `ProtectedResource` serves A2A agents, whose Agent Cards just declare an
OAuth2/bearer scheme.

## Not production keys

The fixed keys in `vectors/inputs.json` and `validation/tokens.json` exist **only** so the ports produce
identical, comparable artifacts for the interop checks. They are throwaway test-vector keys — never use them
for anything real.
