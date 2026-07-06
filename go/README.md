# client-attestation-sdk (Go)

Go port of the client-side SDK for **OAuth Attestation-Based Client Authentication**
(`draft-ietf-oauth-attestation-based-client-auth`). It builds the three artifacts a
client presents at the token endpoint and is wire-compatible with the Java and
Python ports — the same AS-side Java verifier accepts all three.

Package `clientattestation`; signing via
[`github.com/lestrrat-go/jwx/v2`](https://github.com/lestrrat-go/jwx).

## Artifacts

| Artifact | `typ` | Key material in header | Notable claims |
|----------|-------|------------------------|----------------|
| Client Attestation JWT | `oauth-client-attestation+jwt` | attester `kid` (RFC 7638 thumbprint) | `iss`, `sub`=client_id, `iat`, `exp`, `cnf.jwk` (instance public JWK **incl. kid**) |
| PoP JWT | `oauth-client-attestation-pop+jwt` | instance `kid` | `aud`, `jti`, `iat`, optional `iss`/`challenge` (no `exp`) |
| DPoP proof | `dpop+jwt` | embedded `jwk` (instance public JWK **excl. kid**) | `htm`, `htu`, `jti`, `iat`, optional `nonce` |

`kid` is the RFC 7638 JWK thumbprint (SHA-256, base64url no padding). `iat`/`exp`
are integer epoch seconds; `aud` is a single string. ES256 throughout.

## Usage

```go
attester, _ := clientattestation.Generate("ES256") // or FromJWK(jwk, "ES256")
instance, _ := clientattestation.Generate("ES256")

attestation, _ := clientattestation.
    NewClientAttestationBuilder(attester, "https://attester.example.com").
    ClientID("https://rp.example.com").
    ConfirmationKey(instance).
    ExpiresIn(300).
    Build()

cred, _ := clientattestation.NewClientAttestationCredential(attestation, instance)

// Dedicated PoP-JWT mode (attest_jwt_client_auth):
popHeaders, _ := cred.PopHeaders("https://rp.example.com", "https://as.example.com", "")

// DPoP combined mode (attest_jwt_client_auth_dpop):
dpopHeaders, _ := cred.DpopHeaders("POST", "https://as.example.com/as/token.oauth2", "")
```

`PopHeaders` returns `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`;
`DpopHeaders` returns `OAuth-Client-Attestation` + `DPoP`.

## Develop

```sh
go mod tidy
go test ./...        # round-trip self-verification
go run ./cmd/emit    # writes ../vectors/out/go.json for the cross-language gate
```
