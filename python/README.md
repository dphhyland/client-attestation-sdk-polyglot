# client-attestation-sdk (Python)

Client-side builder for **OAuth Attestation-Based Client Authentication**
(draft-ietf-oauth-attestation-based-client-auth). Mints the Client Attestation JWT (attester side) and the
PoP / DPoP proofs + request headers (client side). Depends only on `pyjwt` + `cryptography`.

Part of the [client-attestation-sdk-polyglot](../README.md) monorepo; wire-compatible with the Java,
TypeScript, and Go ports.

## Install

```bash
pip install client-attestation-sdk        # or: pip install -e .[test]
```

## Use

```python
from client_attestation_sdk import (
    SigningKeyPair, ClientAttestationBuilder, ClientAttestationCredential,
)

# Attester issues the attestation, binding the client's public instance key
attester = SigningKeyPair.generate("ES256")
attestation = (
    ClientAttestationBuilder(attester, "https://attester.example.com")
    .client_id("https://rp.example.com")
    .confirmation_jwk(client_instance_public_jwk)
    .expires_in(300)
    .build()
)

# Client mints a fresh proof per token request
instance = SigningKeyPair.from_jwk(my_instance_private_jwk, "ES256")
cred = ClientAttestationCredential(attestation, instance)

headers = cred.pop_headers("https://rp.example.com", "https://as.example.com")   # PoP-JWT mode
# or
headers = cred.dpop_headers("POST", "https://as.example.com/as/token.oauth2")    # DPoP combined mode
# -> {"OAuth-Client-Attestation": "...", "OAuth-Client-Attestation-PoP" | "DPoP": "..."}
```

## Test

```bash
pip install -e .[test]
pytest
```
