"""Builders for the attestation, PoP and DPoP JWTs (draft-ietf-oauth-attestation-based-client-auth)."""
from __future__ import annotations

import time
import uuid

from .keys import SigningKeyPair, require_text, sign_compact

ATTESTATION_TYP = "oauth-client-attestation+jwt"
POP_TYP = "oauth-client-attestation-pop+jwt"
DPOP_TYP = "dpop+jwt"


class ClientAttestationBuilder:
    """Builds a Client Attestation JWT — the credential a Client Attester issues to name a client
    (``sub``) and bind its instance key via ``cnf.jwk``. Attester side; sign with the attester's key."""

    def __init__(self, attester_key: SigningKeyPair, issuer: str):
        self._attester_key = attester_key
        self._issuer = require_text(issuer, "issuer")
        self._client_id = None
        self._cnf_jwk = None
        self._issued_at = None
        self._expires_at = None
        self._ttl = None
        self._authorization_details = None
        self._workload = None

    def client_id(self, client_id: str) -> "ClientAttestationBuilder":
        self._client_id = client_id
        return self

    def confirmation_jwk(self, public_instance_jwk: dict) -> "ClientAttestationBuilder":
        self._cnf_jwk = public_instance_jwk
        return self

    def confirmation_key(self, instance_key: SigningKeyPair) -> "ClientAttestationBuilder":
        return self.confirmation_jwk(instance_key.public_jwk())

    def issued_at(self, epoch_seconds: int) -> "ClientAttestationBuilder":
        self._issued_at = epoch_seconds
        return self

    def expires_at(self, epoch_seconds: int) -> "ClientAttestationBuilder":
        self._expires_at = epoch_seconds
        return self

    def expires_in(self, seconds: int) -> "ClientAttestationBuilder":
        self._ttl = seconds
        return self

    def authorization_details(self, details: list) -> "ClientAttestationBuilder":
        self._authorization_details = details
        return self

    def workload(self, workload: dict) -> "ClientAttestationBuilder":
        self._workload = workload
        return self

    def build(self) -> str:
        sub = require_text(self._client_id, "client_id")
        if self._cnf_jwk is None:
            raise ValueError("confirmation key (cnf.jwk) is required")
        iat = self._issued_at if self._issued_at is not None else int(time.time())
        exp = self._resolve_expiry(iat)
        claims = {"iss": self._issuer, "sub": sub, "iat": iat, "exp": exp, "cnf": {"jwk": self._cnf_jwk}}
        if self._authorization_details:
            claims["authorization_details"] = self._authorization_details
        if self._workload:
            claims["workload"] = self._workload
        return sign_compact(claims, self._attester_key, ATTESTATION_TYP, embed_jwk=False)

    def _resolve_expiry(self, iat: int) -> int:
        if self._expires_at is not None:
            return self._expires_at
        if self._ttl is not None:
            return iat + self._ttl
        raise ValueError("expiry is required: call expires_at(...) or expires_in(...)")


class PopBuilder:
    """Builds a Client Attestation PoP JWT proving possession of the instance key. Client side of
    ``attest_jwt_client_auth``; mint a fresh one per token request."""

    def __init__(self, instance_key: SigningKeyPair):
        self._instance_key = instance_key
        self._client_id = None
        self._audience = None
        self._challenge = None
        self._jwt_id = None
        self._issued_at = None

    def client_id(self, client_id: str) -> "PopBuilder":
        self._client_id = client_id
        return self

    def audience(self, audience: str) -> "PopBuilder":
        self._audience = audience
        return self

    def challenge(self, challenge) -> "PopBuilder":
        self._challenge = challenge
        return self

    def jwt_id(self, jwt_id: str) -> "PopBuilder":
        self._jwt_id = jwt_id
        return self

    def issued_at(self, epoch_seconds: int) -> "PopBuilder":
        self._issued_at = epoch_seconds
        return self

    def build(self) -> str:
        if not self._audience:
            raise ValueError("audience (aud) is required")
        claims = {
            "aud": self._audience,
            "jti": self._jwt_id or str(uuid.uuid4()),
            "iat": self._issued_at if self._issued_at is not None else int(time.time()),
        }
        if self._client_id:
            claims["iss"] = self._client_id
        if self._challenge:
            claims["challenge"] = self._challenge
        return sign_compact(claims, self._instance_key, POP_TYP, embed_jwk=False)


class DpopProofBuilder:
    """Builds a DPoP proof JWT (RFC 9449) for attestation combined mode
    (``attest_jwt_client_auth_dpop``): the embedded ``jwk`` header MUST be the attestation's ``cnf`` key."""

    def __init__(self, instance_key: SigningKeyPair):
        self._instance_key = instance_key
        self._htm = "POST"
        self._htu = None
        self._nonce = None
        self._jwt_id = None
        self._issued_at = None

    def method(self, htm: str) -> "DpopProofBuilder":
        if htm:
            self._htm = htm
        return self

    def uri(self, htu: str) -> "DpopProofBuilder":
        self._htu = htu
        return self

    def nonce(self, nonce) -> "DpopProofBuilder":
        self._nonce = nonce
        return self

    def jwt_id(self, jwt_id: str) -> "DpopProofBuilder":
        self._jwt_id = jwt_id
        return self

    def issued_at(self, epoch_seconds: int) -> "DpopProofBuilder":
        self._issued_at = epoch_seconds
        return self

    def build(self) -> str:
        if not self._htu:
            raise ValueError("uri (htu) is required")
        claims = {
            "htm": self._htm,
            "htu": self._htu,
            "jti": self._jwt_id or str(uuid.uuid4()),
            "iat": self._issued_at if self._issued_at is not None else int(time.time()),
        }
        if self._nonce:
            claims["nonce"] = self._nonce
        return sign_compact(claims, self._instance_key, DPOP_TYP, embed_jwk=True)
