"""Client-side builder SDK for OAuth Attestation-Based Client Authentication."""
from .builders import ClientAttestationBuilder, DpopProofBuilder, PopBuilder
from .credential import (
    ATTESTATION_HEADER,
    DPOP_HEADER,
    POP_HEADER,
    ClientAttestationCredential,
)
from .keys import SigningKeyPair
from .signer import JwsSigner, OpenBaoTransitSigner
from .spiffe import (
    JwtSvid,
    RegistrationEntry,
    SpiffeAgent,
    parse_spiffe_id,
    to_workload_claim,
    verify_jwt_svid,
)

__all__ = [
    "SigningKeyPair",
    "ClientAttestationBuilder",
    "PopBuilder",
    "DpopProofBuilder",
    "ClientAttestationCredential",
    "JwsSigner",
    "OpenBaoTransitSigner",
    "ATTESTATION_HEADER",
    "POP_HEADER",
    "DPOP_HEADER",
    "SpiffeAgent",
    "RegistrationEntry",
    "JwtSvid",
    "verify_jwt_svid",
    "to_workload_claim",
    "parse_spiffe_id",
]
__version__ = "0.1.0"
