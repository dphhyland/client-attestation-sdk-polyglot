"""Client-side builder SDK for OAuth Attestation-Based Client Authentication."""
from .builders import ClientAttestationBuilder, DpopProofBuilder, PopBuilder
from .credential import (
    ATTESTATION_HEADER,
    DPOP_HEADER,
    POP_HEADER,
    ClientAttestationCredential,
)
from .keys import SigningKeyPair

__all__ = [
    "SigningKeyPair",
    "ClientAttestationBuilder",
    "PopBuilder",
    "DpopProofBuilder",
    "ClientAttestationCredential",
    "ATTESTATION_HEADER",
    "POP_HEADER",
    "DPOP_HEADER",
]
__version__ = "0.1.0"
