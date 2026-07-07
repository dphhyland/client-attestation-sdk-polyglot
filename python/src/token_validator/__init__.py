"""Resource-server access-token validation: JWT signature + scope/audience checks, optional RFC 7662
introspection, AS-metadata discovery, and JWKS caching."""
from . import errors
from .config import DEFAULT_ALGORITHMS, IntrospectionConfig, ValidatorConfig
from .discovery import discover
from .result import ValidationResult
from .validator import AccessTokenValidator

__all__ = [
    "AccessTokenValidator",
    "ValidatorConfig",
    "IntrospectionConfig",
    "ValidationResult",
    "DEFAULT_ALGORITHMS",
    "discover",
    "errors",
]
__version__ = "0.1.0"
