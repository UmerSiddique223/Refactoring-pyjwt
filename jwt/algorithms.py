from __future__ import annotations

from .algorithms.algorithms_base import Algorithm
from .algorithms.algorithms_crypto import (
    AllowedECKeys,
    AllowedKeys,
    AllowedOKPKeys,
    AllowedPrivateKeys,
    AllowedPublicKeys,
    AllowedRSAKeys,
    has_crypto,
)
from .algorithms.algorithms_hmac import HMACAlgorithm
from .algorithms.algorithms_none import NoneAlgorithm

requires_cryptography = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES521",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
}

if has_crypto:
    from .algorithms.algorithms_crypto import SECP256K1, SECP256R1, SECP384R1, SECP521R1
    from .algorithms.algorithms_ec import ECAlgorithm
    from .algorithms.algorithms_okp import OKPAlgorithm
    from .algorithms.algorithms_rsa import RSAAlgorithm, RSAPSSAlgorithm


def get_default_algorithms() -> dict[str, Algorithm]:
    """
    Returns the algorithms that are implemented by the library.
    """
    default_algorithms: dict[str, Algorithm] = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm(HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm(HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm(HMACAlgorithm.SHA512),
    }

    if has_crypto:
        default_algorithms.update(
            {
                "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
                "RS384": RSAAlgorithm(RSAAlgorithm.SHA384),
                "RS512": RSAAlgorithm(RSAAlgorithm.SHA512),
                "ES256": ECAlgorithm(ECAlgorithm.SHA256, SECP256R1),
                "ES256K": ECAlgorithm(ECAlgorithm.SHA256, SECP256K1),
                "ES384": ECAlgorithm(ECAlgorithm.SHA384, SECP384R1),
                "ES521": ECAlgorithm(ECAlgorithm.SHA512, SECP521R1),
                "ES512": ECAlgorithm(
                    ECAlgorithm.SHA512, SECP521R1
                ),  # Backward compat for #219 fix
                "PS256": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                "PS384": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                "PS512": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                "EdDSA": OKPAlgorithm(),
            }
        )

    return default_algorithms
