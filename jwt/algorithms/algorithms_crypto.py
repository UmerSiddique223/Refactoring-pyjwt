from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Union

try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256K1,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        EllipticCurve,
        EllipticCurvePrivateKey,
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicKey,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey,
        Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
        RSAPublicNumbers,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )

    if sys.version_info >= (3, 10):
        from typing import TypeAlias
    else:
        # Python 3.9 and lower
        from typing_extensions import TypeAlias

    # Type aliases for convenience in algorithms method signatures
    AllowedRSAKeys: TypeAlias = Union[RSAPrivateKey, RSAPublicKey]
    AllowedECKeys: TypeAlias = Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]
    AllowedOKPKeys: TypeAlias = Union[
        Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey
    ]
    AllowedKeys: TypeAlias = Union[AllowedRSAKeys, AllowedECKeys, AllowedOKPKeys]
    #: Type alias for allowed ``cryptography`` private keys (requires ``cryptography`` to be installed)
    AllowedPrivateKeys: TypeAlias = Union[
        RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey
    ]
    #: Type alias for allowed ``cryptography`` public keys (requires ``cryptography`` to be installed)
    AllowedPublicKeys: TypeAlias = Union[
        RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey
    ]

    if TYPE_CHECKING or bool(os.getenv("SPHINX_BUILD", "")):
        from cryptography.hazmat.primitives.asymmetric.types import (
            PrivateKeyTypes,
            PublicKeyTypes,
        )

    has_crypto = True
except ModuleNotFoundError:
    if sys.version_info >= (3, 11):
        from typing import Never
    else:
        from typing_extensions import Never

    AllowedRSAKeys = Never  # type: ignore[misc]
    AllowedECKeys = Never  # type: ignore[misc]
    AllowedOKPKeys = Never  # type: ignore[misc]
    AllowedKeys = Never  # type: ignore[misc]
    AllowedPrivateKeys = Never  # type: ignore[misc]
    AllowedPublicKeys = Never  # type: ignore[misc]
    has_crypto = False
