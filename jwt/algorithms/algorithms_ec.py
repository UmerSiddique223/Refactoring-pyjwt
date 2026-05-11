from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, Literal, Union, cast, get_args, overload

from .algorithms_base import Algorithm
from .algorithms_crypto import AllowedECKeys, AllowedKeys, has_crypto
from .algorithms_jwk import _jwk_curve_name, _parse_jwk_json, _resolve_ec_curve_from_jwk, _serialize_jwk
from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import (
    base64url_decode,
    der_to_raw_signature,
    force_bytes,
    raw_to_der_signature,
    to_base64url_uint,
)

if TYPE_CHECKING:
    from .algorithms_crypto import PrivateKeyTypes, PublicKeyTypes

if has_crypto:
    from .algorithms_crypto import (
        ECDSA,
        EllipticCurve,
        EllipticCurvePrivateKey,
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicKey,
        EllipticCurvePublicNumbers,
        InvalidSignature,
        hashes,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )

    class ECAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        ECDSA and the specified hash function
        """

        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        _crypto_key_types = cast(
            tuple[type[AllowedKeys], ...],
            get_args(Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]),
        )

        def __init__(
            self,
            hash_alg: type[hashes.HashAlgorithm],
            expected_curve: type[EllipticCurve] | None = None,
        ) -> None:
            self.hash_alg = hash_alg
            self.expected_curve = expected_curve

        def _validate_curve(self, key: AllowedECKeys) -> None:
            """Validate that the key's curve matches the expected curve."""
            if self.expected_curve is None:
                return

            if not isinstance(key.curve, self.expected_curve):
                raise InvalidKeyError(
                    f"The key's curve '{key.curve.name}' does not match the expected "
                    f"curve '{self.expected_curve.name}' for this algorithm"
                )

        def prepare_key(self, key: AllowedECKeys | str | bytes) -> AllowedECKeys:
            if isinstance(key, self._crypto_key_types):
                ec_key = cast(AllowedECKeys, key)
                self._validate_curve(ec_key)
                return ec_key

            if not isinstance(key, (bytes, str)):
                raise TypeError("Expecting a PEM-formatted key.")

            key_bytes = force_bytes(key)

            # Attempt to load key. We don't know if it's
            # a Signing Key or a Verifying Key, so we try
            # the Verifying Key first.
            try:
                if key_bytes.startswith(b"ecdsa-sha2-"):
                    public_key: PublicKeyTypes = load_ssh_public_key(key_bytes)
                else:
                    public_key = load_pem_public_key(key_bytes)

                # Explicit check the key to prevent confusing errors from cryptography
                self.check_crypto_key_type(public_key)
                ec_public_key = cast(EllipticCurvePublicKey, public_key)
                self._validate_curve(ec_public_key)
                return ec_public_key
            except ValueError:
                private_key = load_pem_private_key(key_bytes, password=None)
                self.check_crypto_key_type(private_key)
                ec_private_key = cast(EllipticCurvePrivateKey, private_key)
                self._validate_curve(ec_private_key)
                return ec_private_key

        def sign(self, msg: bytes, key: EllipticCurvePrivateKey) -> bytes:
            der_sig = key.sign(msg, ECDSA(self.hash_alg()))

            return der_to_raw_signature(der_sig, key.curve)

        def verify(self, msg: bytes, key: AllowedECKeys, sig: bytes) -> bool:
            try:
                der_sig = raw_to_der_signature(sig, key.curve)
            except ValueError:
                return False

            try:
                public_key = (
                    key.public_key()
                    if isinstance(key, EllipticCurvePrivateKey)
                    else key
                )
                public_key.verify(der_sig, msg, ECDSA(self.hash_alg()))
                return True
            except InvalidSignature:
                return False

        @overload
        @staticmethod
        def to_jwk(key_obj: AllowedECKeys, as_dict: Literal[True]) -> JWKDict: ...

        @overload
        @staticmethod
        def to_jwk(key_obj: AllowedECKeys, as_dict: Literal[False] = False) -> str: ...

        @staticmethod
        def to_jwk(key_obj: AllowedECKeys, as_dict: bool = False) -> JWKDict | str:
            if isinstance(key_obj, EllipticCurvePrivateKey):
                public_numbers = key_obj.public_key().public_numbers()
            elif isinstance(key_obj, EllipticCurvePublicKey):
                public_numbers = key_obj.public_numbers()
            else:
                raise InvalidKeyError("Not a public or private key")

            obj: dict[str, Any] = {
                "kty": "EC",
                "crv": _jwk_curve_name(key_obj.curve),
                "x": to_base64url_uint(
                    public_numbers.x,
                    bit_length=key_obj.curve.key_size,
                ).decode(),
                "y": to_base64url_uint(
                    public_numbers.y,
                    bit_length=key_obj.curve.key_size,
                ).decode(),
            }

            if isinstance(key_obj, EllipticCurvePrivateKey):
                obj["d"] = to_base64url_uint(
                    key_obj.private_numbers().private_value,
                    bit_length=key_obj.curve.key_size,
                ).decode()

            return _serialize_jwk(obj, as_dict)

        @staticmethod
        def from_jwk(jwk: str | JWKDict) -> AllowedECKeys:
            obj = _parse_jwk_json(jwk)

            if obj.get("kty") != "EC":
                raise InvalidKeyError("Not an Elliptic curve key") from None

            if "x" not in obj or "y" not in obj:
                raise InvalidKeyError("Not an Elliptic curve key") from None

            x = base64url_decode(obj.get("x"))
            y = base64url_decode(obj.get("y"))

            curve_obj = _resolve_ec_curve_from_jwk(obj.get("crv"), len(x), len(y))

            public_numbers = EllipticCurvePublicNumbers(
                x=int.from_bytes(x, byteorder="big"),
                y=int.from_bytes(y, byteorder="big"),
                curve=curve_obj,
            )

            if "d" not in obj:
                return public_numbers.public_key()

            d = base64url_decode(obj.get("d"))
            if len(d) != len(x):
                raise InvalidKeyError(
                    "D should be {} bytes for curve {}", len(x), obj.get("crv")
                )

            return EllipticCurvePrivateNumbers(
                int.from_bytes(d, byteorder="big"), public_numbers
            ).private_key()
