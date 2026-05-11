from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, Literal, Union, cast, get_args, overload

from .algorithms_base import Algorithm
from .algorithms_crypto import AllowedKeys, AllowedRSAKeys, has_crypto
from .algorithms_jwk import _parse_jwk_json, _rsa_private_numbers_from_jwk, _serialize_jwk
from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import force_bytes, from_base64url_uint, to_base64url_uint

if TYPE_CHECKING:
    from .algorithms_crypto import PrivateKeyTypes, PublicKeyTypes

if has_crypto:
    from .algorithms_crypto import (
        InvalidSignature,
        RSAPrivateKey,
        RSAPublicKey,
        RSAPublicNumbers,
        UnsupportedAlgorithm,
        hashes,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
        padding,
    )

    class RSAAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        RSASSA-PKCS-v1_5 and the specified hash function.
        """

        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        _crypto_key_types = cast(
            tuple[type[AllowedKeys], ...],
            get_args(Union[RSAPrivateKey, RSAPublicKey]),
        )
        _MIN_KEY_SIZE: ClassVar[int] = 2048

        def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
            self.hash_alg = hash_alg

        def check_key_length(self, key: AllowedRSAKeys) -> str | None:
            if key.key_size < self._MIN_KEY_SIZE:
                return (
                    f"The RSA key is {key.key_size} bits long, which is below "
                    f"the minimum recommended size of {self._MIN_KEY_SIZE} bits. "
                    f"See NIST SP 800-131A."
                )
            return None

        def prepare_key(self, key: AllowedRSAKeys | str | bytes) -> AllowedRSAKeys:
            if isinstance(key, self._crypto_key_types):
                return cast(AllowedRSAKeys, key)

            if not isinstance(key, (bytes, str)):
                raise TypeError("Expecting a PEM-formatted key.")

            key_bytes = force_bytes(key)

            try:
                if key_bytes.startswith(b"ssh-rsa"):
                    public_key: PublicKeyTypes = load_ssh_public_key(key_bytes)
                    self.check_crypto_key_type(public_key)
                    return cast(RSAPublicKey, public_key)
                else:
                    private_key: PrivateKeyTypes = load_pem_private_key(
                        key_bytes, password=None
                    )
                    self.check_crypto_key_type(private_key)
                    return cast(RSAPrivateKey, private_key)
            except ValueError:
                try:
                    public_key = load_pem_public_key(key_bytes)
                    self.check_crypto_key_type(public_key)
                    return cast(RSAPublicKey, public_key)
                except (ValueError, UnsupportedAlgorithm):
                    raise InvalidKeyError(
                        "Could not parse the provided public key."
                    ) from None

        @overload
        @staticmethod
        def to_jwk(key_obj: AllowedRSAKeys, as_dict: Literal[True]) -> JWKDict: ...

        @overload
        @staticmethod
        def to_jwk(key_obj: AllowedRSAKeys, as_dict: Literal[False] = False) -> str: ...

        @staticmethod
        def to_jwk(key_obj: AllowedRSAKeys, as_dict: bool = False) -> JWKDict | str:
            obj: dict[str, Any]

            if hasattr(key_obj, "private_numbers"):
                # Private key
                numbers = key_obj.private_numbers()

                obj = {
                    "kty": "RSA",
                    "key_ops": ["sign"],
                    "n": to_base64url_uint(numbers.public_numbers.n).decode(),
                    "e": to_base64url_uint(numbers.public_numbers.e).decode(),
                    "d": to_base64url_uint(numbers.d).decode(),
                    "p": to_base64url_uint(numbers.p).decode(),
                    "q": to_base64url_uint(numbers.q).decode(),
                    "dp": to_base64url_uint(numbers.dmp1).decode(),
                    "dq": to_base64url_uint(numbers.dmq1).decode(),
                    "qi": to_base64url_uint(numbers.iqmp).decode(),
                }

            elif hasattr(key_obj, "verify"):
                # Public key
                numbers = key_obj.public_numbers()

                obj = {
                    "kty": "RSA",
                    "key_ops": ["verify"],
                    "n": to_base64url_uint(numbers.n).decode(),
                    "e": to_base64url_uint(numbers.e).decode(),
                }
            else:
                raise InvalidKeyError("Not a public or private key")

            return _serialize_jwk(obj, as_dict)

        @staticmethod
        def from_jwk(jwk: str | JWKDict) -> AllowedRSAKeys:
            obj = _parse_jwk_json(jwk)

            if obj.get("kty") != "RSA":
                raise InvalidKeyError("Not an RSA key") from None

            if "d" in obj and "e" in obj and "n" in obj:
                # Private key
                public_numbers = RSAPublicNumbers(
                    from_base64url_uint(obj["e"]),
                    from_base64url_uint(obj["n"]),
                )
                numbers = _rsa_private_numbers_from_jwk(obj, public_numbers)
                return numbers.private_key()
            elif "n" in obj and "e" in obj:
                # Public key
                return RSAPublicNumbers(
                    from_base64url_uint(obj["e"]),
                    from_base64url_uint(obj["n"]),
                ).public_key()
            else:
                raise InvalidKeyError("Not a public or private key")

        def sign(self, msg: bytes, key: RSAPrivateKey) -> bytes:
            signature: bytes = key.sign(msg, padding.PKCS1v15(), self.hash_alg())
            return signature

        def verify(self, msg: bytes, key: RSAPublicKey, sig: bytes) -> bool:
            try:
                key.verify(sig, msg, padding.PKCS1v15(), self.hash_alg())
                return True
            except InvalidSignature:
                return False

    class RSAPSSAlgorithm(RSAAlgorithm):
        """
        Performs a signature using RSASSA-PSS with MGF1
        """

        def sign(self, msg: bytes, key: RSAPrivateKey) -> bytes:
            signature: bytes = key.sign(
                msg,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_alg()),
                    salt_length=self.hash_alg().digest_size,
                ),
                self.hash_alg(),
            )
            return signature

        def verify(self, msg: bytes, key: RSAPublicKey, sig: bytes) -> bool:
            try:
                key.verify(
                    sig,
                    msg,
                    padding.PSS(
                        mgf=padding.MGF1(self.hash_alg()),
                        salt_length=self.hash_alg().digest_size,
                    ),
                    self.hash_alg(),
                )
                return True
            except InvalidSignature:
                return False
