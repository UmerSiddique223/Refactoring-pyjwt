from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Union, cast, get_args, overload

from .algorithms_base import Algorithm
from .algorithms_crypto import AllowedKeys, AllowedOKPKeys, has_crypto
from .algorithms_jwk import _parse_jwk_json, _serialize_jwk
from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import base64url_decode, base64url_encode, force_bytes

if TYPE_CHECKING:
    from .algorithms_crypto import PrivateKeyTypes, PublicKeyTypes

if has_crypto:
    from .algorithms_crypto import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
        Ed448PrivateKey,
        Ed448PublicKey,
        Encoding,
        InvalidSignature,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )

    class OKPAlgorithm(Algorithm):
        """
        Performs signing and verification operations using EdDSA

        This class requires ``cryptography>=2.6`` to be installed.
        """

        _crypto_key_types = cast(
            tuple[type[AllowedKeys], ...],
            get_args(
                Union[
                    Ed25519PrivateKey,
                    Ed25519PublicKey,
                    Ed448PrivateKey,
                    Ed448PublicKey,
                ]
            ),
        )

        def __init__(self, **kwargs: Any) -> None:
            pass

        def prepare_key(self, key: AllowedOKPKeys | str | bytes) -> AllowedOKPKeys:
            if not isinstance(key, (str, bytes)):
                self.check_crypto_key_type(key)
                return key

            key_str = key.decode("utf-8") if isinstance(key, bytes) else key
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key

            loaded_key: PublicKeyTypes | PrivateKeyTypes
            if "-----BEGIN PUBLIC" in key_str:
                loaded_key = load_pem_public_key(key_bytes)
            elif "-----BEGIN PRIVATE" in key_str:
                loaded_key = load_pem_private_key(key_bytes, password=None)
            elif key_str[0:4] == "ssh-":
                loaded_key = load_ssh_public_key(key_bytes)
            else:
                raise InvalidKeyError("Not a public or private key")

            # Explicit check the key to prevent confusing errors from cryptography
            self.check_crypto_key_type(loaded_key)
            return cast("AllowedOKPKeys", loaded_key)

        def sign(
            self, msg: str | bytes, key: Ed25519PrivateKey | Ed448PrivateKey
        ) -> bytes:
            """
            Sign a message ``msg`` using the EdDSA private key ``key``
            :param str|bytes msg: Message to sign
            :param Ed25519PrivateKey}Ed448PrivateKey key: A :class:`.Ed25519PrivateKey`
                or :class:`.Ed448PrivateKey` isinstance
            :return bytes signature: The signature, as bytes
            """
            msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
            signature: bytes = key.sign(msg_bytes)
            return signature

        def verify(
            self, msg: str | bytes, key: AllowedOKPKeys, sig: str | bytes
        ) -> bool:
            """
            Verify a given ``msg`` against a signature ``sig`` using the EdDSA key ``key``

            :param str|bytes sig: EdDSA signature to check ``msg`` against
            :param str|bytes msg: Message to sign
            :param Ed25519PrivateKey|Ed25519PublicKey|Ed448PrivateKey|Ed448PublicKey key:
                A private or public EdDSA key instance
            :return bool verified: True if signature is valid, False if not.
            """
            try:
                msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
                sig_bytes = sig.encode("utf-8") if isinstance(sig, str) else sig

                public_key = (
                    key.public_key()
                    if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey))
                    else key
                )
                public_key.verify(sig_bytes, msg_bytes)
                return True  # If no exception was raised, the signature is valid.
            except InvalidSignature:
                return False

        @overload
        @staticmethod
        def to_jwk(key: AllowedOKPKeys, as_dict: Literal[True]) -> JWKDict: ...

        @overload
        @staticmethod
        def to_jwk(key: AllowedOKPKeys, as_dict: Literal[False] = False) -> str: ...

        @staticmethod
        def to_jwk(key: AllowedOKPKeys, as_dict: bool = False) -> JWKDict | str:
            if isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
                x = key.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )
                crv = "Ed25519" if isinstance(key, Ed25519PublicKey) else "Ed448"

                obj = {
                    "x": base64url_encode(force_bytes(x)).decode(),
                    "kty": "OKP",
                    "crv": crv,
                }

                return _serialize_jwk(obj, as_dict)

            if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
                d = key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                )

                x = key.public_key().public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )

                crv = "Ed25519" if isinstance(key, Ed25519PrivateKey) else "Ed448"
                obj = {
                    "x": base64url_encode(force_bytes(x)).decode(),
                    "d": base64url_encode(force_bytes(d)).decode(),
                    "kty": "OKP",
                    "crv": crv,
                }

                return _serialize_jwk(obj, as_dict)

            raise InvalidKeyError("Not a public or private key")

        @staticmethod
        def from_jwk(jwk: str | JWKDict) -> AllowedOKPKeys:
            obj = _parse_jwk_json(jwk)

            if obj.get("kty") != "OKP":
                raise InvalidKeyError("Not an Octet Key Pair")

            curve = obj.get("crv")
            if curve != "Ed25519" and curve != "Ed448":
                raise InvalidKeyError(f"Invalid curve: {curve}")

            if "x" not in obj:
                raise InvalidKeyError('OKP should have "x" parameter')
            x = base64url_decode(obj.get("x"))

            try:
                if "d" not in obj:
                    if curve == "Ed25519":
                        return Ed25519PublicKey.from_public_bytes(x)
                    return Ed448PublicKey.from_public_bytes(x)
                d = base64url_decode(obj.get("d"))
                if curve == "Ed25519":
                    return Ed25519PrivateKey.from_private_bytes(d)
                return Ed448PrivateKey.from_private_bytes(d)
            except ValueError as err:
                raise InvalidKeyError("Invalid key parameter") from err
