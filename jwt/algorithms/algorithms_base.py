from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Literal, overload

from .algorithms_crypto import AllowedKeys, has_crypto
from ..exceptions import InvalidKeyError
from ..types import JWKDict

if has_crypto:
    from .algorithms_crypto import default_backend, hashes

if TYPE_CHECKING:
    from .algorithms_crypto import PrivateKeyTypes, PublicKeyTypes


class Algorithm(ABC):
    """
    The interface for an algorithm used to sign and verify tokens.
    """

    # pyjwt-964: Validate to ensure the key passed in was decoded to the correct cryptography key family
    _crypto_key_types: tuple[type[AllowedKeys], ...] | None = None

    def compute_hash_digest(self, bytestr: bytes) -> bytes:
        """
        Compute a hash digest using the specified algorithm's hash algorithm.

        If there is no hash algorithm, raises a NotImplementedError.
        """
        # lookup self.hash_alg if defined in a way that mypy can understand
        hash_alg = getattr(self, "hash_alg", None)
        if hash_alg is None:
            raise NotImplementedError

        if (
            has_crypto
            and isinstance(hash_alg, type)
            and issubclass(hash_alg, hashes.HashAlgorithm)
        ):
            digest = hashes.Hash(hash_alg(), backend=default_backend())
            digest.update(bytestr)
            return bytes(digest.finalize())
        else:
            return bytes(hash_alg(bytestr).digest())

    def check_crypto_key_type(self, key: PublicKeyTypes | PrivateKeyTypes) -> None:
        """Check that the key belongs to the right cryptographic family.

        Note that this method only works when ``cryptography`` is installed.

        :param key: Potentially a cryptography key
        :type key: :py:data:`PublicKeyTypes <cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes>` | :py:data:`PrivateKeyTypes <cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes>`
        :raises ValueError: if ``cryptography`` is not installed, or this method is called by a non-cryptography algorithm
        :raises InvalidKeyError: if the key doesn't match the expected key classes
        """
        if not has_crypto or self._crypto_key_types is None:
            raise ValueError(
                "This method requires the cryptography library, and should only be used by cryptography-based algorithms."
            )

        if not isinstance(key, self._crypto_key_types):
            valid_classes = (cls.__name__ for cls in self._crypto_key_types)
            actual_class = key.__class__.__name__
            self_class = self.__class__.__name__
            raise InvalidKeyError(
                f"Expected one of {valid_classes}, got: {actual_class}. Invalid Key type for {self_class}"
            )

    @abstractmethod
    def prepare_key(self, key: Any) -> Any:
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes:
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """

    @abstractmethod
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.
        """

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: Literal[True]) -> JWKDict: ...  # pragma: no cover

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(
        key_obj: Any, as_dict: Literal[False] = False
    ) -> str: ...  # pragma: no cover

    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str:
        """
        Serializes a given key into a JWK
        """

    @staticmethod
    @abstractmethod
    def from_jwk(jwk: str | JWKDict) -> Any:
        """
        Deserializes a given key from JWK back into a key object
        """

    def check_key_length(self, key: Any) -> str | None:
        """
        Return a warning message if the key is below the minimum
        recommended length for this algorithm, or None if adequate.
        """
        return None
