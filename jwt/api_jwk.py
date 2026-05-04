from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .types import JWKDict

# JWK `kty` -> default algorithm when ``alg`` is not present and `kty` is
# not curve-dependent. EC and OKP need additional `crv` dispatch and are
# handled in `_infer_algorithm_from_kty`.
_KTY_DEFAULT_ALGORITHM = {
    "RSA": "RS256",
    "oct": "HS256",
}

_EC_CRV_TO_ALGORITHM = {
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES512",
    "secp256k1": "ES256K",
}


class PyJWK:
    def __init__(self, jwk_data: JWKDict, algorithm: str | None = None) -> None:
        """A class that represents a `JSON Web Key <https://www.rfc-editor.org/rfc/rfc7517>`_.

        :param jwk_data: The decoded JWK data.
        :type jwk_data: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :raises InvalidKeyError: If the key type (``kty``) is not found or unsupported, or if the curve (``crv``) is not found or unsupported.
        :raises MissingCryptographyError: If the algorithm requires ``cryptography`` to be installed and it is not available.
        :raises PyJWKError: If unable to find an algorithm for the key.
        """
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError(f"kty is not found: {self._jwk_data}")

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            algorithm = self._infer_algorithm_from_kty(kty)

        if not has_crypto and algorithm in requires_cryptography:
            raise MissingCryptographyError(
                f"{algorithm} requires 'cryptography' to be installed."
            )

        self.algorithm_name = algorithm

        try:
            self.Algorithm = get_default_algorithms()[algorithm]
        except KeyError:
            raise PyJWKError(
                f"Unable to find an algorithm for key: {self._jwk_data}",
            ) from None

        self.key = self.Algorithm.from_jwk(self._jwk_data)

    def _infer_algorithm_from_kty(self, kty: str) -> str:
        """Map (kty, crv) to the JWA algorithm name used to interpret this key.

        Falls back to ``ES256`` when an EC key omits ``crv``.
        """
        crv = self._jwk_data.get("crv", None)
        if kty == "EC":
            if not crv:
                return "ES256"
            try:
                return _EC_CRV_TO_ALGORITHM[crv]
            except KeyError:
                raise InvalidKeyError(f"Unsupported crv: {crv}") from None
        if kty == "OKP":
            if not crv:
                raise InvalidKeyError(f"crv is not found: {self._jwk_data}")
            if crv == "Ed25519":
                return "EdDSA"
            raise InvalidKeyError(f"Unsupported crv: {crv}")
        try:
            return _KTY_DEFAULT_ALGORITHM[kty]
        except KeyError:
            raise InvalidKeyError(f"Unsupported kty: {kty}") from None

    @staticmethod
    def from_dict(obj: JWKDict, algorithm: str | None = None) -> PyJWK:
        """Creates a :class:`PyJWK` object from a JSON-like dictionary.

        :param obj: The JWK data, as a dictionary
        :type obj: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :rtype: PyJWK
        """
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: None = None) -> PyJWK:
        """Create a :class:`PyJWK` object from a JSON string.
        Implicitly calls :meth:`PyJWK.from_dict()`.

        :param str data: The JWK data, as a JSON string.
        :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
        :type algorithm: str or None

        :rtype: PyJWK
        """
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str | None:
        """The `kty` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self) -> str | None:
        """The `kid` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self) -> str | None:
        """The `use` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("use", None)


class PyJWKSet:
    def __init__(self, keys: list[JWKDict]) -> None:
        self.keys: list[PyJWK] = []

        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        for key in keys:
            try:
                self.keys.append(PyJWK(key))
            except PyJWTError as error:
                if isinstance(error, MissingCryptographyError):
                    raise error
                # skip unusable keys
                continue

        if len(self.keys) == 0:
            raise PyJWKSetError(
                "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
            )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PyJWKSet:
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data: str) -> PyJWKSet:
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)

    def __getitem__(self, kid: str) -> PyJWK:
        key = self.find_by_kid(kid)
        if key is None:
            raise KeyError(f"keyset has no key for kid: {kid}")
        return key

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)

    def find_by_kid(self, kid: str) -> PyJWK | None:
        """Return the key matching ``kid``, or ``None`` if no key matches."""
        for key in self.keys:
            if key.key_id == kid:
                return key
        return None
