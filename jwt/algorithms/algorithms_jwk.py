from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import from_base64url_uint

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256K1,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        EllipticCurve,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateNumbers,
        RSAPublicNumbers,
        rsa_crt_dmp1,
        rsa_crt_dmq1,
        rsa_crt_iqmp,
        rsa_recover_prime_factors,
    )

    _HAS_CRYPTO = True
except ModuleNotFoundError:
    _HAS_CRYPTO = False

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateNumbers,
        RSAPublicNumbers,
    )


def _parse_jwk_json(jwk: str | JWKDict) -> JWKDict:
    """Parse a JWK input that may be a JSON string or a dict.

    Raises InvalidKeyError when the input is neither a JSON string nor a
    dict, or when the JSON cannot be decoded.
    """
    try:
        if isinstance(jwk, str):
            obj: JWKDict = json.loads(jwk)
        elif isinstance(jwk, dict):
            obj = jwk
        else:
            raise ValueError
    except ValueError:
        raise InvalidKeyError("Key is not valid JSON") from None
    return obj


def _serialize_jwk(obj: JWKDict, as_dict: bool) -> JWKDict | str:
    """Return a JWK either as a dict or a JSON-encoded string."""
    if as_dict:
        return obj
    return json.dumps(obj)


if _HAS_CRYPTO:

    # JWK `crv` name -> (cryptography curve class, expected coordinate byte length).
    _JWK_EC_CURVES: dict[str, tuple[type[EllipticCurve], int]] = {
        "P-256": (SECP256R1, 32),
        "P-384": (SECP384R1, 48),
        "P-521": (SECP521R1, 66),
        "secp256k1": (SECP256K1, 32),
    }

    def _resolve_ec_curve_from_jwk(
        crv: str | None, x_len: int, y_len: int
    ) -> EllipticCurve:
        """Map a JWK ``crv`` field to a cryptography curve instance.

        Verifies that the x/y coordinate byte lengths match the curve's
        key size. Raises ``InvalidKeyError`` for unknown curves or wrong
        coordinate lengths.
        """
        if crv not in _JWK_EC_CURVES:
            raise InvalidKeyError(f"Invalid curve: {crv}")
        curve_class, expected_len = _JWK_EC_CURVES[crv]
        if x_len != expected_len or y_len != expected_len:
            raise InvalidKeyError(
                f"Coords should be {expected_len} bytes for curve {crv}"
            )
        return curve_class()

    def _jwk_curve_name(curve: EllipticCurve) -> str:
        """Return the JWK ``crv`` name for a cryptography curve instance."""
        for crv_name, (curve_class, _) in _JWK_EC_CURVES.items():
            if isinstance(curve, curve_class):
                return crv_name
        raise InvalidKeyError(f"Invalid curve: {curve}")

    def _rsa_private_numbers_from_jwk(
        obj: JWKDict, public_numbers: "RSAPublicNumbers"
    ) -> "RSAPrivateNumbers":
        """Build ``RSAPrivateNumbers`` from a JWK dict.

        Handles two cases: the JWK includes the CRT parameters
        (p/q/dp/dq/qi), or only ``d`` is present and the primes have to
        be recovered.
        """
        if "oth" in obj:
            raise InvalidKeyError(
                "Unsupported RSA private key: > 2 primes not supported"
            )

        other_props = ["p", "q", "dp", "dq", "qi"]
        props_found = [prop in obj for prop in other_props]
        any_props_found = any(props_found)

        if any_props_found and not all(props_found):
            raise InvalidKeyError(
                "RSA key must include all parameters if any are present besides d"
            ) from None

        if any_props_found:
            return RSAPrivateNumbers(
                d=from_base64url_uint(obj["d"]),
                p=from_base64url_uint(obj["p"]),
                q=from_base64url_uint(obj["q"]),
                dmp1=from_base64url_uint(obj["dp"]),
                dmq1=from_base64url_uint(obj["dq"]),
                iqmp=from_base64url_uint(obj["qi"]),
                public_numbers=public_numbers,
            )

        d = from_base64url_uint(obj["d"])
        p, q = rsa_recover_prime_factors(public_numbers.n, d, public_numbers.e)
        return RSAPrivateNumbers(
            d=d,
            p=p,
            q=q,
            dmp1=rsa_crt_dmp1(d, p),
            dmq1=rsa_crt_dmq1(d, q),
            iqmp=rsa_crt_iqmp(p, q),
            public_numbers=public_numbers,
        )

else:

    def _resolve_ec_curve_from_jwk(
        crv: str | None, x_len: int, y_len: int
    ) -> Any:
        raise InvalidKeyError("cryptography is required for EC JWK support")

    def _jwk_curve_name(curve: Any) -> str:
        raise InvalidKeyError("cryptography is required for EC JWK support")

    def _rsa_private_numbers_from_jwk(obj: JWKDict, public_numbers: Any) -> Any:
        raise InvalidKeyError("cryptography is required for RSA JWK support")
