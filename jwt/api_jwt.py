from __future__ import annotations

import json
import os
import warnings
from calendar import timegm
from collections.abc import Container, Iterable, Sequence
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Union, cast

from .api_jws import PyJWS, _ALGORITHM_UNSET, _jws_global_obj
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidSubjectError,
    MissingRequiredClaimError,
)
from .warnings import warn_removed_kwargs

if TYPE_CHECKING or bool(os.getenv("SPHINX_BUILD", "")):
    import sys

    if sys.version_info >= (3, 10):
        from typing import TypeAlias
    else:
        # Python 3.9 and lower
        from typing_extensions import TypeAlias

    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .api_jwk import PyJWK
    from .types import FullOptions, Options, SigOptions

    AllowedPrivateKeyTypes: TypeAlias = Union[AllowedPrivateKeys, PyJWK, str, bytes]
    AllowedPublicKeyTypes: TypeAlias = Union[AllowedPublicKeys, PyJWK, str, bytes]


class PyJWT:
    def __init__(self, options: Options | None = None) -> None:
        self.options: FullOptions
        self.options = self._get_default_options()
        if options is not None:
            self.options = self._merge_options(options)

        self._jws = PyJWS(options=self._get_sig_options())

    @staticmethod
    def _get_default_options() -> FullOptions:
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_sub": True,
            "verify_jti": True,
            "require": [],
            "strict_aud": False,
            "enforce_minimum_key_length": False,
        }

    def _get_sig_options(self) -> SigOptions:
        return {
            "verify_signature": self.options["verify_signature"],
            "enforce_minimum_key_length": self.options.get(
                "enforce_minimum_key_length", False
            ),
        }

    # When the caller turns off `verify_signature`, every other verify_* flag
    # defaults to False (rather than the True from `_get_default_options`).
    # The caller's explicit values still win — these are only the defaults.
    _UNVERIFIED_DEFAULTS: dict[str, bool] = {
        "verify_exp": False,
        "verify_nbf": False,
        "verify_iat": False,
        "verify_aud": False,
        "verify_iss": False,
        "verify_sub": False,
        "verify_jti": False,
    }

    @staticmethod
    def _warn_legacy_verify_mismatch(
        verify: bool | None, verify_signature: bool
    ) -> None:
        """Warn when the deprecated ``verify`` kwarg disagrees with options.

        ``stacklevel=3`` points the warning at the original caller of the
        public API (caller -> public method -> here).
        """
        if verify is not None and verify != verify_signature:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                category=DeprecationWarning,
                stacklevel=3,
            )

    def _merge_options(self, options: Options | None = None) -> FullOptions:
        if options is None:
            return self.options

        if not options.get("verify_signature", True):
            # Layer the unverified-defaults under the caller's options so the
            # caller's explicit values still take precedence. The caller's
            # dict is not mutated.
            return {**self.options, **self._UNVERIFIED_DEFAULTS, **options}
        return {**self.options, **options}

    def encode(
        self,
        payload: dict[str, Any],
        key: AllowedPrivateKeyTypes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        """Encode the ``payload`` as JSON Web Token.

        :param payload: JWT claims, e.g. ``dict(iss=..., aud=..., sub=...)``
        :type payload: dict[str, typing.Any]
        :param key: a key suitable for the chosen algorithm:

            * for **asymmetric algorithms**: PEM-formatted private key, a multiline string
            * for **symmetric algorithms**: plain string, sufficiently long for security

        :type key: str or bytes or PyJWK or :py:class:`jwt.algorithms.AllowedPrivateKeys`
        :param algorithm: algorithm to sign the token with, e.g. ``"ES256"``.
            If ``headers`` includes ``alg``, it will be preferred to this parameter.
            If ``key`` is a :class:`PyJWK` object, by default the key algorithm will be used.
        :type algorithm: str or None
        :param headers: additional JWT header fields, e.g. ``dict(kid="my-key-id")``.
        :type headers: dict[str, typing.Any] or None
        :param json_encoder: custom JSON encoder for ``payload`` and ``headers``
        :type json_encoder: json.JSONEncoder or None

        :rtype: str
        :returns: a JSON Web Token

        :raises TypeError: if ``payload`` is not a ``dict``
        """
        payload = self._prepare_payload_claims(payload)

        json_payload = self._encode_payload(
            payload,
            headers=headers,
            json_encoder=json_encoder,
        )

        return self._jws.encode(
            json_payload,
            key,
            algorithm,
            headers,
            json_encoder,
            sort_headers=sort_headers,
        )

    def _prepare_payload_claims(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalize registered claims before JSON-encoding.

        Returns a shallow copy with datetime values in the time-format claims
        (exp/iat/nbf) converted to integer epoch seconds.
        """
        if not isinstance(payload, dict):
            raise TypeError(
                "Expecting a dict object, as JWT only supports "
                "JSON objects as payloads."
            )

        payload = payload.copy()
        for time_claim in ("exp", "iat", "nbf"):
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())

        # Issue #1039, iss being set to non-string
        if "iss" in payload and not isinstance(payload["iss"], str):
            raise TypeError("Issuer (iss) must be a string.")

        return payload

    def _encode_payload(
        self,
        payload: dict[str, Any],
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
    ) -> bytes:
        """
        Encode a given payload to the bytes to be signed.

        This method is intended to be overridden by subclasses that need to
        encode the payload in a different way, e.g. compress the payload.
        """
        return json.dumps(
            payload,
            separators=(",", ":"),
            cls=json_encoder,
        ).encode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeyTypes = "",
        algorithms: Sequence[str] | None = None,
        options: Options | None = None,
        # deprecated arg, remove in pyjwt3
        verify: bool | None = None,
        # could be used as passthrough to api_jws, consider removal in pyjwt3
        detached_payload: bytes | None = None,
        # passthrough arguments to _validate_claims
        # consider putting in options
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
        # kwargs
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Identical to ``jwt.decode`` except for return value which is a dictionary containing the token header (JOSE Header),
        the token payload (JWT Payload), and token signature (JWT Signature) on the keys "header", "payload",
        and "signature" respectively.

        :param jwt: the token to be decoded
        :type jwt: str or bytes
        :param key: the key suitable for the allowed algorithm
        :type key: str or bytes or PyJWK or :py:class:`jwt.algorithms.AllowedPublicKeys`

        :param algorithms: allowed algorithms, e.g. ``["ES256"]``

            .. warning::

               Do **not** compute the ``algorithms`` parameter based on
               the ``alg`` from the token itself, or on any other data
               that an attacker may be able to influence, as that might
               expose you to various vulnerabilities (see `RFC 8725 §2.1
               <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
               either hard-code a fixed value for ``algorithms``, or
               configure it in the same place you configure the
               ``key``. Make sure not to mix symmetric and asymmetric
               algorithms that interpret the ``key`` in different ways
               (e.g. HS\\* and RS\\*).
        :type algorithms: typing.Sequence[str] or None

        :param jwt.types.Options options: extended decoding and validation options
            Refer to :py:class:`jwt.types.Options` for more information.

        :param audience: optional, the value for ``verify_aud`` check
        :type audience: str or typing.Iterable[str] or None
        :param issuer: optional, the value for ``verify_iss`` check
        :type issuer: str or typing.Container[str] or None
        :param leeway: a time margin in seconds for the expiration check
        :type leeway: float or datetime.timedelta
        :rtype: dict[str, typing.Any]
        :returns: Decoded JWT with the JOSE Header on the key ``header``, the JWS
         Payload on the key ``payload``, and the JWS Signature on the key ``signature``.
        """
        warn_removed_kwargs(kwargs, "decode_complete")

        if options is None:
            verify_signature = True
        else:
            verify_signature = options.get("verify_signature", True)

        self._warn_legacy_verify_mismatch(verify, verify_signature)

        merged_options = self._merge_options(options)

        sig_options: SigOptions = {
            "verify_signature": verify_signature,
        }
        decoded = self._jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=sig_options,
            detached_payload=detached_payload,
        )

        payload = self._decode_payload(decoded)

        self._validate_claims(
            payload,
            merged_options,
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            subject=subject,
        )

        decoded["payload"] = payload
        return decoded

    def _decode_payload(self, decoded: dict[str, Any]) -> dict[str, Any]:
        """
        Decode the payload from a JWS dictionary (payload, signature, header).

        This method is intended to be overridden by subclasses that need to
        decode the payload in a different way, e.g. decompress compressed
        payloads.
        """
        try:
            payload: dict[str, Any] = json.loads(decoded["payload"])
        except ValueError as e:
            raise DecodeError(f"Invalid payload string: {e}") from e
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")
        return payload

    def decode(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: Options | None = None,
        # deprecated arg, remove in pyjwt3
        verify: bool | None = None,
        # could be used as passthrough to api_jws, consider removal in pyjwt3
        detached_payload: bytes | None = None,
        # passthrough arguments to _validate_claims
        # consider putting in options
        audience: str | Iterable[str] | None = None,
        subject: str | None = None,
        issuer: str | Container[str] | None = None,
        leeway: float | timedelta = 0,
        # kwargs
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Verify the ``jwt`` token signature and return the token claims.

        :param jwt: the token to be decoded
        :type jwt: str or bytes
        :param key: the key suitable for the allowed algorithm
        :type key: str or bytes or PyJWK or :py:class:`jwt.algorithms.AllowedPublicKeys`

        :param algorithms: allowed algorithms, e.g. ``["ES256"]``
            If ``key`` is a :class:`PyJWK` object, allowed algorithms will default to the key algorithm.

            .. warning::

               Do **not** compute the ``algorithms`` parameter based on
               the ``alg`` from the token itself, or on any other data
               that an attacker may be able to influence, as that might
               expose you to various vulnerabilities (see `RFC 8725 §2.1
               <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
               either hard-code a fixed value for ``algorithms``, or
               configure it in the same place you configure the
               ``key``. Make sure not to mix symmetric and asymmetric
               algorithms that interpret the ``key`` in different ways
               (e.g. HS\\* and RS\\*).
        :type algorithms: typing.Sequence[str] or None

        :param jwt.types.Options options: extended decoding and validation options
            Refer to :py:class:`jwt.types.Options` for more information.

        :param audience: optional, the value for ``verify_aud`` check
        :type audience: str or typing.Iterable[str] or None
        :param subject: optional, the value for ``verify_sub`` check
        :type subject: str or None
        :param issuer: optional, the value for ``verify_iss`` check
        :type issuer: str or typing.Container[str] or None
        :param leeway: a time margin in seconds for the expiration check
        :type leeway: float or datetime.timedelta
        :rtype: dict[str, typing.Any]
        :returns: the JWT claims
        """
        warn_removed_kwargs(kwargs, "decode")
        decoded = self.decode_complete(
            jwt,
            key,
            algorithms,
            options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            subject=subject,
            issuer=issuer,
            leeway=leeway,
        )
        return cast(dict[str, Any], decoded["payload"])

    def _validate_claims(
        self,
        payload: dict[str, Any],
        options: FullOptions,
        audience: Iterable[str] | str | None = None,
        issuer: Container[str] | str | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
    ) -> None:
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if audience is not None and not isinstance(audience, (str, Iterable)):
            raise TypeError("audience must be a string, iterable or None")

        self._validate_required_claims(payload, options["require"])

        now = datetime.now(tz=timezone.utc).timestamp()

        if "iat" in payload and options["verify_iat"]:
            self._validate_iat(payload, now, leeway)

        if "nbf" in payload and options["verify_nbf"]:
            self._validate_nbf(payload, now, leeway)

        if "exp" in payload and options["verify_exp"]:
            self._validate_exp(payload, now, leeway)

        if options["verify_iss"]:
            self._validate_iss(payload, issuer)

        if options["verify_aud"]:
            self._validate_aud(
                payload, audience, strict=options.get("strict_aud", False)
            )

        if options["verify_sub"]:
            self._validate_sub(payload, subject)

        if options["verify_jti"]:
            self._validate_jti(payload)

    def _validate_required_claims(
        self,
        payload: dict[str, Any],
        claims: Iterable[str],
    ) -> None:
        for claim in claims:
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    def _validate_sub(
        self, payload: dict[str, Any], subject: str | None = None
    ) -> None:
        """
        Checks whether "sub" if in the payload is valid or not.
        This is an Optional claim

        :param payload(dict): The payload which needs to be validated
        :param subject(str): The subject of the token
        """

        if "sub" not in payload:
            return

        if not isinstance(payload["sub"], str):
            raise InvalidSubjectError("Subject must be a string")

        if subject is not None:
            if payload.get("sub") != subject:
                raise InvalidSubjectError("Invalid subject")

    def _validate_jti(self, payload: dict[str, Any]) -> None:
        """
        Checks whether "jti" if in the payload is valid or not
        This is an Optional claim

        :param payload(dict): The payload which needs to be validated
        """

        if "jti" not in payload:
            return

        if not isinstance(payload.get("jti"), str):
            raise InvalidJTIError("JWT ID must be a string")

    # (exception class, error message) per time claim, used by `_coerce_int_claim`
    # when the claim value cannot be converted to int.
    _INT_CLAIM_ERRORS: dict[str, tuple[type[Exception], str]] = {
        "iat": (InvalidIssuedAtError, "Issued At claim (iat) must be an integer."),
        "nbf": (DecodeError, "Not Before claim (nbf) must be an integer."),
        "exp": (DecodeError, "Expiration Time claim (exp) must be an integer."),
    }

    def _coerce_int_claim(self, payload: dict[str, Any], claim: str) -> int:
        """Coerce a numeric claim to int, raising the claim-specific error class."""
        try:
            return int(payload[claim])
        except ValueError:
            error_cls, message = self._INT_CLAIM_ERRORS[claim]
            raise error_cls(message) from None

    def _validate_iat(
        self,
        payload: dict[str, Any],
        now: float,
        leeway: float,
    ) -> None:
        iat = self._coerce_int_claim(payload, "iat")
        if iat > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (iat)")

    def _validate_nbf(
        self,
        payload: dict[str, Any],
        now: float,
        leeway: float,
    ) -> None:
        nbf = self._coerce_int_claim(payload, "nbf")
        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    def _validate_exp(
        self,
        payload: dict[str, Any],
        now: float,
        leeway: float,
    ) -> None:
        exp = self._coerce_int_claim(payload, "exp")
        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(
        self,
        payload: dict[str, Any],
        audience: str | Iterable[str] | None,
        *,
        strict: bool = False,
    ) -> None:
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            # Application did not specify an audience, but
            # the token has the 'aud' claim
            raise InvalidAudienceError("Invalid audience")

        if "aud" not in payload or not payload["aud"]:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise MissingRequiredClaimError("aud")

        audience_claims = payload["aud"]

        # In strict mode, we forbid list matching: the supplied audience
        # must be a string, and it must exactly match the audience claim.
        if strict:
            # Only a single audience is allowed in strict mode.
            if not isinstance(audience, str):
                raise InvalidAudienceError("Invalid audience (strict)")

            # Only a single audience claim is allowed in strict mode.
            if not isinstance(audience_claims, str):
                raise InvalidAudienceError("Invalid claim format in token (strict)")

            if audience != audience_claims:
                raise InvalidAudienceError("Audience doesn't match (strict)")

            return

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, str):
            audience = [audience]

        if all(aud not in audience_claims for aud in audience):
            raise InvalidAudienceError("Audience doesn't match")

    def _validate_iss(
        self, payload: dict[str, Any], issuer: Container[str] | str | None
    ) -> None:
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        iss = payload["iss"]
        if not isinstance(iss, str):
            raise InvalidIssuerError("Payload Issuer (iss) must be a string")

        if isinstance(issuer, str):
            if iss != issuer:
                raise InvalidIssuerError("Invalid issuer")
        else:
            try:
                if iss not in issuer:
                    raise InvalidIssuerError("Invalid issuer")
            except TypeError:
                raise InvalidIssuerError(
                    'Issuer param must be "str" or "Container[str]"'
                ) from None


_jwt_global_obj = PyJWT()
_jwt_global_obj._jws = _jws_global_obj
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
