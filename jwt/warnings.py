from __future__ import annotations

import warnings
from typing import Any


class RemovedInPyjwt3Warning(DeprecationWarning):
    """Warning for features that will be removed in PyJWT 3."""

    pass


class InsecureKeyLengthWarning(UserWarning):
    """Warning emitted when a cryptographic key is shorter than the minimum
    recommended length. See :ref:`key-length-validation` for details."""

    pass


def warn_removed_kwargs(kwargs: dict[str, Any], func_name: str) -> None:
    """Emit a RemovedInPyjwt3Warning for unsupported **kwargs passed to ``func_name``.

    No-op when ``kwargs`` is empty. Uses ``stacklevel=3`` so the warning points
    at the original caller of the public API (caller -> public method -> here).
    """
    if not kwargs:
        return
    warnings.warn(
        f"passing additional kwargs to {func_name}() is deprecated "
        "and will be removed in pyjwt version 3. "
        f"Unsupported kwargs: {tuple(kwargs.keys())}",
        RemovedInPyjwt3Warning,
        stacklevel=3,
    )
