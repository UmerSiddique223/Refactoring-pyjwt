import time
from typing import Optional

from .api_jwk import PyJWKSet


class JWKSetCache:
    def __init__(self, lifespan: float) -> None:
        self._jwk_set: Optional[PyJWKSet] = None
        self._timestamp: float = 0.0
        self.lifespan = lifespan

    def put(self, jwk_set: Optional[PyJWKSet]) -> None:
        if jwk_set is not None:
            self._jwk_set = jwk_set
            self._timestamp = time.monotonic()
        else:
            # clear cache
            self._jwk_set = None
            self._timestamp = 0.0

    def get(self) -> Optional[PyJWKSet]:
        if self._jwk_set is None or self.is_expired():
            return None
        return self._jwk_set

    def is_expired(self) -> bool:
        return (
            self._jwk_set is not None
            and self.lifespan > -1
            and time.monotonic() > self._timestamp + self.lifespan
        )
