from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock

from .models import CredentialKey, SecretValue


@dataclass(frozen=True, repr=False)
class _CachedAccessToken:
    value: SecretValue
    expires_at: datetime


class AccessTokenCache:
    """Process-local access tokens. This class intentionally has no persistence API."""

    def __init__(self, expiry_skew: timedelta = timedelta(seconds=30)) -> None:
        self._tokens: dict[CredentialKey, _CachedAccessToken] = {}
        self._lock = RLock()
        self._expiry_skew = expiry_skew

    def put(self, key: CredentialKey, token: str, expires_at: datetime) -> None:
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        with self._lock:
            self._tokens[key] = _CachedAccessToken(
                SecretValue(token), expires_at.astimezone(timezone.utc)
            )

    def get(self, key: CredentialKey, now: datetime | None = None) -> SecretValue | None:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        with self._lock:
            cached = self._tokens.get(key)
            if cached is None:
                return None
            if current + self._expiry_skew >= cached.expires_at:
                self._tokens.pop(key, None)
                return None
            return cached.value

    def discard(self, key: CredentialKey) -> None:
        with self._lock:
            self._tokens.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._tokens)
