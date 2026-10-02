from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re

from .errors import InvalidCredentialError


_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$")


class CredentialKind(str, Enum):
    REFRESH_TOKEN = "refresh-token"
    LONG_LIVED_CREDENTIAL = "long-lived-credential"
    ACCESS_TOKEN = "access-token"

    @classmethod
    def parse(cls, value: "CredentialKind | str") -> "CredentialKind":
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except ValueError as exc:
            raise InvalidCredentialError(f"Unsupported credential kind: {value!r}") from exc


PERSISTABLE_KINDS = {
    CredentialKind.REFRESH_TOKEN,
    CredentialKind.LONG_LIVED_CREDENTIAL,
}


@dataclass(frozen=True)
class CredentialKey:
    server: str
    account: str
    profile: str = "default"

    def __post_init__(self) -> None:
        for name, value in (
            ("server", self.server),
            ("account", self.account),
            ("profile", self.profile),
        ):
            if not isinstance(value, str) or not _COMPONENT_RE.fullmatch(value):
                raise InvalidCredentialError(
                    f"Credential {name} must be 1-255 safe identifier characters."
                )

    @property
    def service_name(self) -> str:
        return f"mcp-buddy/{self.server}/{self.profile}"

    @property
    def entry_id(self) -> str:
        return f"{self.server}\0{self.profile}\0{self.account}"


class SecretValue:
    """A secret whose string and repr forms are always redacted."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or not value:
            raise InvalidCredentialError("A credential value cannot be empty.")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __bool__(self) -> bool:
        return True


@dataclass(frozen=True)
class StoredCredential:
    key: CredentialKey
    kind: CredentialKind
    secret: SecretValue = field(repr=False)
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.kind not in PERSISTABLE_KINDS:
            raise InvalidCredentialError(
                "Access tokens are memory-only and cannot be represented as stored credentials."
            )


def require_persistable(kind: CredentialKind | str) -> CredentialKind:
    parsed = CredentialKind.parse(kind)
    if parsed not in PERSISTABLE_KINDS:
        raise InvalidCredentialError(
            "Access tokens must use AccessTokenCache and are never persisted."
        )
    return parsed
