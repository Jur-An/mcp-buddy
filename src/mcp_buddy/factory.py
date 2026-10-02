from __future__ import annotations

import getpass
import platform
from pathlib import Path
from typing import Any, Callable

import keyring
from platformdirs import user_data_path

from .errors import SecretStoreUnavailable
from .stores import EncryptedFileStore, NativeKeyringStore, SecretStore


class CachedPassphrasePrompt:
    """Interactive vault unlock prompt cached only in this process."""

    def __init__(self, vault_path: Path) -> None:
        self._vault_path = vault_path
        self._cached: str | None = None

    def __call__(self) -> str:
        if self._cached is not None:
            return self._cached
        first = getpass.getpass("mcp-buddy encrypted vault passphrase: ")
        if not self._vault_path.exists():
            second = getpass.getpass("Confirm new vault passphrase: ")
            if first != second:
                raise SecretStoreUnavailable("Vault passphrases do not match.")
        self._cached = first
        return first


def build_secret_store(
    *,
    vault_path: Path | None = None,
    passphrase_provider: Callable[[], str] | None = None,
    system: str | None = None,
    keyring_backend: Any | None = None,
) -> SecretStore:
    """Use native keyring, with encrypted-file fallback only on Linux."""

    operating_system = system or platform.system()
    backend = keyring_backend if keyring_backend is not None else keyring.get_keyring()
    if _native_backend_usable(backend):
        return NativeKeyringStore(backend)

    if operating_system != "Linux":
        raise SecretStoreUnavailable(
            "No usable native credential store is available. Encrypted-file fallback "
            "is intentionally limited to Linux without Secret Service."
        )

    resolved_path = vault_path or (
        user_data_path("mcp-buddy", appauthor=False) / "secrets.vault"
    )
    provider = passphrase_provider or CachedPassphrasePrompt(resolved_path)
    return EncryptedFileStore(resolved_path, provider)


def _native_backend_usable(backend: Any) -> bool:
    backend_type = f"{type(backend).__module__}.{type(backend).__name__}".lower()
    try:
        priority = float(getattr(backend, "priority", 0))
    except Exception:
        return False
    insecure_markers = ("plaintext", "keyrings.alt", "filekeyring", "nullkeyring")
    if (
        priority <= 0
        or ".fail." in backend_type
        or backend_type.endswith("fail.keyring")
        or any(marker in backend_type for marker in insecure_markers)
    ):
        return False
    try:
        backend.get_password("mcp-buddy/backend-probe", "availability")
        return True
    except Exception as exc:
        # A locked keychain exists and must be unlocked; silently switching vaults
        # would split credentials between two stores. Only absence/unavailability
        # selects the Linux fallback.
        name = type(exc).__name__.lower()
        module = type(exc).__module__.lower()
        unavailable = (
            "nokeyring" in name
            or "notavailable" in name
            or "nosuchobject" in name
            or "secretservice" in module
            or "dbus" in module
        )
        if unavailable:
            return False
        raise SecretStoreUnavailable(
            "Native credential store exists but could not be opened; unlock or repair it."
        ) from exc
