from __future__ import annotations

from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
from threading import RLock
from typing import Callable, Iterator, Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import InvalidCredentialError, SecretStoreUnavailable, VaultDecryptionError
from .models import (
    CredentialKey,
    CredentialKind,
    SecretValue,
    StoredCredential,
    require_persistable,
)


_VAULT_VERSION = 1
_AAD = b"mcp-buddy-secrets-v1"
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


class SecretStore(ABC):
    @property
    @abstractmethod
    def backend_name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def set(
        self,
        key: CredentialKey,
        kind: CredentialKind | str,
        secret: str | SecretValue,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def get(self, key: CredentialKey) -> StoredCredential | None:
        raise NotImplementedError

    @abstractmethod
    def delete(self, key: CredentialKey) -> bool:
        raise NotImplementedError


class NativeKeyringStore(SecretStore):
    def __init__(self, backend: Any) -> None:
        self._backend = backend

    @property
    def backend_name(self) -> str:
        return f"native-keyring:{type(self._backend).__module__}.{type(self._backend).__name__}"

    def set(
        self,
        key: CredentialKey,
        kind: CredentialKind | str,
        secret: str | SecretValue,
    ) -> None:
        parsed_kind = require_persistable(kind)
        value = _reveal(secret)
        payload = _encode_entry(parsed_kind, value)
        try:
            self._backend.set_password(key.service_name, key.account, payload)
        except Exception as exc:
            raise SecretStoreUnavailable(
                f"Native credential store could not save {key.server}/{key.profile}."
            ) from exc

    def get(self, key: CredentialKey) -> StoredCredential | None:
        try:
            payload = self._backend.get_password(key.service_name, key.account)
        except Exception as exc:
            raise SecretStoreUnavailable(
                f"Native credential store could not read {key.server}/{key.profile}."
            ) from exc
        if payload is None:
            return None
        return _decode_entry(key, payload)

    def delete(self, key: CredentialKey) -> bool:
        try:
            if self._backend.get_password(key.service_name, key.account) is None:
                return False
            self._backend.delete_password(key.service_name, key.account)
            return True
        except Exception as exc:
            raise SecretStoreUnavailable(
                f"Native credential store could not delete {key.server}/{key.profile}."
            ) from exc


class EncryptedFileStore(SecretStore):
    """Linux fallback vault encrypted as one authenticated JSON document."""

    def __init__(self, path: Path, passphrase_provider: Callable[[], str]) -> None:
        self.path = Path(path)
        self._passphrase_provider = passphrase_provider
        self._process_lock = RLock()

    @property
    def backend_name(self) -> str:
        return f"encrypted-file:{self.path}"

    def set(
        self,
        key: CredentialKey,
        kind: CredentialKind | str,
        secret: str | SecretValue,
    ) -> None:
        parsed_kind = require_persistable(kind)
        value = _reveal(secret)
        with self._locked():
            entries = self._load()
            entries[key.entry_id] = {
                "kind": parsed_kind.value,
                "secret": value,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save(entries)

    def get(self, key: CredentialKey) -> StoredCredential | None:
        with self._locked():
            entry = self._load().get(key.entry_id)
        if entry is None:
            return None
        return _entry_from_dict(key, entry)

    def delete(self, key: CredentialKey) -> bool:
        with self._locked():
            entries = self._load()
            if key.entry_id not in entries:
                return False
            del entries[key.entry_id]
            self._save(entries)
            return True

    def _load(self) -> dict[str, dict[str, str]]:
        if not self.path.exists():
            return {}
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            if envelope.get("version") != _VAULT_VERSION:
                raise VaultDecryptionError("Unsupported encrypted vault version.")
            kdf = envelope["kdf"]
            cipher = envelope["cipher"]
            salt = b64decode(kdf["salt"], validate=True)
            nonce = b64decode(cipher["nonce"], validate=True)
            ciphertext = b64decode(cipher["ciphertext"], validate=True)
            key = _derive_key(self._passphrase(), salt, kdf)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, _AAD)
            document = json.loads(plaintext.decode("utf-8"))
            entries = document.get("entries")
            if not isinstance(entries, dict):
                raise VaultDecryptionError("Encrypted vault has an invalid payload.")
            return entries
        except InvalidTag as exc:
            raise VaultDecryptionError(
                "Cannot decrypt the vault: wrong passphrase or modified file."
            ) from exc
        except VaultDecryptionError:
            raise
        except Exception as exc:
            raise VaultDecryptionError("Encrypted vault is malformed or unreadable.") from exc

    def _save(self, entries: dict[str, dict[str, str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.path.parent, 0o700)
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        kdf_settings = {
            "name": "scrypt",
            "salt": b64encode(salt).decode("ascii"),
            "n": _SCRYPT_N,
            "r": _SCRYPT_R,
            "p": _SCRYPT_P,
        }
        key = _derive_key(self._passphrase(), salt, kdf_settings)
        plaintext = json.dumps(
            {"entries": entries}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _AAD)
        envelope = {
            "version": _VAULT_VERSION,
            "kdf": kdf_settings,
            "cipher": {
                "name": "AES-256-GCM",
                "nonce": b64encode(nonce).decode("ascii"),
                "ciphertext": b64encode(ciphertext).decode("ascii"),
            },
        }
        temporary = self.path.with_name(
            f".{self.path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            temporary.write_text(
                json.dumps(envelope, indent=2) + "\n", encoding="utf-8"
            )
            if os.name == "posix":
                os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def _passphrase(self) -> str:
        value = self._passphrase_provider()
        if not isinstance(value, str) or len(value) < 12:
            raise InvalidCredentialError(
                "Encrypted vault passphrase must contain at least 12 characters."
            )
        return value

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with self._process_lock:
            with lock_path.open("a+b") as handle:
                if os.name == "posix":
                    import fcntl

                    os.chmod(lock_path, 0o600)
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if os.name == "posix":
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _derive_key(passphrase: str, salt: bytes, settings: dict[str, Any]) -> bytes:
    if settings.get("name") != "scrypt":
        raise VaultDecryptionError("Unsupported vault key derivation function.")
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=int(settings["n"]),
        r=int(settings["r"]),
        p=int(settings["p"]),
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _reveal(value: str | SecretValue) -> str:
    if isinstance(value, SecretValue):
        return value.reveal()
    if not isinstance(value, str) or not value:
        raise InvalidCredentialError("A credential value cannot be empty.")
    return value


def _encode_entry(kind: CredentialKind, secret: str) -> str:
    return json.dumps(
        {
            "version": 1,
            "kind": kind.value,
            "secret": secret,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        separators=(",", ":"),
    )


def _decode_entry(key: CredentialKey, payload: str) -> StoredCredential:
    try:
        entry = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SecretStoreUnavailable("Native credential entry is malformed.") from exc
    return _entry_from_dict(key, entry)


def _entry_from_dict(key: CredentialKey, entry: dict[str, Any]) -> StoredCredential:
    kind = require_persistable(entry.get("kind"))
    updated_at = datetime.fromisoformat(entry["updated_at"])
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    return StoredCredential(
        key=key,
        kind=kind,
        secret=SecretValue(entry["secret"]),
        updated_at=updated_at,
    )
