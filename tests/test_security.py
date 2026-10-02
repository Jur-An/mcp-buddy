from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import logging
from pathlib import Path
import tempfile
import unittest

from mcp_buddy.access_tokens import AccessTokenCache
from mcp_buddy.config import load_config
from mcp_buddy.errors import (
    InvalidCredentialError,
    UnsafeConfigurationError,
    VaultDecryptionError,
)
from mcp_buddy.logging_utils import RedactingFilter, redact_text
from mcp_buddy.models import CredentialKey, CredentialKind, SecretValue
from mcp_buddy.stores import EncryptedFileStore, NativeKeyringStore


class FakeKeyring:
    priority = 10

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, account: str, value: str) -> None:
        self.values[(service, account)] = value

    def get_password(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def delete_password(self, service: str, account: str) -> None:
        del self.values[(service, account)]


class SecretStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = CredentialKey("fcm", "andjurek", "prod")

    def test_native_keyring_roundtrip_and_redacted_model(self) -> None:
        backend = FakeKeyring()
        store = NativeKeyringStore(backend)
        store.set(self.key, CredentialKind.REFRESH_TOKEN, "refresh-value")
        credential = store.get(self.key)
        self.assertIsNotNone(credential)
        self.assertEqual(credential.secret.reveal(), "refresh-value")
        self.assertEqual(str(credential.secret), "<redacted>")
        self.assertNotIn("refresh-value", repr(credential))
        self.assertTrue(store.delete(self.key))
        self.assertIsNone(store.get(self.key))

    def test_persistent_stores_reject_access_tokens(self) -> None:
        store = NativeKeyringStore(FakeKeyring())
        with self.assertRaisesRegex(InvalidCredentialError, "never persisted"):
            store.set(self.key, CredentialKind.ACCESS_TOKEN, "short-lived")

    def test_encrypted_file_roundtrip_and_no_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secrets.vault"
            store = EncryptedFileStore(path, lambda: "a-strong-test-passphrase")
            store.set(
                self.key,
                CredentialKind.LONG_LIVED_CREDENTIAL,
                "super-secret-value",
            )
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("super-secret-value", raw)
            self.assertNotIn("andjurek", raw)
            credential = store.get(self.key)
            self.assertEqual(credential.secret.reveal(), "super-secret-value")
            self.assertTrue(store.delete(self.key))
            self.assertIsNone(store.get(self.key))

    def test_encrypted_file_wrong_passphrase_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secrets.vault"
            EncryptedFileStore(path, lambda: "correct-test-passphrase").set(
                self.key, CredentialKind.REFRESH_TOKEN, "refresh-value"
            )
            with self.assertRaises(VaultDecryptionError):
                EncryptedFileStore(path, lambda: "incorrect-passphrase").get(self.key)


class AccessTokenTests(unittest.TestCase):
    def test_access_token_lives_only_in_memory_and_expires(self) -> None:
        cache = AccessTokenCache(expiry_skew=timedelta(0))
        key = CredentialKey("fcm", "andjurek", "prod")
        now = datetime.now(timezone.utc)
        cache.put(key, "access-value", now + timedelta(minutes=5))
        self.assertEqual(cache.get(key, now).reveal(), "access-value")
        self.assertIsNone(cache.get(key, now + timedelta(minutes=6)))
        self.assertEqual(len(cache), 0)

    def test_secret_value_never_stringifies_to_secret(self) -> None:
        value = SecretValue("hidden")
        self.assertEqual(str(value), "<redacted>")
        self.assertNotIn("hidden", repr(value))


class ConfigTests(unittest.TestCase):
    def test_example_style_config_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.yaml"
            path.write_text(
                """servers:\n  fcm:\n    url: https://fcm.example.com/mcp\n    transport: streamable-http\n    auth:\n      type: oauth-pkce\n      credential_profile: fcm-prod\n      client_id: public-id\n      scopes: [mcp]\n""",
                encoding="utf-8",
            )
            config = load_config(path)
            self.assertEqual(config.servers["fcm"].auth.credential_profile, "fcm-prod")

    def test_secret_like_yaml_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.yaml"
            path.write_text(
                """servers:\n  fcm:\n    url: https://fcm.example.com/mcp\n    auth:\n      type: bearer\n      credential_profile: prod\n      access_token: forbidden\n""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(UnsafeConfigurationError, "forbidden"):
                load_config(path)

    def test_url_userinfo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.yaml"
            path.write_text(
                """servers:\n  fcm:\n    url: https://user:password@example.com/mcp\n    auth:\n      type: none\n""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(UnsafeConfigurationError, "userinfo"):
                load_config(path)


class LoggingTests(unittest.TestCase):
    def test_common_secret_patterns_are_redacted(self) -> None:
        message = "Authorization: Bearer abc.def refresh_token=refresh-value password=hunter2"
        redacted = redact_text(message)
        self.assertNotIn("abc.def", redacted)
        self.assertNotIn("refresh-value", redacted)
        self.assertNotIn("hunter2", redacted)

    def test_filter_redacts_known_opaque_value(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        filter_ = RedactingFilter()
        filter_.add_secret("opaque-secret")
        handler.addFilter(filter_)
        logger = logging.getLogger("mcp-buddy-test")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.info("value=%s", "opaque-secret")
        self.assertNotIn("opaque-secret", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
