from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from mcp_buddy.cli import build_parser
from mcp_buddy.errors import SecretStoreUnavailable
from mcp_buddy.factory import build_secret_store
from mcp_buddy.stores import EncryptedFileStore, NativeKeyringStore


class WorkingBackend:
    priority = 10

    def get_password(self, service, account):
        return None

    def set_password(self, service, account, value):
        pass

    def delete_password(self, service, account):
        pass


class MissingBackend:
    priority = 0


class PlaintextKeyring:
    __module__ = "keyrings.alt.file"
    priority = 10

    def get_password(self, service, account):
        return None


class FactoryTests(unittest.TestCase):
    def test_native_backend_is_default(self) -> None:
        store = build_secret_store(system="Windows", keyring_backend=WorkingBackend())
        self.assertIsInstance(store, NativeKeyringStore)

    def test_linux_missing_backend_uses_encrypted_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = build_secret_store(
                system="Linux",
                keyring_backend=MissingBackend(),
                vault_path=Path(temp) / "vault",
                passphrase_provider=lambda: "strong-test-passphrase",
            )
            self.assertIsInstance(store, EncryptedFileStore)

    def test_non_linux_missing_backend_fails(self) -> None:
        with self.assertRaises(SecretStoreUnavailable):
            build_secret_store(system="Windows", keyring_backend=MissingBackend())

    def test_plaintext_keyring_is_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = build_secret_store(
                system="Linux",
                keyring_backend=PlaintextKeyring(),
                vault_path=Path(temp) / "vault",
                passphrase_provider=lambda: "strong-test-passphrase",
            )
            self.assertIsInstance(store, EncryptedFileStore)

    def test_cli_has_no_secret_value_option(self) -> None:
        parser = build_parser()
        option_strings = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        for action in parser._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                for subparser in choices.values():
                    option_strings.update(
                        option
                        for child_action in subparser._actions
                        for option in child_action.option_strings
                    )
        self.assertNotIn("--token", option_strings)
        self.assertNotIn("--password", option_strings)
        self.assertNotIn("--secret", option_strings)


if __name__ == "__main__":
    unittest.main()
