from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
from pathlib import Path
import sys

from .config import load_config
from .errors import McpBuddyError, UnsafeConfigurationError
from .factory import build_secret_store
from .logging_utils import configure_logging
from .models import CredentialKey, CredentialKind
from .access_tokens import AccessTokenCache
from .oauth import OAuthManager
from .proxy import create_proxy_app, run_proxy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-buddy")
    parser.add_argument(
        "--vault-path",
        type=Path,
        default=None,
        help="Linux encrypted fallback location (never contains its passphrase).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("backend", help="Show the selected credential backend.")

    store = commands.add_parser("store", help="Store a persistent credential via hidden prompt.")
    _add_key_arguments(store)
    store.add_argument(
        "--kind",
        required=True,
        choices=[
            CredentialKind.REFRESH_TOKEN.value,
            CredentialKind.LONG_LIVED_CREDENTIAL.value,
        ],
    )

    check = commands.add_parser("check", help="Check metadata without printing the secret.")
    _add_key_arguments(check)

    delete = commands.add_parser("delete", help="Delete one persistent credential.")
    _add_key_arguments(delete)

    validate = commands.add_parser("validate-config", help="Validate secret-free YAML config.")
    validate.add_argument("path", type=Path)

    login = commands.add_parser("login", help="Log in through OAuth Authorization Code + PKCE.")
    _add_config_server_arguments(login)

    logout = commands.add_parser("logout", help="Delete a server's refresh token.")
    _add_config_server_arguments(logout)

    serve = commands.add_parser("serve", help="Run the loopback Streamable HTTP MCP proxy.")
    serve.add_argument("config", type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    return parser


def _add_key_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("server")
    parser.add_argument("account")
    parser.add_argument("--profile", default="default")


def _add_config_server_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("config", type=Path)
    parser.add_argument("server")


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-config":
            config = load_config(args.path)
            print(f"Configuration valid: {len(config.servers)} server(s).")
            return 0

        store = build_secret_store(vault_path=args.vault_path)
        if args.command == "backend":
            print(store.backend_name)
            return 0

        if args.command in {"login", "logout", "serve"}:
            config = load_config(args.config)
            if args.command == "serve":
                app = create_proxy_app(config, store)
                run_proxy(app, args.host, args.port)
                return 0
            server = config.servers.get(args.server)
            if server is None:
                raise UnsafeConfigurationError(
                    f"Server {args.server!r} does not exist in the configuration."
                )
            manager = OAuthManager(store, AccessTokenCache())
            if args.command == "login":
                asyncio.run(manager.login(server))
                print(f"OAuth login stored for server {server.name!r}.")
                return 0
            deleted = manager.logout(server)
            print("OAuth login deleted." if deleted else "OAuth login not found.")
            return 0 if deleted else 1

        key = CredentialKey(args.server, args.account, args.profile)
        if args.command == "store":
            value = getpass.getpass("Credential value: ")
            store.set(key, args.kind, value)
            print(f"Credential stored: {key.server}/{key.profile}/{key.account} ({args.kind}).")
            return 0
        if args.command == "check":
            credential = store.get(key)
            if credential is None:
                print("Credential not found.")
                return 1
            print(
                "Credential present: "
                f"kind={credential.kind.value}, updated_at={credential.updated_at.isoformat()}"
            )
            return 0
        if args.command == "delete":
            deleted = store.delete(key)
            print("Credential deleted." if deleted else "Credential not found.")
            return 0 if deleted else 1
    except McpBuddyError as exc:
        logging.error("%s", exc)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
