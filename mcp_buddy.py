#!/usr/bin/env python3
"""Small helper to manage MCP service keys locally."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict


DEFAULT_STORE = Path.home() / ".config" / "mcp-buddy" / "keys.json"


class KeyStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> Dict[str, Dict[str, str]]:
        if not self.path.exists():
            return {}
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("Store format is invalid")
        return {
            str(service): {str(k): str(v) for k, v in keys.items()}
            for service, keys in data.items()
            if isinstance(keys, dict)
        }

    def save(self, data: Dict[str, Dict[str, str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(data, indent=2, sort_keys=True) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
        finally:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass



def _print_masked(data: Dict[str, str]) -> None:
    for key in sorted(data):
        print(f"{key}=***")



def cmd_set(store: KeyStore, service: str, key: str, value: str) -> int:
    data = store.load()
    service_data = data.setdefault(service, {})
    service_data[key] = value
    store.save(data)
    print(f"Saved {key} for service '{service}'.")
    return 0



def cmd_get(store: KeyStore, service: str, key: str, reveal: bool) -> int:
    data = store.load()
    value = data.get(service, {}).get(key)
    if value is None:
        print(f"Missing key '{key}' for service '{service}'.")
        return 1
    if reveal:
        print(value)
    else:
        print("***")
    return 0



def cmd_unset(store: KeyStore, service: str, key: str) -> int:
    data = store.load()
    service_data = data.get(service)
    if not service_data or key not in service_data:
        print(f"Nothing to remove for {service}.{key}.")
        return 1
    del service_data[key]
    if not service_data:
        del data[service]
    store.save(data)
    print(f"Removed {key} from service '{service}'.")
    return 0



def cmd_list(store: KeyStore, service: str | None) -> int:
    data = store.load()
    if service:
        service_data = data.get(service)
        if not service_data:
            print(f"No keys stored for service '{service}'.")
            return 1
        _print_masked(service_data)
        return 0

    if not data:
        print("No keys stored.")
        return 0

    for name in sorted(data):
        keys = ", ".join(sorted(data[name])) or "(none)"
        print(f"{name}: {keys}")
    return 0



def cmd_export(store: KeyStore, service: str) -> int:
    data = store.load()
    service_data = data.get(service)
    if not service_data:
        print(f"No keys stored for service '{service}'.")
        return 1
    for key in sorted(service_data):
        print(f"export {key}={json.dumps(service_data[key])}")
    return 0



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-buddy", description="MCP key helper")
    parser.add_argument(
        "--store",
        default=os.environ.get("MCP_BUDDY_STORE", str(DEFAULT_STORE)),
        help="Path to key store file (default: %(default)s)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_set = sub.add_parser("set", help="Set a key")
    p_set.add_argument("service")
    p_set.add_argument("key")
    p_set.add_argument("value")

    p_get = sub.add_parser("get", help="Get a key")
    p_get.add_argument("service")
    p_get.add_argument("key")
    p_get.add_argument("--reveal", action="store_true", help="Print raw key")

    p_unset = sub.add_parser("unset", help="Delete a key")
    p_unset.add_argument("service")
    p_unset.add_argument("key")

    p_list = sub.add_parser("list", help="List services or keys")
    p_list.add_argument("service", nargs="?")

    p_export = sub.add_parser("export", help="Print shell exports for a service")
    p_export.add_argument("service")

    return parser



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = KeyStore(Path(args.store))

    if args.command == "set":
        return cmd_set(store, args.service, args.key, args.value)
    if args.command == "get":
        return cmd_get(store, args.service, args.key, args.reveal)
    if args.command == "unset":
        return cmd_unset(store, args.service, args.key)
    if args.command == "list":
        return cmd_list(store, args.service)
    if args.command == "export":
        return cmd_export(store, args.service)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
