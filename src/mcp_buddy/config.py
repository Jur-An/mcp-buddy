from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .errors import UnsafeConfigurationError


_SECRET_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "cookie",
    "credentials",
    "password",
    "passphrase",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}
_TOP_LEVEL_KEYS = {"servers"}
_SERVER_KEYS = {"url", "transport", "command", "auth"}
_AUTH_KEYS = {
    "type",
    "credential_profile",
    "client_id",
    "authorization_url",
    "token_url",
    "resource",
    "scopes",
}
_AUTH_TYPES = {"none", "oauth-pkce", "bearer"}
_TRANSPORTS = {"stdio", "sse", "streamable-http"}


@dataclass(frozen=True)
class AuthConfig:
    type: str
    credential_profile: str | None = None
    client_id: str | None = None
    authorization_url: str | None = None
    token_url: str | None = None
    resource: str | None = None
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServerConfig:
    name: str
    transport: str
    auth: AuthConfig
    url: str | None = None
    command: tuple[str, ...] = ()


@dataclass(frozen=True)
class BuddyConfig:
    servers: dict[str, ServerConfig]


def load_config(path: str | Path) -> BuddyConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise UnsafeConfigurationError("Configuration root must be an object.")
    _reject_secret_fields(raw)
    _reject_unknown(raw, _TOP_LEVEL_KEYS, "configuration")
    servers_raw = raw.get("servers")
    if not isinstance(servers_raw, dict) or not servers_raw:
        raise UnsafeConfigurationError("Configuration requires a non-empty servers map.")
    servers: dict[str, ServerConfig] = {}
    for name, value in servers_raw.items():
        if not isinstance(name, str) or not name:
            raise UnsafeConfigurationError("Server names must be non-empty strings.")
        if not isinstance(value, dict):
            raise UnsafeConfigurationError(f"Server {name!r} must be an object.")
        _reject_unknown(value, _SERVER_KEYS, f"server {name}")
        servers[name] = _parse_server(name, value)
    return BuddyConfig(servers)


def _parse_server(name: str, raw: dict[str, Any]) -> ServerConfig:
    transport = str(raw.get("transport", "streamable-http"))
    if transport not in _TRANSPORTS:
        raise UnsafeConfigurationError(
            f"Server {name!r} has unsupported transport {transport!r}."
        )
    url = raw.get("url")
    command = raw.get("command", [])
    if transport == "stdio":
        if not isinstance(command, list) or not command or not all(
            isinstance(item, str) and item for item in command
        ):
            raise UnsafeConfigurationError(
                f"stdio server {name!r} requires a non-empty command list."
            )
        if url is not None:
            raise UnsafeConfigurationError(f"stdio server {name!r} cannot define url.")
    else:
        if not isinstance(url, str):
            raise UnsafeConfigurationError(f"Remote server {name!r} requires url.")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise UnsafeConfigurationError(
                f"Server {name!r} URL must be HTTPS and cannot contain userinfo."
            )
        if command:
            raise UnsafeConfigurationError(f"Remote server {name!r} cannot define command.")

    auth_raw = raw.get("auth", {"type": "none"})
    if not isinstance(auth_raw, dict):
        raise UnsafeConfigurationError(f"Server {name!r} auth must be an object.")
    _reject_unknown(auth_raw, _AUTH_KEYS, f"server {name} auth")
    auth_type = auth_raw.get("type", "none")
    if auth_type not in _AUTH_TYPES:
        raise UnsafeConfigurationError(
            f"Server {name!r} has unsupported auth type {auth_type!r}."
        )
    profile = auth_raw.get("credential_profile")
    if auth_type != "none" and (not isinstance(profile, str) or not profile):
        raise UnsafeConfigurationError(
            f"Server {name!r} auth requires credential_profile."
        )
    scopes = auth_raw.get("scopes", [])
    if not isinstance(scopes, list) or not all(isinstance(v, str) for v in scopes):
        raise UnsafeConfigurationError(f"Server {name!r} scopes must be a string list.")
    return ServerConfig(
        name=name,
        transport=transport,
        url=url,
        command=tuple(command),
        auth=AuthConfig(
            type=auth_type,
            credential_profile=profile,
            client_id=auth_raw.get("client_id"),
            authorization_url=auth_raw.get("authorization_url"),
            token_url=auth_raw.get("token_url"),
            resource=auth_raw.get("resource"),
            scopes=tuple(scopes),
        ),
    )


def _reject_secret_fields(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _SECRET_KEYS:
                raise UnsafeConfigurationError(
                    f"Secret-like field {path}.{key} is forbidden; store it in SecretStore."
                )
            _reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, f"{path}[{index}]")


def _reject_unknown(raw: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise UnsafeConfigurationError(
            f"Unknown fields in {label}: {', '.join(unknown)}."
        )
