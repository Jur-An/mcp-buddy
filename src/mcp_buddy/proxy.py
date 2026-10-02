from __future__ import annotations

from contextlib import asynccontextmanager
import ipaddress
from typing import AsyncIterator
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from .access_tokens import AccessTokenCache
from .config import BuddyConfig, ServerConfig
from .errors import McpBuddyError, OAuthError, ProxyError
from .models import CredentialKey, CredentialKind
from .oauth import OAuthManager
from .stores import SecretStore


_REQUEST_HEADERS = {
    "accept",
    "content-type",
    "last-event-id",
    "mcp-method",
    "mcp-name",
    "mcp-protocol-version",
    "mcp-session-id",
}
_RESPONSE_HEADERS = {
    "cache-control",
    "content-type",
    "mcp-protocol-version",
    "mcp-session-id",
    "retry-after",
    "www-authenticate",
}
_MAX_REQUEST_BYTES = 32 * 1024 * 1024


def create_proxy_app(
    config: BuddyConfig,
    store: SecretStore,
    access_tokens: AccessTokenCache | None = None,
    *,
    upstream_client: httpx.AsyncClient | None = None,
    oauth_manager: OAuthManager | None = None,
) -> Starlette:
    cache = access_tokens or AccessTokenCache()
    managed_upstream = upstream_client is None
    upstream = upstream_client or httpx.AsyncClient(
        timeout=httpx.Timeout(None, connect=15), follow_redirects=False
    )
    managed_oauth = oauth_manager is None
    oauth_http = httpx.AsyncClient(timeout=15, follow_redirects=False) if managed_oauth else None
    oauth = oauth_manager or OAuthManager(store, cache, client=oauth_http)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            cache.clear()
            if managed_upstream:
                await upstream.aclose()
            if managed_oauth and oauth_http is not None:
                await oauth_http.aclose()

    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def forward(request: Request) -> Response:
        server_name = request.path_params["server"]
        server = config.servers.get(server_name)
        if server is None:
            return _error(404, "Unknown MCP server.")
        if server.transport != "streamable-http":
            return _error(400, "Only streamable-http servers can use the HTTP proxy.")
        if not _safe_origin(request.headers.get("origin")):
            return _error(403, "Browser Origin is not loopback.")
        try:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > _MAX_REQUEST_BYTES:
                return _error(413, "MCP request is too large.")
            body = await request.body()
            if len(body) > _MAX_REQUEST_BYTES:
                return _error(413, "MCP request is too large.")
            response = await _send(
                upstream, oauth, store, server, request.method, request.headers, body
            )
            return StreamingResponse(
                response.aiter_bytes(),
                status_code=response.status_code,
                headers=_response_headers(response),
                background=BackgroundTask(response.aclose),
            )
        except ValueError:
            return _error(400, "Invalid Content-Length header.")
        except OAuthError as exc:
            return _error(401, str(exc))
        except (httpx.HTTPError, ProxyError) as exc:
            return _error(502, str(exc))
        except McpBuddyError as exc:
            return _error(500, str(exc))

    return Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/mcp/{server}", forward, methods=["POST", "GET", "DELETE"]),
        ],
        lifespan=lifespan,
    )


async def _send(
    client: httpx.AsyncClient,
    oauth: OAuthManager,
    store: SecretStore,
    server: ServerConfig,
    method: str,
    incoming_headers: object,
    body: bytes,
) -> httpx.Response:
    token = await _token_for(oauth, store, server, force_refresh=False)
    response = await _send_once(
        client, server, method, incoming_headers, body, token
    )
    if response.status_code == 401 and server.auth.type == "oauth-pkce":
        await response.aclose()
        token = await _token_for(oauth, store, server, force_refresh=True)
        response = await _send_once(
            client, server, method, incoming_headers, body, token
        )
    return response


async def _send_once(
    client: httpx.AsyncClient,
    server: ServerConfig,
    method: str,
    incoming_headers: object,
    body: bytes,
    token: str | None,
) -> httpx.Response:
    if not server.url:
        raise ProxyError("Remote MCP server has no URL.")
    headers = _request_headers(incoming_headers)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = client.build_request(method, server.url, headers=headers, content=body)
    try:
        return await client.send(request, stream=True, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise ProxyError("Remote MCP server could not be reached.") from exc


async def _token_for(
    oauth: OAuthManager,
    store: SecretStore,
    server: ServerConfig,
    *,
    force_refresh: bool,
) -> str | None:
    if server.auth.type == "none":
        return None
    if server.auth.type == "oauth-pkce":
        return await oauth.access_token(server, force_refresh=force_refresh)
    if server.auth.type == "bearer":
        key = CredentialKey(
            server.name,
            server.auth.account,
            server.auth.credential_profile or "default",
        )
        credential = store.get(key)
        if credential is None or credential.kind != CredentialKind.LONG_LIVED_CREDENTIAL:
            raise OAuthError(
                f"No long-lived Bearer credential exists for server {server.name!r}."
            )
        return credential.secret.reveal()
    raise ProxyError(f"Unsupported auth type {server.auth.type!r}.")


def _request_headers(headers: object) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in headers.items():  # type: ignore[attr-defined]
        lowered = name.lower()
        if lowered in _REQUEST_HEADERS or lowered.startswith("x-mcp-header-"):
            result[name] = value
    return result


def _response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        name: value
        for name, value in response.headers.items()
        if name.lower() in _RESPONSE_HEADERS
    }


def _safe_origin(origin: str | None) -> bool:
    if origin is None:
        return True
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    return is_loopback_host(parsed.hostname)


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run_proxy(app: Starlette, host: str, port: int) -> None:
    if not is_loopback_host(host):
        raise ProxyError("Proxy must bind to localhost or a loopback IP address.")
    if not 1 <= port <= 65535:
        raise ProxyError("Proxy port must be between 1 and 65535.")
    import uvicorn

    uvicorn.run(app, host=host, port=port, access_log=False)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)
