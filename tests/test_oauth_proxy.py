from __future__ import annotations

import asyncio
from datetime import timedelta
import json
from urllib.parse import parse_qs, quote, urlsplit
import unittest

import httpx

from mcp_buddy.access_tokens import AccessTokenCache
from mcp_buddy.config import AuthConfig, BuddyConfig, ServerConfig
from mcp_buddy.models import CredentialKey
from mcp_buddy.oauth import (
    OAuthMetadata,
    OAuthManager,
    authorization_server_metadata_urls,
    create_pkce_pair,
    protected_resource_metadata_url,
)
from mcp_buddy.proxy import create_proxy_app, is_loopback_host
from mcp_buddy.stores import NativeKeyringStore
from mcp_buddy.errors import OAuthError


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


def oauth_server() -> ServerConfig:
    return ServerConfig(
        name="fcm",
        url="https://fcm.example.com/mcp",
        transport="streamable-http",
        auth=AuthConfig(
            type="oauth-pkce",
            credential_profile="prod",
            account="andjurek",
            client_id="public-client",
            issuer="https://auth.example.com",
            resource="https://fcm.example.com/mcp",
            scopes=("mcp", "offline_access"),
            callback_timeout_seconds=30,
        ),
    )


def dynamic_oauth_server() -> ServerConfig:
    return ServerConfig(
        name="fcm-dynamic",
        url="https://fcm.example.com/mcp",
        transport="streamable-http",
        auth=AuthConfig(
            type="oauth-pkce",
            credential_profile="prod",
            account="andjurek",
            issuer="https://auth.example.com",
            registration_url="https://auth.example.com/register",
            resource="https://fcm.example.com/mcp",
            scopes=("mcp",),
            callback_timeout_seconds=30,
        ),
    )


class OAuthTests(unittest.IsolatedAsyncioTestCase):
    def test_pkce_and_well_known_urls(self) -> None:
        verifier, challenge = create_pkce_pair()
        self.assertGreaterEqual(len(verifier), 43)
        self.assertEqual(len(challenge), 43)
        self.assertNotIn("=", challenge)
        self.assertEqual(
            protected_resource_metadata_url("https://example.com/a/mcp"),
            "https://example.com/.well-known/oauth-protected-resource/a/mcp",
        )
        self.assertEqual(
            authorization_server_metadata_urls("https://login.example.com/tenant"),
            (
                "https://login.example.com/.well-known/oauth-authorization-server/tenant",
                "https://login.example.com/tenant/.well-known/openid-configuration",
            ),
        )

    async def test_login_and_refresh_keep_access_token_memory_only(self) -> None:
        token_requests: list[dict[str, list[str]]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "fcm.example.com":
                return httpx.Response(
                    200,
                    json={
                        "resource": "https://fcm.example.com/mcp",
                        "authorization_servers": ["https://auth.example.com"],
                    },
                )
            if request.url.path == "/.well-known/oauth-authorization-server":
                return httpx.Response(
                    200,
                    json={
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "https://auth.example.com/authorize",
                        "token_endpoint": "https://auth.example.com/token",
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["none"],
                        "scopes_supported": ["mcp", "offline_access"],
                        "authorization_response_iss_parameter_supported": True,
                    },
                )
            if request.url.path == "/token":
                form = parse_qs(request.content.decode("ascii"))
                token_requests.append(form)
                refresh = "refresh-initial" if form["grant_type"] == ["authorization_code"] else "refresh-rotated"
                access = "access-initial" if len(token_requests) == 1 else "access-refreshed"
                return httpx.Response(
                    200,
                    json={
                        "access_token": access,
                        "refresh_token": refresh,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    },
                )
            return httpx.Response(404)

        async_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        backend = FakeKeyring()
        store = NativeKeyringStore(backend)
        cache = AccessTokenCache(expiry_skew=timedelta(0))

        def open_browser(url: str) -> bool:
            params = parse_qs(urlsplit(url).query)
            self.assertEqual(params["code_challenge_method"], ["S256"])
            self.assertEqual(params["resource"], ["https://fcm.example.com/mcp"])
            redirect = urlsplit(params["redirect_uri"][0])

            async def callback() -> None:
                reader, writer = await asyncio.open_connection(redirect.hostname, redirect.port)
                path = (
                    f"{redirect.path}?code=test-code&state={quote(params['state'][0])}"
                    f"&iss={quote('https://auth.example.com', safe='')}"
                )
                writer.write(
                    f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode()
                )
                await writer.drain()
                await reader.read()
                writer.close()
                await writer.wait_closed()

            asyncio.get_running_loop().create_task(callback())
            return True

        manager = OAuthManager(
            store, cache, client=async_client, browser_open=open_browser
        )
        server = oauth_server()
        await manager.login(server)
        key = CredentialKey("fcm", "andjurek", "prod")
        self.assertEqual(cache.get(key).reveal(), "access-initial")
        raw_keyring = next(iter(backend.values.values()))
        self.assertNotIn("access-initial", raw_keyring)
        self.assertNotIn('"access_token"', raw_keyring)
        self.assertEqual(token_requests[0]["resource"], [server.auth.resource])
        self.assertIn("code_verifier", token_requests[0])

        refreshed = await manager.access_token(server, force_refresh=True)
        self.assertEqual(refreshed, "access-refreshed")
        stored_envelope = json.loads(store.get(key).secret.reveal())
        self.assertEqual(stored_envelope["refresh_token"], "refresh-rotated")
        self.assertEqual(token_requests[1]["resource"], [server.auth.resource])
        await async_client.aclose()

    async def test_dynamic_registration_client_is_bound_and_reused_for_refresh(self) -> None:
        registrations: list[dict[str, object]] = []
        authorization_client_ids: list[str] = []
        token_requests: list[dict[str, list[str]]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "fcm.example.com":
                return httpx.Response(
                    200,
                    json={
                        "resource": "https://fcm.example.com/mcp",
                        "authorization_servers": ["https://auth.example.com"],
                    },
                )
            if request.url.path == "/.well-known/oauth-authorization-server":
                return httpx.Response(
                    200,
                    json={
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "https://auth.example.com/authorize",
                        "token_endpoint": "https://auth.example.com/token",
                        "registration_endpoint": "https://auth.example.com/register",
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["none"],
                        "scopes_supported": ["mcp"],
                    },
                )
            if request.url.path == "/register":
                registration = json.loads(request.content)
                registrations.append(registration)
                return httpx.Response(
                    201,
                    json={
                        "client_id": "dynamic-client-id",
                        "redirect_uris": registration["redirect_uris"],
                        "token_endpoint_auth_method": "none",
                    },
                )
            if request.url.path == "/token":
                form = parse_qs(request.content.decode("ascii"))
                token_requests.append(form)
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"access-{len(token_requests)}",
                        "refresh_token": "dynamic-refresh-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    },
                )
            return httpx.Response(404)

        async_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        backend = FakeKeyring()
        store = NativeKeyringStore(backend)
        cache = AccessTokenCache(expiry_skew=timedelta(0))

        def open_browser(url: str) -> bool:
            params = parse_qs(urlsplit(url).query)
            authorization_client_ids.append(params["client_id"][0])
            redirect = urlsplit(params["redirect_uri"][0])

            async def callback() -> None:
                reader, writer = await asyncio.open_connection(
                    redirect.hostname, redirect.port
                )
                path = (
                    f"{redirect.path}?code=test-code&state={quote(params['state'][0])}"
                )
                writer.write(
                    f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode()
                )
                await writer.drain()
                await reader.read()
                writer.close()
                await writer.wait_closed()

            asyncio.get_running_loop().create_task(callback())
            return True

        manager = OAuthManager(
            store, cache, client=async_client, browser_open=open_browser
        )
        server = dynamic_oauth_server()
        await manager.login(server)

        self.assertEqual(len(registrations), 1)
        registration = registrations[0]
        self.assertEqual(registration["application_type"], "native")
        self.assertEqual(registration["token_endpoint_auth_method"], "none")
        self.assertEqual(
            registration["grant_types"], ["authorization_code", "refresh_token"]
        )
        self.assertEqual(authorization_client_ids, ["dynamic-client-id"])
        self.assertEqual(token_requests[0]["client_id"], ["dynamic-client-id"])
        self.assertEqual(
            registration["redirect_uris"], token_requests[0]["redirect_uri"]
        )
        key = CredentialKey("fcm-dynamic", "andjurek", "prod")
        stored_envelope = json.loads(store.get(key).secret.reveal())
        self.assertEqual(stored_envelope["client_id"], "dynamic-client-id")

        refreshed = await manager.access_token(server, force_refresh=True)
        self.assertEqual(refreshed, "access-2")
        self.assertEqual(len(registrations), 1)
        self.assertEqual(token_requests[1]["client_id"], ["dynamic-client-id"])
        await async_client.aclose()

    async def test_dynamic_registration_rejects_client_secret(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                201,
                json={
                    "client_id": "confidential-client",
                    "client_secret": "must-not-be-stored",
                },
            )

        async_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        manager = OAuthManager(
            NativeKeyringStore(FakeKeyring()),
            AccessTokenCache(),
            client=async_client,
        )
        metadata = OAuthMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            registration_endpoint="https://auth.example.com/register",
        )
        with self.assertRaisesRegex(OAuthError, "client_secret"):
            await manager.register_client(
                metadata,
                dynamic_oauth_server(),
                "http://127.0.0.1:49152/callback",
            )
        await async_client.aclose()


class FakeOAuthManager:
    def __init__(self) -> None:
        self.calls: list[bool] = []

    async def access_token(self, server: ServerConfig, *, force_refresh: bool = False) -> str:
        self.calls.append(force_refresh)
        return "second-token" if force_refresh else "first-token"


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_filters_headers_and_retries_one_401(self) -> None:
        seen: list[httpx.Request] = []

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if len(seen) == 1:
                return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})
            return httpx.Response(
                200,
                headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "legacy"},
                content=b"event: message\ndata: ok\n\n",
            )

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
        oauth = FakeOAuthManager()
        app = create_proxy_app(
            BuddyConfig({"fcm": oauth_server()}),
            NativeKeyringStore(FakeKeyring()),
            upstream_client=upstream,
            oauth_manager=oauth,  # type: ignore[arg-type]
        )
        async with app.router.lifespan_context(app):
            local = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
            )
            response = await local.post(
                "/mcp/fcm",
                content=b'{"jsonrpc":"2.0"}',
                headers={
                    "Authorization": "Bearer attacker-value",
                    "Cookie": "secret=cookie",
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/call",
                    "X-Unrelated": "drop-me",
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, "event: message\ndata: ok\n\n")
            self.assertEqual(response.headers["mcp-session-id"], "legacy")
            await local.aclose()

        self.assertEqual(oauth.calls, [False, True])
        self.assertEqual(seen[0].headers["authorization"], "Bearer first-token")
        self.assertEqual(seen[1].headers["authorization"], "Bearer second-token")
        self.assertNotIn("cookie", seen[0].headers)
        self.assertNotIn("x-unrelated", seen[0].headers)
        self.assertEqual(seen[0].headers["mcp-method"], "tools/call")
        await upstream.aclose()

    async def test_non_loopback_browser_origin_is_rejected(self) -> None:
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
        app = create_proxy_app(
            BuddyConfig({"fcm": oauth_server()}),
            NativeKeyringStore(FakeKeyring()),
            upstream_client=upstream,
            oauth_manager=FakeOAuthManager(),  # type: ignore[arg-type]
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
            ) as local:
                response = await local.post(
                    "/mcp/fcm", headers={"Origin": "https://evil.example"}
                )
                self.assertEqual(response.status_code, 403)
        await upstream.aclose()

    def test_proxy_bind_must_be_loopback(self) -> None:
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertFalse(is_loopback_host("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
