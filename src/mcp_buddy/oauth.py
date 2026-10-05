from __future__ import annotations

import asyncio
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
import webbrowser

import httpx

from .access_tokens import AccessTokenCache
from .config import ServerConfig
from .errors import OAuthError
from .models import CredentialKey, CredentialKind
from .stores import SecretStore


@dataclass(frozen=True)
class OAuthMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    authorization_response_iss_parameter_supported: bool = False


@dataclass(frozen=True, repr=False)
class OAuthCredential:
    refresh_token: str
    issuer: str
    resource: str
    client_id: str

    def serialize(self) -> str:
        return json.dumps(
            {
                "version": 1,
                "refresh_token": self.refresh_token,
                "issuer": self.issuer,
                "resource": self.resource,
                "client_id": self.client_id,
            },
            separators=(",", ":"),
        )

    @classmethod
    def parse(cls, value: str) -> "OAuthCredential":
        try:
            raw = json.loads(value)
            if raw.get("version") != 1:
                raise ValueError("version")
            fields = ("refresh_token", "issuer", "resource", "client_id")
            if not all(isinstance(raw.get(field), str) and raw[field] for field in fields):
                raise ValueError("fields")
            return cls(**{field: raw[field] for field in fields})
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            raise OAuthError("Stored OAuth refresh credential is malformed.") from exc

    def __repr__(self) -> str:
        return (
            "OAuthCredential(refresh_token=<redacted>, "
            f"issuer={self.issuer!r}, resource={self.resource!r}, client_id={self.client_id!r})"
        )


def create_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def protected_resource_metadata_url(resource: str) -> str:
    parsed = urlsplit(resource)
    if parsed.scheme != "https" or not parsed.netloc:
        raise OAuthError("OAuth resource must be an absolute HTTPS URI.")
    suffix = parsed.path.rstrip("/")
    path = "/.well-known/oauth-protected-resource" + suffix
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def authorization_server_metadata_urls(issuer: str) -> tuple[str, str]:
    parsed = urlsplit(issuer)
    if parsed.scheme != "https" or not parsed.netloc:
        raise OAuthError("OAuth issuer must be an absolute HTTPS URI.")
    issuer_path = parsed.path.rstrip("/")
    oauth_path = "/.well-known/oauth-authorization-server" + issuer_path
    oidc_path = issuer_path + "/.well-known/openid-configuration"
    return (
        urlunsplit((parsed.scheme, parsed.netloc, oauth_path, "", "")),
        urlunsplit((parsed.scheme, parsed.netloc, oidc_path, "", "")),
    )


def build_authorization_url(
    metadata: OAuthMetadata,
    server: ServerConfig,
    redirect_uri: str,
    state: str,
    challenge: str,
    client_id: str | None = None,
) -> str:
    auth = server.auth
    parameters: list[tuple[str, str]] = [
        ("response_type", "code"),
        ("client_id", _required(client_id or auth.client_id, "client_id")),
        ("redirect_uri", redirect_uri),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("resource", _required(auth.resource, "resource")),
    ]
    if auth.scopes:
        parameters.append(("scope", " ".join(auth.scopes)))
    separator = "&" if urlsplit(metadata.authorization_endpoint).query else "?"
    return metadata.authorization_endpoint + separator + urlencode(parameters)


class OAuthManager:
    def __init__(
        self,
        store: SecretStore,
        access_tokens: AccessTokenCache,
        *,
        client: httpx.AsyncClient | None = None,
        browser_open: Callable[[str], bool] = webbrowser.open,
    ) -> None:
        self._store = store
        self._access_tokens = access_tokens
        self._client = client
        self._browser_open = browser_open

    async def discover(self, server: ServerConfig) -> OAuthMetadata:
        if server.auth.type != "oauth-pkce":
            raise OAuthError(f"Server {server.name!r} does not use OAuth PKCE.")
        resource = _required(server.auth.resource, "resource")
        client, owned = self._http_client()
        try:
            prm = await _get_json(client, protected_resource_metadata_url(resource))
            if prm.get("resource") != resource:
                raise OAuthError("Protected Resource Metadata resource does not match configuration.")
            advertised = prm.get("authorization_servers")
            if not isinstance(advertised, list) or not all(
                isinstance(value, str) and value for value in advertised
            ) or not advertised:
                raise OAuthError("Protected Resource Metadata has no authorization_servers.")
            configured_issuer = server.auth.issuer
            if configured_issuer:
                if configured_issuer not in advertised:
                    raise OAuthError("Configured OAuth issuer was not advertised by the MCP server.")
                issuer = configured_issuer
            elif len(advertised) == 1:
                issuer = advertised[0]
            else:
                raise OAuthError("Multiple OAuth issuers were advertised; pin auth.issuer in YAML.")
            raw_metadata: dict[str, Any] | None = None
            last_error: OAuthError | None = None
            for metadata_url in authorization_server_metadata_urls(issuer):
                try:
                    raw_metadata = await _get_json(client, metadata_url)
                    break
                except OAuthError as exc:
                    last_error = exc
            if raw_metadata is None:
                raise OAuthError("OAuth authorization server discovery failed.") from last_error
            if raw_metadata.get("issuer") != issuer:
                raise OAuthError("Authorization server metadata issuer mismatch.")
            authorization_endpoint = _metadata_https_url(
                raw_metadata, "authorization_endpoint"
            )
            token_endpoint = _metadata_https_url(raw_metadata, "token_endpoint")
            registration_endpoint = _metadata_optional_https_url(
                raw_metadata, "registration_endpoint"
            )
            _match_pin(server.auth.authorization_url, authorization_endpoint, "authorization_url")
            _match_pin(server.auth.token_url, token_endpoint, "token_url")
            if server.auth.registration_url is not None:
                if registration_endpoint is None:
                    raise OAuthError(
                        "Configured OAuth registration_url was not advertised by the authorization server."
                    )
                _match_pin(
                    server.auth.registration_url,
                    registration_endpoint,
                    "registration_url",
                )
            methods = raw_metadata.get("code_challenge_methods_supported")
            if not isinstance(methods, list) or "S256" not in methods:
                raise OAuthError("Authorization server does not advertise PKCE S256 support.")
            token_auth = raw_metadata.get("token_endpoint_auth_methods_supported")
            if isinstance(token_auth, list) and "none" not in token_auth:
                raise OAuthError("Authorization server does not support a public OAuth client.")
            supported_scopes = raw_metadata.get("scopes_supported")
            if isinstance(supported_scopes, list):
                missing = set(server.auth.scopes) - set(supported_scopes)
                if missing:
                    raise OAuthError(
                        "Authorization server does not advertise requested scope(s): "
                        + ", ".join(sorted(missing))
                    )
            return OAuthMetadata(
                issuer=issuer,
                authorization_endpoint=authorization_endpoint,
                token_endpoint=token_endpoint,
                registration_endpoint=registration_endpoint,
                authorization_response_iss_parameter_supported=bool(
                    raw_metadata.get("authorization_response_iss_parameter_supported", False)
                ),
            )
        finally:
            if owned:
                await client.aclose()

    async def login(self, server: ServerConfig) -> None:
        metadata = await self.discover(server)
        verifier, challenge = create_pkce_pair()
        state = secrets.token_urlsafe(32)
        callback = asyncio.get_running_loop().create_future()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                first_line = await asyncio.wait_for(reader.readline(), timeout=5)
                if len(first_line) > 8192:
                    raise OAuthError("OAuth callback request was too large.")
                parts = first_line.decode("ascii", errors="replace").strip().split(" ")
                if len(parts) != 3 or parts[0] != "GET":
                    raise OAuthError("OAuth callback used an unsupported HTTP request.")
                callback_url = urlsplit(parts[1])
                if callback_url.path != "/callback":
                    raise OAuthError("OAuth callback used an unexpected path.")
                query = parse_qs(callback_url.query, keep_blank_values=True)
                result = {key: values[0] for key, values in query.items() if values}
                if not callback.done():
                    callback.set_result(result)
                body = b"OAuth login completed. You can close this window."
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + body
                )
                await writer.drain()
            except Exception as exc:
                if not callback.done():
                    callback.set_exception(exc)
            finally:
                writer.close()
                await writer.wait_closed()

        listener = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            port = listener.sockets[0].getsockname()[1]
            redirect_uri = f"http://127.0.0.1:{port}/callback"
            client_id = server.auth.client_id or await self.register_client(
                metadata, server, redirect_uri
            )
            authorization_url = build_authorization_url(
                metadata, server, redirect_uri, state, challenge, client_id
            )
            if not self._browser_open(authorization_url):
                raise OAuthError("Could not open the system browser for OAuth login.")
            try:
                response = await asyncio.wait_for(
                    callback, timeout=server.auth.callback_timeout_seconds
                )
            except TimeoutError as exc:
                raise OAuthError("Timed out waiting for the OAuth callback.") from exc
        finally:
            listener.close()
            await listener.wait_closed()

        error = response.get("error")
        if error:
            raise OAuthError(f"Authorization server returned OAuth error {error!r}.")
        returned_state = response.get("state", "")
        if not hmac.compare_digest(returned_state, state):
            raise OAuthError("OAuth callback state mismatch.")
        response_issuer = response.get("iss")
        if response_issuer is not None and response_issuer != metadata.issuer:
            raise OAuthError("OAuth callback issuer mismatch.")
        if metadata.authorization_response_iss_parameter_supported and not response_issuer:
            raise OAuthError("OAuth callback omitted the required issuer identifier.")
        code = response.get("code")
        if not code:
            raise OAuthError("OAuth callback did not contain an authorization code.")
        token = await self._token_request(
            metadata.token_endpoint,
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
                "resource": _required(server.auth.resource, "resource"),
            },
        )
        refresh_token = token.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise OAuthError(
                "Authorization server did not issue a refresh token; mcp-buddy will not persist an access token."
            )
        self._save_credential(server, metadata.issuer, client_id, refresh_token)
        self._cache_access_token(server, token)

    async def register_client(
        self,
        metadata: OAuthMetadata,
        server: ServerConfig,
        redirect_uri: str,
    ) -> str:
        endpoint = metadata.registration_endpoint
        if endpoint is None:
            raise OAuthError(
                "OAuth client_id is not configured and the authorization server does not advertise Dynamic Client Registration."
            )
        registration: dict[str, Any] = {
            "client_name": "mcp-buddy",
            "client_uri": "https://github.com/Jur-An/mcp-buddy",
            "software_id": "mcp-buddy",
            "application_type": "native",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
        if server.auth.scopes:
            registration["scope"] = " ".join(server.auth.scopes)
        client, owned = self._http_client()
        try:
            try:
                response = await client.post(
                    endpoint,
                    json=registration,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                )
            except httpx.HTTPError as exc:
                raise OAuthError(
                    "OAuth Dynamic Client Registration endpoint could not be reached."
                ) from exc
            if response.status_code != 201:
                raise OAuthError(
                    "OAuth Dynamic Client Registration returned "
                    f"HTTP {response.status_code}."
                )
            payload = _response_json(
                response, "OAuth Dynamic Client Registration endpoint"
            )
            client_id = payload.get("client_id")
            if not isinstance(client_id, str) or not client_id:
                raise OAuthError(
                    "OAuth Dynamic Client Registration response has no client_id."
                )
            if payload.get("client_secret"):
                raise OAuthError(
                    "Authorization server returned a client_secret, but mcp-buddy only supports public clients."
                )
            auth_method = payload.get("token_endpoint_auth_method")
            if auth_method is not None and auth_method != "none":
                raise OAuthError(
                    "Dynamically registered client does not use token_endpoint_auth_method=none."
                )
            redirect_uris = payload.get("redirect_uris")
            if isinstance(redirect_uris, list) and redirect_uri not in redirect_uris:
                raise OAuthError(
                    "Dynamically registered client does not allow the current loopback callback."
                )
            return client_id
        finally:
            if owned:
                await client.aclose()

    async def access_token(self, server: ServerConfig, *, force_refresh: bool = False) -> str:
        key = self.credential_key(server)
        if not force_refresh:
            cached = self._access_tokens.get(key)
            if cached is not None:
                return cached.reveal()
        return await self.refresh(server)

    async def refresh(self, server: ServerConfig) -> str:
        key = self.credential_key(server)
        stored = self._store.get(key)
        if stored is None or stored.kind != CredentialKind.REFRESH_TOKEN:
            raise OAuthError(f"No OAuth login exists for server {server.name!r}; run mcp-buddy login.")
        credential = OAuthCredential.parse(stored.secret.reveal())
        metadata = await self.discover(server)
        if (
            credential.issuer != metadata.issuer
            or credential.resource != _required(server.auth.resource, "resource")
            or (
                server.auth.client_id is not None
                and credential.client_id != server.auth.client_id
            )
        ):
            raise OAuthError("Stored refresh token is bound to different OAuth metadata.")
        token = await self._token_request(
            metadata.token_endpoint,
            {
                "grant_type": "refresh_token",
                "refresh_token": credential.refresh_token,
                "client_id": credential.client_id,
                "resource": credential.resource,
            },
        )
        rotated = token.get("refresh_token")
        if rotated is not None:
            if not isinstance(rotated, str) or not rotated:
                raise OAuthError("Authorization server returned an invalid rotated refresh token.")
            self._save_credential(
                server, metadata.issuer, credential.client_id, rotated
            )
        self._cache_access_token(server, token)
        cached = self._access_tokens.get(key)
        if cached is None:
            raise OAuthError("Received access token expired immediately.")
        return cached.reveal()

    def logout(self, server: ServerConfig) -> bool:
        key = self.credential_key(server)
        self._access_tokens.discard(key)
        return self._store.delete(key)

    def credential_key(self, server: ServerConfig) -> CredentialKey:
        return CredentialKey(
            server.name,
            server.auth.account,
            server.auth.credential_profile or "default",
        )

    async def _token_request(self, url: str, form: dict[str, str]) -> dict[str, Any]:
        client, owned = self._http_client()
        try:
            try:
                response = await client.post(
                    url,
                    data=form,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                )
            except httpx.HTTPError as exc:
                raise OAuthError("OAuth token endpoint could not be reached.") from exc
            if response.status_code != 200:
                raise OAuthError(
                    f"OAuth token endpoint returned HTTP {response.status_code}."
                )
            payload = _response_json(response, "OAuth token endpoint")
            access_token = payload.get("access_token")
            token_type = payload.get("token_type")
            if not isinstance(access_token, str) or not access_token:
                raise OAuthError("OAuth token response has no access_token.")
            if not isinstance(token_type, str) or token_type.lower() != "bearer":
                raise OAuthError("OAuth token response is not a Bearer token.")
            return payload
        finally:
            if owned:
                await client.aclose()

    def _save_credential(
        self,
        server: ServerConfig,
        issuer: str,
        client_id: str,
        refresh_token: str,
    ) -> None:
        credential = OAuthCredential(
            refresh_token=refresh_token,
            issuer=issuer,
            resource=_required(server.auth.resource, "resource"),
            client_id=client_id,
        )
        self._store.set(
            self.credential_key(server), CredentialKind.REFRESH_TOKEN, credential.serialize()
        )

    def _cache_access_token(self, server: ServerConfig, token: dict[str, Any]) -> None:
        expires_in = token.get("expires_in", 300)
        if not isinstance(expires_in, (int, float)) or isinstance(expires_in, bool) or expires_in <= 0:
            raise OAuthError("OAuth token response has invalid expires_in.")
        self._access_tokens.put(
            self.credential_key(server),
            token["access_token"],
            datetime.now(timezone.utc) + timedelta(seconds=float(expires_in)),
        )

    def _http_client(self) -> tuple[httpx.AsyncClient, bool]:
        if self._client is not None:
            return self._client, False
        return httpx.AsyncClient(timeout=15, follow_redirects=False), True


async def _get_json(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    try:
        response = await client.get(
            url, headers={"Accept": "application/json"}, follow_redirects=False
        )
    except httpx.HTTPError as exc:
        raise OAuthError("OAuth metadata endpoint could not be reached.") from exc
    if response.status_code != 200:
        raise OAuthError(f"OAuth metadata endpoint returned HTTP {response.status_code}.")
    return _response_json(response, "OAuth metadata endpoint")


def _response_json(response: httpx.Response, label: str) -> dict[str, Any]:
    try:
        value = response.json()
    except (ValueError, UnicodeDecodeError) as exc:
        raise OAuthError(f"{label} returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise OAuthError(f"{label} returned a non-object JSON document.")
    return value


def _metadata_https_url(metadata: dict[str, Any], field: str) -> str:
    value = metadata.get(field)
    if not isinstance(value, str):
        raise OAuthError(f"Authorization server metadata has no {field}.")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise OAuthError(f"Authorization server {field} is not a safe HTTPS URL.")
    return value


def _metadata_optional_https_url(
    metadata: dict[str, Any], field: str
) -> str | None:
    if field not in metadata:
        return None
    return _metadata_https_url(metadata, field)


def _match_pin(configured: str | None, discovered: str, label: str) -> None:
    if configured is not None and configured != discovered:
        raise OAuthError(f"Discovered OAuth {label} does not match the configured pin.")


def _required(value: str | None, label: str) -> str:
    if not value:
        raise OAuthError(f"OAuth {label} is required.")
    return value
