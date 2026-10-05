# mcp-buddy

`mcp-buddy` is a local Streamable HTTP MCP proxy with OAuth 2.1 Authorization
Code + PKCE. It keeps short-lived access tokens only in process memory and
persists refresh tokens through the operating system credential store.

## What it does

- discovers Protected Resource Metadata and OAuth/OIDC authorization-server
  metadata;
- opens the system browser and receives the authorization response on a random
  `127.0.0.1` callback port;
- uses PKCE S256, validates `state` and the authorization-response issuer, and
  sends the MCP `resource` parameter in authorization and token requests;
- uses a configured public `client_id` when present, or falls back to Dynamic
  Client Registration for authorization servers that advertise it;
- stores only the refresh token plus its non-secret issuer/resource/client
  binding; rotated refresh tokens replace previous values;
- exposes each allowlisted remote server at
  `http://127.0.0.1:8765/mcp/<server-name>`;
- injects Bearer authorization upstream, refreshes once after HTTP 401, and
  streams JSON or SSE responses;
- supports current MCP request headers and preserves the legacy
  `Mcp-Session-Id` header for older servers.

The proxy drops incoming `Authorization`, cookies and unrelated headers. It
rejects non-loopback browser origins and cannot bind to `0.0.0.0` or a LAN
address. Redirects are disabled for metadata, token and MCP requests.

## Secret storage

- Windows and macOS use the native backend selected by Python `keyring`.
- Linux uses Secret Service/KWallet when available.
- Linux without a usable native backend falls back to an AES-256-GCM encrypted
  vault protected by a passphrase-derived scrypt key.
- Access tokens use `AccessTokenCache`, which has no persistence API.
- YAML, CLI options, logs and the executable never contain secrets.

The encrypted Linux fallback cannot start unattended without an unlock source.
This is deliberate: putting its passphrase in a file, environment variable or
command line would only move the bootstrap secret.

## Configuration

Copy `mcp-buddy.example.yaml`, or use `mcp-buddy.fcm.example.yaml` for FCM. A
pre-registered public OAuth client ID is optional. When `client_id` is absent,
`login` uses the discovered Dynamic Client Registration endpoint and registers
a native public client for its exact loopback callback. It requests
`token_endpoint_auth_method: none`; a response containing a client secret is
rejected.

`issuer`, `authorization_url`, `token_url` and `registration_url`, when
present, are security pins and must match discovery metadata. Pinning `issuer`
is recommended and becomes required when a resource advertises more than one
authorization server. DCR is retained by MCP for backwards compatibility and
is used here because FCM currently advertises DCR rather than Client ID
Metadata Documents.

The authorization server must issue a refresh token because `mcp-buddy` refuses
to persist an access token. Add `offline_access` only if the provider advertises
or requires that scope.

## Installation and use

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
mcp-buddy validate-config mcp-buddy.yaml
mcp-buddy login mcp-buddy.yaml fcm
mcp-buddy serve mcp-buddy.yaml --host 127.0.0.1 --port 8765
```

Point the MCP client at:

```text
http://127.0.0.1:8765/mcp/fcm
```

Other credential commands remain available:

```text
mcp-buddy backend
mcp-buddy check fcm andjurek --profile fcm-prod
mcp-buddy logout mcp-buddy.yaml fcm
```

`login` opens a browser. Its local callback expires after 180 seconds by
default; `callback_timeout_seconds` can be set to 30-900 in the server's `auth`
section. On a successful DCR login, the issued non-secret `client_id` is bound
to the discovered issuer and persisted inside the refresh-token credential.
Subsequent `serve` runs reuse it during refresh and do not register again.

## Building an executable

Build separately on each target operating system and architecture:

```powershell
python -m pip install -e ".[build]"
pyinstaller --onefile --name mcp-buddy --clean mcp_buddy_entry.py
```

Do not bundle a populated configuration, vault or credential into the binary.
Production Windows and macOS artifacts should be code-signed; macOS artifacts
should also be notarized.

## Tests

```powershell
python -B -m unittest discover -s tests -v
```
