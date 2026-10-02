# mcp-buddy

`mcp-buddy` is the security and credential-storage foundation for a future local
MCP broker. Version `0.1.0` implements credential storage, an in-memory access
token cache, safe configuration loading and log redaction. It does **not** yet
proxy MCP traffic or implement OAuth authorization flows.

## Security model

- Application code uses one `SecretStore` API.
- Windows and macOS use the native backend selected by Python `keyring`.
- Linux uses the native Secret Service/KWallet backend when available.
- Linux without a usable native backend falls back to an AES-256-GCM encrypted
  vault protected by a passphrase-derived scrypt key.
- Access tokens can only be stored in `AccessTokenCache`, which is process
  memory and has no persistence API.
- Persistent stores accept only refresh tokens and long-lived credentials.
- Secrets are entered through an interactive hidden prompt. CLI options,
  environment variables and YAML secret values are intentionally unsupported.
- YAML is schema-validated and secret-like fields are rejected recursively.
- Secret values use a redacted representation, and application logging installs
  a defense-in-depth redaction filter.

The encrypted Linux fallback cannot start unattended without an unlock source.
This is deliberate: storing its passphrase in a file, environment variable or
command line would move rather than solve the bootstrap-secret problem.

## Installation

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
```

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

## CLI

The CLI never accepts a secret as an argument and never prints a stored value.

```text
mcp-buddy backend
mcp-buddy store fcm andjurek --profile fcm-prod --kind refresh-token
mcp-buddy check fcm andjurek --profile fcm-prod
mcp-buddy delete fcm andjurek --profile fcm-prod
mcp-buddy validate-config mcp-buddy.yaml
```

`store` reads the credential through `getpass`. On headless Linux using the
encrypted fallback, the vault passphrase is also requested through `getpass`.

## Building an executable

Build separately on every target OS and architecture:

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

## Next scope

The next layer can add OAuth 2.1/PKCE and a loopback MCP proxy. It should obtain
refresh tokens through this package, keep access tokens in `AccessTokenCache`,
and inject authorization only for an exact allowlisted MCP origin and resource.
