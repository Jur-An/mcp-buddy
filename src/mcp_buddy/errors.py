class McpBuddyError(RuntimeError):
    """Base error for expected mcp-buddy failures."""


class InvalidCredentialError(McpBuddyError):
    """A credential is empty, malformed or not allowed in persistent storage."""


class SecretStoreUnavailable(McpBuddyError):
    """No permitted persistent secret store is available."""


class VaultDecryptionError(McpBuddyError):
    """The encrypted vault could not be decrypted."""


class UnsafeConfigurationError(McpBuddyError):
    """Configuration contains a secret-like field or unsupported structure."""


class OAuthError(McpBuddyError):
    """OAuth discovery, authorization or token refresh failed safely."""


class ProxyError(McpBuddyError):
    """The local MCP proxy could not safely forward a request."""
