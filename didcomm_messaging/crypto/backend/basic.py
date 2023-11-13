"""Basic Crypto Implementations."""

from typing import Optional
from didcomm_messaging.crypto.base import S, SecretsManager


class InMemorySecretsManager(SecretsManager[S]):
    """In Memory Secrets Manager."""

    def __init__(self, secrets: Optional[dict] = None):
        """Initialize the InMemorySecretsManager."""
        self.secrets = secrets or {}

    async def get_secret_by_kid(self, kid: str) -> Optional[S]:
        """Get a secret by its kid."""
        return self.secrets.get(kid)

    async def add_secret(self, secret: S) -> None:
        """Add a secret to the secrets manager."""
        self.secrets[secret.kid] = secret
