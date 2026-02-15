"""Basic Crypto Implementations."""

import atexit
import json
import shutil
from pathlib import Path
from typing import Callable, Dict, Optional

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


class FileBasedSecretsManager(SecretsManager[S]):
    """File-based Secrets Manager with in-memory caching and auto-save.

    Secrets are stored in memory for fast access and persisted to a JSONL file.
    The file is saved automatically on program exit via atexit, and can also
    be flushed explicitly using the flush() method.

    Requires serializer and deserializer callbacks to convert between SecretKey
    objects and their JSON-serializable representation.
    """

    def __init__(
        self,
        path: str,
        serializer: Callable[[S], Dict],
        deserializer: Callable[[str, Dict], S],
        secrets: Optional[dict] = None,
    ):
        """Initialize the FileBasedSecretsManager.

        Args:
            path: Full path to the JSONL file for storing secrets.
            serializer: Callback to serialize a SecretKey to a dict.
            deserializer: Callback to deserialize a dict to a SecretKey.
                Takes (kid, serialized_dict) as arguments.
            secrets: Optional initial secrets to load (file takes precedence).
        """
        self._path = Path(path)
        self._serializer = serializer
        self._deserializer = deserializer
        self._secrets: Dict[str, S] = secrets or {}

        if self._path.exists():
            with open(self._path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    kid = data.get("kid")
                    if kid:
                        self._secrets[kid] = self._deserializer(kid, data)

        atexit.register(self._sync)

    @property
    def path(self) -> str:
        """Return the path to the secrets file."""
        return str(self._path)

    async def get_secret_by_kid(self, kid: str) -> Optional[S]:
        """Get a secret by its kid."""
        return self._secrets.get(kid)

    async def add_secret(self, secret: S) -> None:
        """Add a secret to the secrets manager."""
        self._secrets[secret.kid] = secret

    async def flush(self) -> None:
        """Explicitly save secrets to the file."""
        self._sync()

    def _sync(self) -> None:
        """Write secrets to file (called on atexit and flush)."""
        tmp_path = self._path.with_suffix(".tmp")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w") as f:
            for kid, secret in self._secrets.items():
                data = self._serializer(secret)
                data["kid"] = kid
                f.write(json.dumps(data) + "\n")
        shutil.move(tmp_path, self._path)
