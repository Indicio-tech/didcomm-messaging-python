import json
import os
import tempfile

import pytest
from didcomm_messaging.crypto import SecretKey

from didcomm_messaging.crypto.backend.basic import (
    FileBasedSecretsManager,
    InMemorySecretsManager,
)


class MockSecretKey(SecretKey):
    def __init__(self, kid) -> None:
        self._kid = kid

    @property
    def kid(self):
        return self._kid

    def __repr__(self):
        return f"MockSecretKey({self._kid!r})"


@pytest.fixture()
def in_memory_secrets_manager():
    yield InMemorySecretsManager()


@pytest.fixture()
def secret():
    kid = "did:example:alice#key-1"
    key = MockSecretKey(kid=kid)
    yield key


@pytest.mark.asyncio
async def test_in_memory_secrets(
    in_memory_secrets_manager: InMemorySecretsManager, secret: MockSecretKey
):
    await in_memory_secrets_manager.add_secret(secret)

    assert await in_memory_secrets_manager.get_secret_by_kid(secret.kid) == secret


@pytest.fixture()
def temp_secrets_file():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)
    if os.path.exists(path + ".tmp"):
        os.remove(path + ".tmp")


def serializer(secret: MockSecretKey):
    return {"multikey": f"multikey:{secret.kid}"}


def deserializer(kid: str, data: dict):
    return MockSecretKey(kid=kid)


@pytest.mark.asyncio
async def test_file_based_secrets(temp_secrets_file):
    manager = FileBasedSecretsManager(temp_secrets_file, serializer, deserializer)

    secret = MockSecretKey(kid="did:example:alice#key-1")
    await manager.add_secret(secret)

    result = await manager.get_secret_by_kid(secret.kid)
    assert result == secret

    await manager.flush()

    with open(temp_secrets_file) as f:
        lines = f.readlines()

    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["kid"] == secret.kid
    assert data["multikey"] == f"multikey:{secret.kid}"


@pytest.mark.asyncio
async def test_file_based_secrets_loads_existing(temp_secrets_file):
    initial_data = [{"kid": "did:example:alice#key-1", "multikey": "multikey:existing"}]
    with open(temp_secrets_file, "w") as f:
        for item in initial_data:
            f.write(json.dumps(item) + "\n")

    manager = FileBasedSecretsManager(temp_secrets_file, serializer, deserializer)

    secret = await manager.get_secret_by_kid("did:example:alice#key-1")
    assert secret is not None
    assert secret.kid == "did:example:alice#key-1"


@pytest.mark.asyncio
async def test_file_based_secrets_empty_file(temp_secrets_file):
    """Test that empty file doesn't cause error."""
    with open(temp_secrets_file, "w") as f:
        f.write("")

    manager = FileBasedSecretsManager(temp_secrets_file, serializer, deserializer)
    result = await manager.get_secret_by_kid("any-key")
    assert result is None
