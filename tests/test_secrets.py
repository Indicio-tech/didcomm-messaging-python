import pytest
from didcomm_messaging.crypto import SecretKey

from didcomm_messaging.crypto.basic import InMemorySecretsManager


class TestSecretKey(SecretKey):
    def __init__(self, kid) -> None:
        self._kid = kid

    @property
    def kid(self):
        return self._kid


@pytest.fixture()
def in_memory_secrets_manager():
    yield InMemorySecretsManager()


@pytest.fixture()
def secret():
    kid = "did:example:alice#key-1"
    key = TestSecretKey(kid=kid)
    yield key


@pytest.mark.asycnio
async def test_in_memory_secrets(
    in_memory_secrets_manager: InMemorySecretsManager, secret: TestSecretKey
):
    await in_memory_secrets_manager.add_secret(secret)

    assert in_memory_secrets_manager.get_secret_by_kid(secret.kid) == secret
