import pytest
import pytest_asyncio
import base58

from didcomm_messaging.crypto.backend.askar import AskarSecretsManager
from didcomm_messaging.legacy.askar import AskarLegacyCryptoService, AskarSecretKey
from didcomm_messaging.legacy.nacl import InMemSecretsManager, NaclLegacyCryptoService

from aries_askar import Key, KeyAlg, Store

from didcomm_messaging.legacy.packaging import LegacyPackagingService


@pytest.fixture
def nacl():
    yield NaclLegacyCryptoService()


@pytest.fixture
def askar():
    yield AskarLegacyCryptoService()


@pytest.fixture
def nacl_secrets():
    yield InMemSecretsManager()


@pytest_asyncio.fixture
async def store():
    key = Store.generate_raw_key()
    yield await Store.provision("sqlite://:memory:", key_method="RAW", pass_key=key)


@pytest_asyncio.fixture
async def askar_secrets(store: Store):
    yield AskarSecretsManager(store)


@pytest.fixture
def alice(nacl_secrets: InMemSecretsManager):
    """Generate alice's keys."""
    yield nacl_secrets.create()


@pytest.fixture
def bob(nacl_secrets: InMemSecretsManager):
    """Generate bob's keys."""
    yield nacl_secrets.create()


@pytest.fixture
def packer():
    yield LegacyPackagingService()


@pytest_asyncio.fixture
async def askarlice(store: Store):
    """Generate alice's keys."""

    key = Key.generate(KeyAlg.ED25519)
    kid = base58.b58encode(key.get_public_bytes()).decode()
    async with store.session() as session:
        await session.insert_key(kid, key)
    return AskarSecretKey(key, kid)


@pytest_asyncio.fixture
async def bobskar(store: Store):
    """Generate bob's keys."""
    key = Key.generate(KeyAlg.ED25519)
    kid = base58.b58encode(key.get_public_bytes()).decode()
    async with store.session() as session:
        await session.insert_key(kid, key)
    return AskarSecretKey(key, kid)
