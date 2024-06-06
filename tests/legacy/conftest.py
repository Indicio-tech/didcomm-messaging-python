from aries_askar import Key, KeyAlg, Store
import base58
from did_peer_4.input_doc import KeySpec, input_doc_from_keys_and_services
import did_peer_4
import pytest
import pytest_asyncio

from didcomm_messaging.crypto.backend.askar import AskarKey, AskarSecretsManager
from didcomm_messaging.legacy.askar import AskarLegacyCryptoService, AskarSecretKey
from didcomm_messaging.legacy.messaging import LegacyDIDCommMessaging
from didcomm_messaging.legacy.nacl import (
    EdPublicKey,
    InMemSecretsManager,
    KeyPair,
    NaclLegacyCryptoService,
)
from didcomm_messaging.legacy.packaging import LegacyPackagingService
from didcomm_messaging.resolver import DIDResolver
from didcomm_messaging.resolver.peer import Peer4


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
def packer():
    yield LegacyPackagingService()


@pytest.fixture
def resolver():
    yield Peer4()


@pytest.fixture
def alice(
    nacl: NaclLegacyCryptoService,
    nacl_secrets: InMemSecretsManager,
    packer: LegacyPackagingService,
    resolver: DIDResolver,
):
    yield LegacyDIDCommMessaging(nacl, nacl_secrets, resolver, packer)


@pytest.fixture
def bob(
    askar: AskarLegacyCryptoService,
    askar_secrets: AskarSecretsManager,
    resolver: DIDResolver,
    packer: LegacyPackagingService,
):
    yield LegacyDIDCommMessaging(askar, askar_secrets, resolver, packer)


@pytest_asyncio.fixture
async def bob_key(store: Store):
    """Generate bob's keys."""
    key = Key.generate(KeyAlg.ED25519)
    kid = base58.b58encode(key.get_public_bytes()).decode()
    async with store.session() as session:
        await session.insert_key(kid, key)
    return AskarSecretKey(key, kid)


@pytest.fixture
def alice_key(nacl_secrets: InMemSecretsManager):
    """Generate alice's keys."""
    yield nacl_secrets.create()


@pytest.fixture
def alice_did(alice_key: KeyPair):
    alice_pub = EdPublicKey(alice_key.verkey)
    input_doc = input_doc_from_keys_and_services(
        [KeySpec(alice_pub.multikey, relationships=["authentication"])],
        [
            {
                "id": "#didcomm",
                "type": "did-communication",
                "recipientKeys": ["#key-0"],
                "serviceEndpoint": "https://example.com",
            }
        ],
    )
    return did_peer_4.encode(input_doc, validate=True)


@pytest.fixture
def bob_did(bob_key: AskarSecretKey):
    bob_pub = AskarKey(bob_key.key, bob_key.kid)
    input_doc = input_doc_from_keys_and_services(
        [KeySpec(bob_pub.multikey, relationships=["authentication"])],
        [
            {
                "id": "#didcomm",
                "type": "did-communication",
                "recipientKeys": ["#key-0"],
                "serviceEndpoint": "https://example.com",
            }
        ],
    )
    return did_peer_4.encode(input_doc, validate=True)
