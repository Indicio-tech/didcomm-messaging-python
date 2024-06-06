from aries_askar import Key, KeyAlg, Store
import base58
import did_peer_4
from did_peer_4.input_doc import KeySpec, input_doc_from_keys_and_services
import pytest
import pytest_asyncio

from didcomm_messaging.crypto.backend.askar import AskarKey, AskarSecretsManager
from didcomm_messaging.resolver import DIDResolver
from didcomm_messaging.resolver.peer import Peer4
from didcomm_messaging.v1.crypto.askar import AskarV1CryptoService
from didcomm_messaging.v1.crypto.nacl import (
    EdPublicKey,
    InMemSecretsManager,
    NaclV1CryptoService,
)
from didcomm_messaging.v1.messaging import V1DIDCommMessaging
from didcomm_messaging.v1.packaging import V1PackagingService


@pytest.fixture
def nacl():
    yield NaclV1CryptoService()


@pytest.fixture
def askar():
    yield AskarV1CryptoService()


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
    yield V1PackagingService()


@pytest.fixture
def resolver():
    yield Peer4()


@pytest.fixture
def alice(
    nacl: NaclV1CryptoService,
    nacl_secrets: InMemSecretsManager,
    packer: V1PackagingService,
    resolver: DIDResolver,
):
    yield V1DIDCommMessaging(nacl, nacl_secrets, resolver, packer)


@pytest.fixture
def bob(
    askar: AskarV1CryptoService,
    askar_secrets: AskarSecretsManager,
    resolver: DIDResolver,
    packer: V1PackagingService,
):
    yield V1DIDCommMessaging(askar, askar_secrets, resolver, packer)


@pytest_asyncio.fixture
async def bob_key(store: Store):
    """Generate bob's keys."""
    key = Key.generate(KeyAlg.ED25519)
    kid = base58.b58encode(key.get_public_bytes()).decode()
    async with store.session() as session:
        await session.insert_key(kid, key)
    yield AskarKey(key, kid)


@pytest.fixture
def alice_key(nacl_secrets: InMemSecretsManager):
    """Generate alice's keys."""
    keypair = nacl_secrets.create()
    yield EdPublicKey(keypair.verkey)


@pytest.fixture
def alice_did(alice_key: EdPublicKey):
    input_doc = input_doc_from_keys_and_services(
        [KeySpec(alice_key.multikey, relationships=["authentication"])],
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
def bob_did(bob_key: AskarKey):
    input_doc = input_doc_from_keys_and_services(
        [KeySpec(bob_key.multikey, relationships=["authentication"])],
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
