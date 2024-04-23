"""Test PackagingService."""

import pytest

from aries_askar import Key, KeyAlg
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.crypto.backend.basic import InMemorySecretsManager
from didcomm_messaging.crypto.base import CryptoService
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.multiformats import multibase
from didcomm_messaging.multiformats import multicodec
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.resolver import DIDResolver, PrefixResolver
from did_peer_2 import KeySpec, generate


@pytest.fixture
def secrets():
    """Fixture for secrets."""
    yield InMemorySecretsManager()


@pytest.fixture
def crypto():
    """Fixture for crypto."""
    yield AskarCryptoService()


@pytest.fixture
def resolver():
    yield PrefixResolver({"did:peer:2": Peer2(), "did:peer:4": Peer4()})


@pytest.fixture
def packaging():
    """Fixture for packaging."""
    yield PackagingService()


# TODO More thorough tests
@pytest.mark.asyncio
async def test_packer_basic(
    crypto: CryptoService,
    secrets: InMemorySecretsManager,
    resolver: DIDResolver,
    packaging: PackagingService,
):
    """Test basic packaging.

    This is a happy path test.
    """
    verkey = Key.generate(KeyAlg.ED25519)
    xkey = Key.generate(KeyAlg.X25519)
    did = generate(
        [
            KeySpec.verification(
                multibase.encode(
                    multicodec.wrap("ed25519-pub", verkey.get_public_bytes()),
                    "base58btc",
                )
            ),
            KeySpec.key_agreement(
                multibase.encode(
                    multicodec.wrap("x25519-pub", xkey.get_public_bytes()), "base58btc"
                )
            ),
        ],
        [],
    )
    await secrets.add_secret(AskarSecretKey(verkey, f"{did}#key-1"))
    await secrets.add_secret(AskarSecretKey(xkey, f"{did}#key-2"))
    message = b"hello world"
    packed = await packaging.pack(crypto, resolver, secrets, message, [did], did)
    unpacked, meta = await packaging.unpack(crypto, resolver, secrets, packed)
    assert unpacked == message
