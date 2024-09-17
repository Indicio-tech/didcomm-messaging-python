"""Test forwarding."""

from aries_askar import Key, KeyAlg, Store
import base58
import did_peer_4
from did_peer_4.input_doc import KeySpec, input_doc_from_keys_and_services
import pytest
from didcomm_messaging.crypto.backend.askar import AskarKey
from didcomm_messaging.v1.crypto.nacl import EdPublicKey, InMemSecretsManager
from didcomm_messaging.v1.messaging import V1DIDCommMessaging


@pytest.mark.asyncio
async def test_nacl_forward(
    alice: V1DIDCommMessaging,
    nacl_secrets: InMemSecretsManager,
):
    """Test nacl crypto forwarding."""
    local_key = EdPublicKey(nacl_secrets.create().verkey)
    routing_key = EdPublicKey(nacl_secrets.create().verkey)
    doc = input_doc_from_keys_and_services(
        [KeySpec(local_key.multikey, relationships=["authentication"])],
        [
            {
                "id": "#didcomm",
                "type": "did-communication",
                "recipientKeys": ["#key-0"],
                "routingKeys": [f"did:key:{routing_key.multikey}#{routing_key.multikey}"],
                "serviceEndpoint": "https://example.com",
            }
        ],
    )
    did = did_peer_4.encode(doc)
    msg = b"hello world"
    packed = await alice.pack(msg, did, did)
    unpacked = await alice.unpack(packed.message)
    forward = unpacked.message
    assert forward["@type"] == "https://didcomm.org/routing/1.0/forward"
    unwrapped = await alice.unpack(forward["msg"])
    assert unwrapped.unpacked == msg


@pytest.mark.asyncio
async def test_askar_forward(
    bob: V1DIDCommMessaging,
    store: Store,
):
    """Test nacl crypto forwarding."""
    key = Key.generate(KeyAlg.ED25519)
    kid = base58.b58encode(key.get_public_bytes()).decode()
    async with store.session() as session:
        await session.insert_key(kid, key)
    local_key = AskarKey(key, kid)

    key = Key.generate(KeyAlg.ED25519)
    kid = base58.b58encode(key.get_public_bytes()).decode()
    async with store.session() as session:
        await session.insert_key(kid, key)
    routing_key = AskarKey(key, kid)

    doc = input_doc_from_keys_and_services(
        [KeySpec(local_key.multikey, relationships=["authentication"])],
        [
            {
                "id": "#didcomm",
                "type": "did-communication",
                "recipientKeys": ["#key-0"],
                "routingKeys": [f"did:key:{routing_key.multikey}#{routing_key.multikey}"],
                "serviceEndpoint": "https://example.com",
            }
        ],
    )
    did = did_peer_4.encode(doc)
    msg = b"hello world"
    packed = await bob.pack(msg, did, did)
    unpacked = await bob.unpack(packed.message)
    forward = unpacked.message
    assert forward["@type"] == "https://didcomm.org/routing/1.0/forward"
    unwrapped = await bob.unpack(forward["msg"])
    assert unwrapped.unpacked == msg
