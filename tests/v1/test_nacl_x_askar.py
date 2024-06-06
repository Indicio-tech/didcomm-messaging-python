import pytest

from didcomm_messaging.crypto.base import SecretKey
from didcomm_messaging.v1.messaging import V1DIDCommMessaging


@pytest.mark.asyncio
async def test_pack_unpack_auth_n_to_a(
    alice: V1DIDCommMessaging,
    bob: V1DIDCommMessaging,
    alice_did: str,
    bob_did: str,
    alice_key: SecretKey,
    bob_key: SecretKey,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await alice.pack(msg, bob_did, alice_did)
    unpacked = await bob.unpack(packed_msg.message)
    assert unpacked.unpacked == msg
    assert unpacked.sender_kid == alice_key.kid
    assert unpacked.recipient_kid == bob_key.kid


@pytest.mark.asyncio
async def test_pack_unpack_auth_a_to_n(
    alice: V1DIDCommMessaging,
    bob: V1DIDCommMessaging,
    alice_did: str,
    bob_did: str,
    alice_key: SecretKey,
    bob_key: SecretKey,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await bob.pack(msg, alice_did, bob_did)
    unpacked = await alice.unpack(packed_msg.message)
    assert unpacked.unpacked == msg
    assert unpacked.sender_kid == bob_key.kid
    assert unpacked.recipient_kid == alice_key.kid


@pytest.mark.asyncio
async def test_pack_unpack_anon_n_to_a(
    alice: V1DIDCommMessaging,
    bob: V1DIDCommMessaging,
    bob_did: str,
    bob_key: SecretKey,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await alice.pack(msg, bob_did)
    unpacked = await bob.unpack(packed_msg.message)
    assert unpacked.unpacked == msg
    assert unpacked.recipient_kid == bob_key.kid
    assert unpacked.sender_kid is None


@pytest.mark.asyncio
async def test_pack_unpack_anon_a_to_n(
    alice: V1DIDCommMessaging,
    bob: V1DIDCommMessaging,
    alice_did: str,
    alice_key: SecretKey,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await bob.pack(msg, alice_did)
    unpacked = await alice.unpack(packed_msg.message)
    assert unpacked.unpacked == msg
    assert unpacked.recipient_kid == alice_key.kid
    assert unpacked.sender_kid is None
