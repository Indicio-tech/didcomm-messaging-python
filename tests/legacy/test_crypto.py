"""Test Pack and Unpack."""

import pytest
from didcomm_messaging.legacy import crypto
from didcomm_messaging.v1.crypto.nacl import KeyPair


@pytest.fixture
def alice():
    """Generate alice's keys."""
    yield KeyPair(*crypto.create_keypair())


@pytest.fixture
def bob():
    """Generate bob's keys."""
    yield KeyPair(*crypto.create_keypair())


def test_pack_unpack_auth(alice: KeyPair, bob: KeyPair):
    """Test the pack-unpack loop with authcrypt."""
    msg = "hello world"
    packed_msg = crypto.pack_message(msg, [bob.verkey], alice.verkey, alice.sigkey)

    recv_msg, sender, receiver = crypto.unpack_message(packed_msg, bob.verkey, bob.sigkey)
    assert recv_msg == msg
    assert sender == alice.verkey_b58
    assert receiver == bob.verkey_b58


def test_pack_unpack_anon(bob):
    """Test the pack-unpack loop with anoncrypt."""
    msg = "hello world"
    packed_msg = crypto.pack_message(msg, [bob.verkey])

    recv_msg, sender, receiver = crypto.unpack_message(packed_msg, bob.verkey, bob.sigkey)
    assert recv_msg == msg
    assert sender is None
    assert receiver == bob.verkey_b58
