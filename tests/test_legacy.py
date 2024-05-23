"""Test Pack and Unpack."""

from typing import NamedTuple

import base58
import pytest

from didcomm_messaging.legacy import crypto


class KeyPair(NamedTuple):
    """Keys."""

    verkey: bytes
    sigkey: bytes

    @property
    def verkey_b58(self) -> str:
        return base58.b58encode(self.verkey).decode()


@pytest.fixture(scope="module")
def alice():
    """Generate alice's keys."""
    yield KeyPair(*crypto.create_keypair())


@pytest.fixture(scope="module")
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
