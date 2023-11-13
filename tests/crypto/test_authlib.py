"""Test the authlib crypto service implementation."""

from authlib.jose import OKPKey
import pytest

from didcomm_messaging.crypto.backend.authlib import (
    AuthlibCryptoService,
    AuthlibKey,
    AuthlibSecretKey,
)


ALICE_KID = "did:example:alice#key-1"
BOB_KID = "did:example:bob#key-1"
CAROL_KID = "did:example:carol#key-2"
MESSAGE = b"Expecto patronum"


@pytest.fixture
def crypto():
    yield AuthlibCryptoService()


def test_multikey_roundtrip():
    """Test multikey round trip."""
    key = OKPKey.generate_key("Ed25519", is_private=False)
    multikey = AuthlibKey.key_to_multikey(key)
    back_again = AuthlibKey.multikey_to_key(multikey)
    assert key.as_dict() == back_again.as_dict()


@pytest.mark.asyncio
async def test_1pu_round_trip(crypto: AuthlibCryptoService):
    """Test 1PU round trip."""
    alice_sk = OKPKey.generate_key("X25519", is_private=True)
    alice_pk = alice_sk.get_public_key()
    bob_sk = OKPKey.generate_key("X25519", is_private=True)
    bob_pk = bob_sk.get_public_key()

    bob_key = AuthlibKey(bob_sk, BOB_KID)
    bob_priv_key = AuthlibSecretKey(bob_sk, BOB_KID)

    alice_key = AuthlibKey(alice_sk, ALICE_KID)
    alice_priv_key = AuthlibSecretKey(alice_sk, ALICE_KID)

    enc_message = await crypto.ecdh_1pu_encrypt([bob_key], alice_priv_key, MESSAGE)

    plaintext = await crypto.ecdh_1pu_decrypt(enc_message, bob_priv_key, alice_key)
    assert plaintext == MESSAGE


@pytest.mark.asyncio
async def test_es_round_trip(crypto: AuthlibCryptoService):
    """Test ECDH-ES round trip."""
    alice_sk = OKPKey.generate_key("X25519", is_private=True)
    alice_pk = alice_sk.get_public_key()
    bob_sk = OKPKey.generate_key("X25519", is_private=True)
    bob_pk = bob_sk.get_public_key()

    bob_key = AuthlibKey(bob_sk, BOB_KID)
    bob_priv_key = AuthlibSecretKey(bob_sk, BOB_KID)

    alice_key = AuthlibKey(alice_sk, ALICE_KID)
    alice_priv_key = AuthlibSecretKey(alice_sk, ALICE_KID)

    enc_message = await crypto.ecdh_es_encrypt([bob_key], MESSAGE)

    plaintext = await crypto.ecdh_es_decrypt(enc_message, bob_priv_key)
    assert plaintext == MESSAGE
