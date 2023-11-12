from aries_askar import Key, KeyAlg
import pytest

from didcomm_messaging.crypto.backend.askar import (
    AskarCryptoService,
    AskarKey,
    AskarSecretKey,
)


ALICE_KID = "did:example:alice#key-1"
BOB_KID = "did:example:bob#key-1"
CAROL_KID = "did:example:carol#key-2"
MESSAGE = b"Expecto patronum"


@pytest.fixture
def crypto():
    yield AskarCryptoService()


@pytest.mark.asyncio
async def test_1pu_round_trip(crypto: AskarCryptoService):
    alg = KeyAlg.X25519
    alice_sk = Key.generate(alg)
    alice_pk = Key.from_jwk(alice_sk.get_jwk_public())
    bob_sk = Key.generate(alg)
    bob_pk = Key.from_jwk(bob_sk.get_jwk_public())
    bob_key = AskarKey(bob_sk, BOB_KID)
    bob_priv_key = AskarSecretKey(bob_sk, BOB_KID)
    alice_key = AskarKey(alice_sk, ALICE_KID)
    alice_priv_key = AskarSecretKey(alice_sk, ALICE_KID)

    enc_message = await crypto.ecdh_1pu_encrypt([bob_key], alice_priv_key, MESSAGE)

    plaintext = await crypto.ecdh_1pu_decrypt(enc_message, bob_priv_key, alice_key)
    assert plaintext == MESSAGE
