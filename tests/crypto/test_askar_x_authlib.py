"""Test compabibility between Askar and Authlib."""

import json
from aries_askar import Key, KeyAlg
from authlib.jose import OKPKey
import pytest

from didcomm_messaging.crypto.backend.askar import (
    AskarCryptoService,
    AskarKey,
    AskarSecretKey,
)
from didcomm_messaging.crypto.backend.authlib import (
    AuthlibCryptoService,
    AuthlibKey,
    AuthlibSecretKey,
)


ALICE_KID = "did:example:alice#key-1"
BOB_KID = "did:example:bob#key-1"


@pytest.fixture
def alice_askar_key():
    yield Key.generate(KeyAlg.X25519)


@pytest.fixture
def bob_askar_key():
    yield Key.generate(KeyAlg.X25519)


@pytest.fixture
def alice_authlib_key(alice_askar_key: Key):
    yield OKPKey.import_key(json.loads(alice_askar_key.get_jwk_public()))


@pytest.fixture
def bob_authlib_key(bob_askar_key: Key):
    yield OKPKey.import_key(json.loads(bob_askar_key.get_jwk_secret()))


@pytest.fixture
def alice(alice_askar_key: Key, alice_authlib_key: OKPKey):
    yield (
        AskarSecretKey(alice_askar_key, ALICE_KID),
        AuthlibKey(alice_authlib_key, ALICE_KID),
    )


@pytest.fixture
def bob(bob_askar_key: Key, bob_authlib_key: OKPKey):
    yield AuthlibSecretKey(bob_authlib_key, BOB_KID), AskarKey(bob_askar_key, BOB_KID)


@pytest.fixture
def askar():
    yield AskarCryptoService()


@pytest.fixture
def authlib():
    yield AuthlibCryptoService()


@pytest.mark.asyncio
async def test_compat_ecdh_1pu(
    askar: AskarCryptoService,
    authlib: AuthlibCryptoService,
    alice: tuple[AskarSecretKey, AuthlibKey],
    bob: tuple[AuthlibSecretKey, AskarKey],
):
    """Test compabibility between Askar and Authlib.

    Alice uses Askar, Bob uses Authlib.
    """
    alice_sk, alice_pk = alice
    bob_sk, bob_pk = bob

    to_alice = b"Dear alice, please decrypt this"
    alice_enc_message = await authlib.ecdh_1pu_encrypt([alice_pk], bob_sk, to_alice)
    print(alice_enc_message)

    plaintext = await askar.ecdh_1pu_decrypt(alice_enc_message, alice_sk, bob_pk)
    assert plaintext == to_alice

    to_bob = b"Dear bob, please decrypt this"
    bob_enc_message = await askar.ecdh_1pu_encrypt([bob_pk], alice_sk, to_bob)

    print(bob_enc_message)

    plaintext = await authlib.ecdh_1pu_decrypt(bob_enc_message, bob_sk, alice_pk)
    assert plaintext == to_bob


@pytest.mark.asyncio
async def test_compat_ecdh_es(
    askar: AskarCryptoService,
    authlib: AuthlibCryptoService,
    alice: tuple[AskarSecretKey, AuthlibKey],
    bob: tuple[AuthlibSecretKey, AskarKey],
):
    """Test compabibility between Askar and Authlib.

    Alice uses Askar, Bob uses Authlib.
    """
    alice_sk, alice_pk = alice
    bob_sk, bob_pk = bob

    to_alice = b"Dear alice, please decrypt this"
    alice_enc_message = await authlib.ecdh_es_encrypt([alice_pk], to_alice)
    print(alice_enc_message)

    plaintext = await askar.ecdh_es_decrypt(alice_enc_message, alice_sk)
    assert plaintext == to_alice

    to_bob = b"Dear bob, please decrypt this"
    bob_enc_message = await askar.ecdh_es_encrypt([bob_pk], to_bob)

    print(bob_enc_message)

    plaintext = await authlib.ecdh_es_decrypt(bob_enc_message, bob_sk)
    assert plaintext == to_bob
