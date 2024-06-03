import pytest

from didcomm_messaging.crypto.backend.askar import AskarSecretKey, AskarSecretsManager
from didcomm_messaging.legacy.nacl import (
    InMemSecretsManager,
    NaclLegacyCryptoService,
    KeyPair,
)
from didcomm_messaging.legacy.askar import AskarLegacyCryptoService
from didcomm_messaging.legacy.packaging import LegacyPackagingService


@pytest.mark.asyncio
async def test_pack_unpack_auth_n_to_a(
    nacl: NaclLegacyCryptoService,
    askar: AskarLegacyCryptoService,
    nacl_secrets: InMemSecretsManager,
    askar_secrets: AskarSecretsManager,
    packer: LegacyPackagingService,
    alice: KeyPair,
    bobskar: AskarSecretKey,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await packer.pack(nacl, nacl_secrets, msg, [bobskar.kid], alice.kid)
    recv_msg, receiver, sender = await packer.unpack(askar, askar_secrets, packed_msg)
    assert recv_msg == msg
    assert sender == alice.verkey_b58
    assert receiver == bobskar.kid


@pytest.mark.asyncio
async def test_pack_unpack_auth_a_to_n(
    nacl: NaclLegacyCryptoService,
    askar: AskarLegacyCryptoService,
    askar_secrets: AskarSecretsManager,
    nacl_secrets: InMemSecretsManager,
    packer: LegacyPackagingService,
    askarlice: AskarSecretKey,
    bob: KeyPair,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await packer.pack(
        askar, askar_secrets, msg, [bob.verkey_b58], askarlice.kid
    )
    recv_msg, receiver, sender = await packer.unpack(nacl, nacl_secrets, packed_msg)
    assert recv_msg == msg
    assert sender == askarlice.kid
    assert receiver == bob.kid


@pytest.mark.asyncio
async def test_pack_unpack_anon_n_to_a(
    nacl: NaclLegacyCryptoService,
    askar: AskarLegacyCryptoService,
    nacl_secrets: InMemSecretsManager,
    askar_secrets: AskarSecretsManager,
    packer: LegacyPackagingService,
    bobskar: AskarSecretKey,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await packer.pack(nacl, nacl_secrets, msg, [bobskar.kid])
    recv_msg, receiver, sender = await packer.unpack(askar, askar_secrets, packed_msg)
    assert recv_msg == msg
    assert sender is None
    assert receiver == bobskar.kid


@pytest.mark.asyncio
async def test_pack_unpack_anon_a_to_n(
    nacl: NaclLegacyCryptoService,
    askar: AskarLegacyCryptoService,
    nacl_secrets: InMemSecretsManager,
    askar_secrets: AskarSecretsManager,
    packer: LegacyPackagingService,
    bob: KeyPair,
):
    """Test that we can pack and unpack going from askar to crypto."""

    msg = b"hello world"
    packed_msg = await packer.pack(askar, askar_secrets, msg, [bob.verkey_b58])
    recv_msg, receiver, sender = await packer.unpack(nacl, nacl_secrets, packed_msg)
    assert recv_msg == msg
    assert sender is None
    assert receiver == bob.kid
