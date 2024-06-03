"""LegacyCryptoService implementation for pynacl."""

from dataclasses import dataclass
from typing import Dict, Optional, Sequence

import base58

try:
    import nacl.bindings
    import nacl.exceptions
    import nacl.utils
except ImportError as err:
    raise ImportError(
        "Legacy implementation requires 'legacy' extra to be installed"
    ) from err
from pydid import VerificationMethod

from didcomm_messaging.crypto.base import (
    PublicKey,
    SecretKey,
    SecretsManager,
)
from didcomm_messaging.crypto.jwe import JweEnvelope
from didcomm_messaging.multiformats import multibase, multicodec

from . import crypto
from .base import LegacyCryptoService, LegacyUnpackResult, RecipData


@dataclass
class KeyPair(SecretKey):
    """Keys."""

    verkey: bytes
    sigkey: bytes

    @property
    def verkey_b58(self) -> str:
        """Return base58 encoding of verkey."""
        return base58.b58encode(self.verkey).decode()

    @property
    def kid(self) -> str:
        """Get the key ID."""
        return self.verkey_b58


@dataclass
class EdPublicKey(PublicKey):
    """Simple public key representation as base58 encoded str."""

    value: bytes

    @classmethod
    def from_verification_method(cls, vm: VerificationMethod) -> "EdPublicKey":
        """Create a Key instance from a DID Document Verification Method."""
        key_bytes = cls.key_bytes_from_verification_method(vm)
        return EdPublicKey(key_bytes)

    @property
    def key(self) -> str:
        """Return base58 encoded key."""
        return base58.b58encode(self.value).decode()

    @property
    def kid(self) -> str:
        """Get the key ID."""
        return self.key

    @property
    def multikey(self) -> str:
        """Get the key in multikey format."""
        return multibase.encode(
            multicodec.wrap("ed25519-pub", base58.b58decode(self.key)), "base58btc"
        )


class NaclLegacyCryptoService(LegacyCryptoService[EdPublicKey, KeyPair]):
    """Legacy crypto service using pynacl."""

    def kid_to_public_key(self, kid: str):
        """Get a public key from a kid.

        In DIDComm v1, kids are the base58 encoded keys.
        """
        return EdPublicKey(base58.b58decode(kid))

    async def pack_message(
        self,
        to_verkeys: Sequence[EdPublicKey],
        from_key: Optional[KeyPair],
        message: bytes,
    ) -> JweEnvelope:
        """Encode a message using the DIDComm v1 'pack' algorithm."""
        packed = crypto.pack_message(
            message=message.decode(),
            to_verkeys=[vk.value for vk in to_verkeys],
            from_verkey=from_key.verkey if from_key else None,
            from_sigkey=from_key.sigkey if from_key else None,
        )
        return JweEnvelope.deserialize(packed)

    def _extract_payload_key(self, recip_key: KeyPair, recip_data: RecipData):
        """Extract the payload key."""
        pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(recip_key.verkey)
        sk = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(recip_key.sigkey)

        if recip_data.nonce and recip_data.enc_sender:
            sender_vk = nacl.bindings.crypto_box_seal_open(
                recip_data.enc_sender, pk, sk
            ).decode()
            sender_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(
                crypto.b58_to_bytes(sender_vk)
            )
            cek = nacl.bindings.crypto_box_open(
                recip_data.enc_cek, recip_data.nonce, sender_pk, sk
            )
        else:
            sender_vk = None
            cek = nacl.bindings.crypto_box_seal_open(recip_data.enc_cek, pk, sk)
        return cek, sender_vk

    async def unpack_message(
        self, wrapper: JweEnvelope, recip_key: KeyPair, recip_data: RecipData
    ) -> LegacyUnpackResult:
        """Decode a message using DIDCvomm v1 'unpack' algorithm."""
        cek, sender_vk = self._extract_payload_key(recip_key, recip_data)

        payload_bin = wrapper.ciphertext + wrapper.tag
        message = crypto.decrypt_plaintext(
            payload_bin, wrapper.protected_b64, wrapper.iv, cek
        )
        return LegacyUnpackResult(message.encode(), recip_key.kid, sender_vk)


class InMemSecretsManager(SecretsManager[KeyPair]):
    """In-memory secrets manager for ed25519 key pairs."""

    def __init__(self):
        """Initialize the manager."""
        self.secrets: Dict[str, KeyPair] = {}

    async def get_secret_by_kid(self, kid: str) -> Optional[KeyPair]:
        """Retrieve secret by kid."""
        return self.secrets.get(kid)

    def create(self, seed: Optional[bytes] = None) -> KeyPair:
        """Create and store a new keypair."""
        keys = KeyPair(*crypto.create_keypair(seed))
        self.secrets[keys.kid] = keys
        return keys
