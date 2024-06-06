"""V1CryptoService implementation for pynacl."""

from dataclasses import dataclass
from typing import Dict, Optional, OrderedDict, Sequence, Tuple

import base58
from pydid import VerificationMethod

from didcomm_messaging.crypto.base import PublicKey, SecretKey, SecretsManager
from didcomm_messaging.crypto.jwe import JweBuilder, JweEnvelope, JweRecipient
from didcomm_messaging.multiformats import multibase, multicodec

from .base import V1CryptoService, V1CryptoUnpackResult, RecipData

try:
    import nacl.bindings
    import nacl.exceptions
    import nacl.utils
except ImportError as err:
    raise ImportError(
        "V1 nacl implementation requires 'nacl' extra to be installed"
    ) from err


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
        raise NotImplementedError()

    @property
    def multikey(self) -> str:
        """Get the key in multikey format."""
        return multibase.encode(
            multicodec.wrap("ed25519-pub", base58.b58decode(self.key)), "base58btc"
        )


class NaclV1CryptoService(V1CryptoService[EdPublicKey, KeyPair]):
    """V1 crypto service using pynacl."""

    def v1_kid_to_public_key(self, kid: str):
        """Get a public key from a kid.

        In DIDComm v1, kids are the base58 encoded keys.
        """
        return EdPublicKey(base58.b58decode(kid))

    def public_key_to_v1_kid(self, key: EdPublicKey) -> str:
        """Convert a public key into a v1 kid representation."""
        return base58.b58encode(key.value).decode()

    @classmethod
    def verification_method_to_public_key(cls, vm: VerificationMethod) -> EdPublicKey:
        """Convert a verification method to a public key."""
        return EdPublicKey.from_verification_method(vm)

    async def pack_message(
        self,
        to_verkeys: Sequence[EdPublicKey],
        from_key: Optional[KeyPair],
        message: bytes,
    ) -> JweEnvelope:
        """Encode a message using the DIDComm v1 'pack' algorithm."""
        builder = JweBuilder(
            with_protected_recipients=True, with_flatten_recipients=False
        )
        cek = nacl.bindings.crypto_secretstream_xchacha20poly1305_keygen()
        sender_vk = from_key.verkey_b58.encode() if from_key else None
        sender_xk = (
            nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(from_key.sigkey)
            if from_key
            else None
        )
        for target_vk in to_verkeys:
            target_xk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(
                target_vk.value
            )
            if sender_vk and sender_xk:
                enc_sender = nacl.bindings.crypto_box_seal(sender_vk, target_xk)
                nonce = nacl.utils.random(nacl.bindings.crypto_box_NONCEBYTES)
                enc_cek = nacl.bindings.crypto_box(cek, nonce, target_xk, sender_xk)
                builder.add_recipient(
                    JweRecipient(
                        encrypted_key=enc_cek,
                        header=OrderedDict(
                            [
                                ("kid", self.public_key_to_v1_kid(target_vk)),
                                ("sender", self.b64url.encode(enc_sender)),
                                ("iv", self.b64url.encode(nonce)),
                            ]
                        ),
                    )
                )
            else:
                enc_cek = nacl.bindings.crypto_box_seal(cek, target_xk)
                builder.add_recipient(
                    JweRecipient(
                        encrypted_key=enc_cek,
                        header={"kid": self.public_key_to_v1_kid(target_vk)},
                    )
                )

        builder.set_protected(
            OrderedDict(
                [
                    ("enc", "xchacha20poly1305_ietf"),
                    ("typ", "JWM/1.0"),
                    ("alg", "Authcrypt" if from_key else "Anoncrypt"),
                ]
            ),
        )

        nonce = nacl.utils.random(
            nacl.bindings.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
        )
        output = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
            message, builder.protected_bytes, nonce, cek
        )
        mlen = len(message)
        ciphertext = output[:mlen]
        tag = output[mlen:]
        builder.set_payload(ciphertext, nonce, tag)

        return builder.build()

    def _extract_payload_key(self, recip_key: KeyPair, recip_data: RecipData):
        """Extract the payload key."""
        pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(recip_key.verkey)
        sk = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(recip_key.sigkey)

        if recip_data.nonce and recip_data.enc_sender:
            sender_vk = nacl.bindings.crypto_box_seal_open(
                recip_data.enc_sender, pk, sk
            ).decode()
            sender_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(
                base58.b58decode(sender_vk)
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
    ) -> V1CryptoUnpackResult:
        """Decode a message using DIDCvomm v1 'unpack' algorithm."""
        cek, sender_vk = self._extract_payload_key(recip_key, recip_data)

        payload_bin = wrapper.ciphertext + wrapper.tag
        message = nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
            payload_bin, wrapper.protected_b64, wrapper.iv, cek
        )
        return V1CryptoUnpackResult(message, recip_key.kid, sender_vk)


class InMemSecretsManager(SecretsManager[KeyPair]):
    """In-memory secrets manager for ed25519 key pairs."""

    def __init__(self):
        """Initialize the manager."""
        self.secrets: Dict[str, KeyPair] = {}

    async def get_secret_by_kid(self, kid: str) -> Optional[KeyPair]:
        """Retrieve secret by kid."""
        return self.secrets.get(kid)

    def _create_keypair(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Create a keypair."""
        if seed:
            if not isinstance(seed, bytes):
                raise ValueError("Seed value is not bytes")
            if len(seed) != 32:
                raise ValueError("Seed value must be 32 bytes in length")
        else:
            seed = nacl.utils.random(nacl.bindings.crypto_secretbox_KEYBYTES)

        pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
        return pk, sk

    def create(self, seed: Optional[bytes] = None) -> KeyPair:
        """Create and store a new keypair."""
        keys = KeyPair(*self._create_keypair(seed))
        self.secrets[keys.kid] = keys
        return keys
