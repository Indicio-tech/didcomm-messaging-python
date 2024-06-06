"""V1CryptoService implementation for askar."""

from collections import OrderedDict
from typing import Optional, Sequence, Tuple, cast

from base58 import b58decode
import base58
from pydid import VerificationMethod

from didcomm_messaging.crypto.jwe import JweBuilder, JweEnvelope, JweRecipient
from .base import (
    V1CryptoService,
    V1CryptoServiceError,
    V1CryptoUnpackResult,
    RecipData,
)

try:
    from aries_askar import Key, KeyAlg, crypto_box
    from aries_askar.bindings import key_get_secret_bytes
    from didcomm_messaging.crypto.backend.askar import AskarKey, AskarSecretKey
except ImportError:
    raise ImportError("V1 Askar backend requires the 'askar' extra to be installed")


class AskarV1CryptoService(V1CryptoService[AskarKey, AskarSecretKey]):
    """V1 crypto service implementation for askar."""

    def v1_kid_to_public_key(self, kid: str) -> AskarKey:
        """Get a public key from a kid.

        In DIDComm v1, kids are the base58 encoded keys.
        """
        return AskarKey(Key.from_public_bytes(KeyAlg.ED25519, b58decode(kid)), kid)

    def public_key_to_v1_kid(self, key: AskarKey) -> str:
        """Convert a public key into a v1 kid representation."""
        if key.key.algorithm != KeyAlg.ED25519:
            raise V1CryptoServiceError()
        return base58.b58encode(key.key.get_public_bytes()).decode()

    @classmethod
    def verification_method_to_public_key(cls, vm: VerificationMethod) -> AskarKey:
        """Convert a verification method to a public key."""
        return AskarKey.from_verification_method(vm)

    async def pack_message(
        self,
        to_verkeys: Sequence[AskarKey],
        from_key: Optional[AskarSecretKey],
        message: bytes,
    ) -> JweEnvelope:
        """Encode a message using the DIDComm v1 'pack' algorithm."""
        builder = JweBuilder(
            with_protected_recipients=True, with_flatten_recipients=False
        )
        cek = Key.generate(KeyAlg.C20P)
        # avoid converting to bytes object: this way the only copy is zeroed afterward
        # tell type checking it's bytes to make it happy
        cek_b = cast(bytes, key_get_secret_bytes(cek._handle))
        sender_vk = (
            self.public_key_to_v1_kid(from_key.as_public_key()) if from_key else None
        )
        sender_xk = from_key.key.convert_key(KeyAlg.X25519) if from_key else None

        for target_vk in to_verkeys:
            target_xk = target_vk.key.convert_key(KeyAlg.X25519)
            target_vk_kid = self.public_key_to_v1_kid(target_vk)
            if sender_vk and sender_xk:
                enc_sender = crypto_box.crypto_box_seal(target_xk, sender_vk)
                nonce = crypto_box.random_nonce()
                enc_cek = crypto_box.crypto_box(target_xk, sender_xk, cek_b, nonce)
                builder.add_recipient(
                    JweRecipient(
                        encrypted_key=enc_cek,
                        header=OrderedDict(
                            [
                                ("kid", target_vk_kid),
                                ("sender", self.b64url.encode(enc_sender)),
                                ("iv", self.b64url.encode(nonce)),
                            ]
                        ),
                    )
                )
            else:
                enc_cek = crypto_box.crypto_box_seal(target_xk, cek_b)
                builder.add_recipient(
                    JweRecipient(encrypted_key=enc_cek, header={"kid": target_vk_kid})
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
        enc = cek.aead_encrypt(message, aad=builder.protected_bytes)
        ciphertext, tag, nonce = enc.parts
        builder.set_payload(ciphertext, nonce, tag)
        return builder.build()

    async def unpack_message(
        self,
        wrapper: JweEnvelope,
        recip_key: AskarSecretKey,
        recip_data: RecipData,
    ) -> V1CryptoUnpackResult:
        """Decode a message using the DIDComm v1 'unpack' algorithm."""
        payload_key, sender_vk = self._extract_payload_key(recip_key.key, recip_data)

        cek = Key.from_secret_bytes(KeyAlg.C20P, payload_key)
        message = cek.aead_decrypt(
            wrapper.ciphertext,
            nonce=wrapper.iv,
            tag=wrapper.tag,
            aad=wrapper.protected_b64,
        )
        return V1CryptoUnpackResult(message, recip_key.kid, sender_vk)

    def _extract_payload_key(
        self, recip_key: Key, recip_data: RecipData
    ) -> Tuple[bytes, Optional[str]]:
        """Extract the payload key from pack recipient details.

        Returns: A tuple of the CEK and sender verkey
        """
        recip_x = recip_key.convert_key(KeyAlg.X25519)

        if recip_data.nonce and recip_data.enc_sender:
            sender_vk = crypto_box.crypto_box_seal_open(
                recip_x, recip_data.enc_sender
            ).decode("utf-8")
            sender_x = Key.from_public_bytes(
                KeyAlg.ED25519, b58decode(sender_vk)
            ).convert_key(KeyAlg.X25519)
            cek = crypto_box.crypto_box_open(
                recip_x, sender_x, recip_data.enc_cek, recip_data.nonce
            )
        else:
            sender_vk = None
            cek = crypto_box.crypto_box_seal_open(recip_x, recip_data.enc_cek)
        return cek, sender_vk
