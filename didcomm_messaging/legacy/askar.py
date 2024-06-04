"""LegacyCryptoService implementation for askar."""

from collections import OrderedDict
from typing import Optional, Sequence, Tuple, cast

from base58 import b58decode

from didcomm_messaging.crypto.jwe import JweBuilder, JweEnvelope, JweRecipient
from didcomm_messaging.legacy.base import (
    LegacyCryptoService,
    LegacyUnpackResult,
    RecipData,
)

try:
    from aries_askar import Key, KeyAlg, crypto_box
    from aries_askar.bindings import key_get_secret_bytes
    from didcomm_messaging.crypto.backend.askar import AskarKey, AskarSecretKey
except ImportError:
    raise ImportError("Legacy Askar backend requires the 'askar' extra to be installed")


class AskarLegacyCryptoService(LegacyCryptoService[AskarKey, AskarSecretKey]):
    """Legacy crypto service implementation for askar."""

    def kid_to_public_key(self, kid: str) -> AskarKey:
        """Get a public key from a kid.

        In DIDComm v1, kids are the base58 encoded keys.
        """
        return AskarKey(Key.from_public_bytes(KeyAlg.ED25519, b58decode(kid)), kid)

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
        sender_vk = from_key.kid if from_key else None
        sender_xk = from_key.key.convert_key(KeyAlg.X25519) if from_key else None

        for target_vk in to_verkeys:
            target_xk = target_vk.key.convert_key(KeyAlg.X25519)
            if sender_vk and sender_xk:
                enc_sender = crypto_box.crypto_box_seal(target_xk, sender_vk)
                nonce = crypto_box.random_nonce()
                enc_cek = crypto_box.crypto_box(target_xk, sender_xk, cek_b, nonce)
                builder.add_recipient(
                    JweRecipient(
                        encrypted_key=enc_cek,
                        header=OrderedDict(
                            [
                                ("kid", target_vk.kid),
                                ("sender", self.b64url.encode(enc_sender)),
                                ("iv", self.b64url.encode(nonce)),
                            ]
                        ),
                    )
                )
            else:
                enc_sender = None
                nonce = None
                enc_cek = crypto_box.crypto_box_seal(target_xk, cek_b)
                builder.add_recipient(
                    JweRecipient(encrypted_key=enc_cek, header={"kid": target_vk.kid})
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
    ) -> LegacyUnpackResult:
        """Decode a message using the DIDComm v1 'unpack' algorithm."""
        payload_key, sender_vk = self._extract_payload_key(recip_key.key, recip_data)

        cek = Key.from_secret_bytes(KeyAlg.C20P, payload_key)
        message = cek.aead_decrypt(
            wrapper.ciphertext,
            nonce=wrapper.iv,
            tag=wrapper.tag,
            aad=wrapper.protected_b64,
        )
        return LegacyUnpackResult(message, recip_key.kid, sender_vk)

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
