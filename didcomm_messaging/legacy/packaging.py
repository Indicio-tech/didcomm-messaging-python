"""LegacyPackagingService interface."""

from typing import Generic, Optional, Sequence, Tuple, Union

from didcomm_messaging.crypto.base import P, S, SecretsManager
from didcomm_messaging.crypto.jwe import JweEnvelope, JweRecipient
from didcomm_messaging.legacy.base import (
    LegacyCryptoService,
    LegacyUnpackResult,
    RecipData,
)
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder


class LegacyPackagingServiceError(Exception):
    """Represents an error from the DIDComm Messaging interface."""


class LegacyPackagingService(Generic[P, S]):
    """Legacy packagin service."""

    b64url = Base64UrlEncoder()

    def extract_pack_recipients(self, recipients: Sequence[JweRecipient]):
        """Extract the pack message recipients and yield the values.

        Args:
            recipients: Recipients to locate

        Raises:
            ValueError: If the recipients block is malformed

        """
        seen_recips = []
        for recip in recipients:
            recip_vk_b58 = recip.header.get("kid")
            if not recip_vk_b58:
                raise ValueError("Blank recipient key")
            if recip_vk_b58 in seen_recips:
                raise ValueError("Duplicate recipient key")
            seen_recips.append(recip_vk_b58)

            sender_b64 = recip.header.get("sender")
            enc_sender = self.b64url.decode(sender_b64) if sender_b64 else None

            nonce_b64 = recip.header.get("iv")
            if sender_b64 and not nonce_b64:
                raise ValueError("Missing iv")
            elif not sender_b64 and nonce_b64:
                raise ValueError("Unexpected iv")
            nonce = self.b64url.decode(nonce_b64) if nonce_b64 else None

            yield RecipData(recip_vk_b58, enc_sender, nonce, recip.encrypted_key)

    async def extract_packed_message_metadata(
        self, secrets: SecretsManager[S], wrapper: JweEnvelope
    ) -> Tuple[S, RecipData]:
        """Extrat packed message metadata."""
        alg = wrapper.protected.get("alg")
        if not alg:
            raise LegacyPackagingServiceError("Missing alg header")

        if alg not in ("Authcrypt", "Anoncrypt"):
            raise LegacyPackagingServiceError(
                f"Unsupported DIDComm encryption algorithm: {alg}"
            )

        secret = None
        matched_recip = None
        for recip in self.extract_pack_recipients(wrapper.recipients):
            secret = await secrets.get_secret_by_kid(recip.kid)
            if secret:
                matched_recip = recip
                break

        if not matched_recip or not secret:
            raise LegacyPackagingServiceError("No recognized recipient key")

        return secret, matched_recip

    async def unpack(
        self,
        crypto: LegacyCryptoService[P, S],
        secrets: SecretsManager[S],
        enc_message: Union[JweEnvelope, str, bytes],
    ) -> LegacyUnpackResult:
        """Unpack a DIDComm v1 message."""
        if isinstance(enc_message, (str, bytes)):
            try:
                wrapper = JweEnvelope.from_json(enc_message)
            except ValueError:
                raise LegacyPackagingServiceError("Invalid packed message")
        elif isinstance(enc_message, JweEnvelope):
            wrapper = enc_message
        else:
            raise TypeError("Invalid enc_message")

        recip_key, recip_data = await self.extract_packed_message_metadata(
            secrets, wrapper
        )
        return await crypto.unpack_message(wrapper, recip_key, recip_data)

    async def pack(
        self,
        crypto: LegacyCryptoService[P, S],
        secrets: SecretsManager[S],
        message: bytes,
        to: Sequence[str],
        frm: Optional[str] = None,
    ):
        """Pack a DIDComm v1 message."""
        recip_keys = [crypto.kid_to_public_key(kid) for kid in to]
        sender_key = await secrets.get_secret_by_kid(frm) if frm else None
        return await crypto.pack_message(recip_keys, sender_key, message)
