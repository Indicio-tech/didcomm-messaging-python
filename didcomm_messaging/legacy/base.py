"""DIDComm v1 Base Services."""

from abc import ABC, abstractmethod
from typing import Generic, NamedTuple, Optional, Sequence
from didcomm_messaging.crypto.base import P, S
from didcomm_messaging.crypto.jwe import JweEnvelope
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder


class RecipData(NamedTuple):
    """Recipient metadata."""

    kid: str
    enc_sender: Optional[bytes]
    nonce: Optional[bytes]
    enc_cek: bytes


class LegacyUnpackResult(NamedTuple):
    """Result of unpacking."""

    message: bytes
    recip: str
    sender: Optional[str]


class LegacyCryptoService(ABC, Generic[P, S]):
    """CryptoService interface for DIDComm v1."""

    b64url = Base64UrlEncoder()

    @abstractmethod
    def kid_to_public_key(self, kid: str) -> P:
        """Get a public key from a kid.

        In DIDComm v1, kids are the base58 encoded keys.
        """

    @abstractmethod
    async def pack_message(
        self, to_verkeys: Sequence[P], from_key: Optional[S], message: bytes
    ) -> JweEnvelope:
        """Encode a message using the DIDComm v1 'pack' algorithm."""

    @abstractmethod
    async def unpack_message(
        self, wrapper: JweEnvelope, recip_key: S, recip_data: RecipData
    ) -> LegacyUnpackResult:
        """Decode a message using DIDCvomm v1 'unpack' algorithm."""
