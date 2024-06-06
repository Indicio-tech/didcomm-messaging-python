"""DIDComm v1 Base Services."""

from abc import ABC, abstractmethod
from typing import Generic, NamedTuple, Optional, Sequence

from pydid import VerificationMethod
from didcomm_messaging.crypto.base import P, S
from didcomm_messaging.crypto.jwe import JweEnvelope
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder


class RecipData(NamedTuple):
    """Recipient metadata."""

    kid: str
    enc_sender: Optional[bytes]
    nonce: Optional[bytes]
    enc_cek: bytes


class V1CryptoUnpackResult(NamedTuple):
    """Result of unpacking."""

    unpacked: bytes
    recip: str
    sender: Optional[str]


class V1CryptoServiceError(Exception):
    """Raised on errors in crypto service."""


class V1CryptoService(ABC, Generic[P, S]):
    """CryptoService interface for DIDComm v1."""

    b64url = Base64UrlEncoder()

    @abstractmethod
    def v1_kid_to_public_key(self, kid: str) -> P:
        """Get a public key from a kid.

        In DIDComm v1, kids are the base58 encoded keys.
        """

    @abstractmethod
    def public_key_to_v1_kid(self, key: P) -> str:
        """Return the DIDComm v1 kid representation for a key."""

    @classmethod
    @abstractmethod
    def verification_method_to_public_key(cls, vm: VerificationMethod) -> P:
        """Convert a verification method to a public key."""

    @abstractmethod
    async def pack_message(
        self, to_verkeys: Sequence[P], from_key: Optional[S], message: bytes
    ) -> JweEnvelope:
        """Encode a message using the DIDComm v1 'pack' algorithm."""

    @abstractmethod
    async def unpack_message(
        self, wrapper: JweEnvelope, recip_key: S, recip_data: RecipData
    ) -> V1CryptoUnpackResult:
        """Decode a message using DIDCvomm v1 'unpack' algorithm."""
