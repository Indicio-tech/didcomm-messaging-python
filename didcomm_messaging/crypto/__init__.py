"""Key Management Service (CryptoService) interface for DIDComm Messaging."""


from abc import ABC, abstractmethod
from typing import Generic, Optional, Sequence, TypeVar, Union

from pydid import VerificationMethod

from didcomm_messaging.jwe import JweEnvelope, from_b64url


class CryptoServiceError(Exception):
    """Represents an error from a CryptoService."""


class PublicKey(ABC):
    """Key representation for CryptoService."""

    @classmethod
    @abstractmethod
    def from_verification_method(cls, vm: VerificationMethod) -> "PublicKey":
        """Create a Key instance from a DID Document Verification Method."""

    @property
    @abstractmethod
    def kid(self) -> str:
        """Get the key ID."""

    @property
    @abstractmethod
    def multikey(self) -> str:
        """Get the key in multikey format."""


class SecretKey(ABC):
    """Secret Key Type."""
    @property
    @abstractmethod
    def kid(self) -> str:
        """Get the key ID."""


P = TypeVar("P", bound=PublicKey)
S = TypeVar("S", bound=SecretKey)


class CryptoService(ABC, Generic[P, S]):
    """Key Management Service (CryptoService) interface for DIDComm Messaging."""

    @abstractmethod
    async def ecdh_es_encrypt(self, to_keys: Sequence[P], message: bytes) -> bytes:
        """Encode a message into DIDComm v2 anonymous encryption."""

    @abstractmethod
    async def ecdh_es_decrypt(
        self, wrapper: Union[JweEnvelope, str, bytes], recip_key: S
    ) -> bytes:
        """Decode a message from DIDComm v2 anonymous encryption."""

    @abstractmethod
    async def ecdh_1pu_encrypt(
        self,
        to_keys: Sequence[P],
        sender_key: S,
        message: bytes,
    ) -> bytes:
        """Encode a message into DIDComm v2 authenticated encryption."""

    @abstractmethod
    async def ecdh_1pu_decrypt(
        self,
        wrapper: Union[JweEnvelope, str, bytes],
        recip_key: S,
        sender_key: P,
    ) -> bytes:
        """Decode a message from DIDComm v2 authenticated encryption."""

    @classmethod
    @abstractmethod
    def verification_method_to_public_key(cls, vm: VerificationMethod) -> P:
        """Convert a verification method to a public key."""


class SecretsManager(ABC, Generic[S]):
    """Secrets Resolver interface.

    Thie secrets resolver may be used to supplement the CryptoService backend to provide
    greater flexibility.
    """

    @abstractmethod
    async def get_secret_by_kid(self, kid: str) -> Optional[S]:
        """Get a secret key by its ID."""
