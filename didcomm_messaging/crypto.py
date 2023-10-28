"""Key Management Service (CryptoService) interface for DIDComm Messaging."""


from abc import ABC, abstractmethod
from typing import Generic, Literal, Mapping, NamedTuple, Optional, TypeVar, Union

from didcomm_messaging.jwe import JweEnvelope, from_b64url


P = TypeVar("P", bound="PublicKey")
S = TypeVar("S", bound="SecretKey")


class CryptoServiceError(Exception):
    """Represents an error from a CryptoService."""


class PublicKey(ABC):
    """Key representation for CryptoService."""

    @classmethod
    @abstractmethod
    def from_verification_method(cls, vm: dict) -> "PublicKey":
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


class PackedMessageMetadata(NamedTuple):
    """Unpack result."""

    wrapper: JweEnvelope
    method: Literal["ECDH-ES", "ECDH-1PU"]
    recip_kid: str
    sender_kid: Optional[str]


class CryptoService(ABC, Generic[P, S]):
    """Key Management Service (CryptoService) interface for DIDComm Messaging."""

    @abstractmethod
    async def ecdh_es_encrypt(self, to_keys: Mapping[str, P], message: bytes) -> bytes:
        """Encode a message into DIDComm v2 anonymous encryption."""

    @abstractmethod
    async def ecdh_es_decrypt(
        self, message: bytes, recip_kid, str, recip_key: P
    ) -> bytes:
        """Decode a message from DIDComm v2 anonymous encryption."""

    @abstractmethod
    async def ecdh_1pu_encrypt(
        self,
        to_keys: Mapping[str, P],
        sender_kid: str,
        sender_key: P,
        message: bytes,
    ) -> bytes:
        """Encode a message into DIDComm v2 authenticated encryption."""

    @abstractmethod
    async def ecdh_1pu_decrypt(
        self,
        message: bytes,
        recip_kid: str,
        recip_key: P,
        sender_key: P,
    ) -> bytes:
        """Decode a message from DIDComm v2 authenticated encryption."""

    @classmethod
    @abstractmethod
    def verification_method_to_public_key(cls, vm: dict) -> P:
        """Convert a DIDComm v2 verification method to a public key."""


class SecretsManager(ABC):
    """Secrets Resolver interface.

    Thie secrets resolver may be used to supplement the CryptoService backend to provide
    greater flexibility.
    """

    @abstractmethod
    async def get_secret_by_kid(self, kid: str) -> Optional[SecretKey]:
        """Get a secret key by its ID."""


class KMS(CryptoService, SecretsManager):
    """Key Management Service interface for DIDComm Messaging."""

    async def extract_packed_message_metadata(
        self, enc_message: Union[str, bytes]
    ) -> PackedMessageMetadata:
        """Extract metadata from a packed DIDComm message."""
        try:
            wrapper = JweEnvelope.from_json(enc_message)
        except ValueError:
            raise CryptoServiceError("Invalid packed message")

        alg = wrapper.protected.get("alg")
        if not alg:
            raise CryptoServiceError("Missing alg header")

        method = next((m for m in ("ECDH-1PU", "ECDH-ES") if m in alg), None)
        if not method:
            raise CryptoServiceError(f"Unsupported DIDComm encryption algorithm: {alg}")

        sender_kid = None
        recip_key = None
        for kid in wrapper.recipient_key_ids:
            recip_key = await self.get_secret_by_kid(kid)
            if recip_key:
                break

        if not recip_key:
            raise CryptoServiceError("No recognized recipient key")

        recip_kid = recip_key.kid

        if method == "ECDH-1PU":
            sender_kid_apu = None
            apu = wrapper.protected.get("apu")
            if apu:
                try:
                    sender_kid_apu = from_b64url(apu).decode("utf-8")
                except (UnicodeDecodeError, ValueError):
                    raise CryptoServiceError("Invalid apu value")
            sender_kid = wrapper.protected.get("skid") or sender_kid_apu
            if sender_kid_apu and sender_kid != sender_kid_apu:
                raise CryptoServiceError("Mismatch between skid and apu")
            if not sender_kid:
                raise CryptoServiceError("Sender key ID not provided")
            # FIXME - validate apv if present?

        return PackedMessageMetadata(wrapper, method, recip_kid, sender_kid)
