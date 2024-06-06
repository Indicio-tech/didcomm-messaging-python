"""CryptoService and SecretsManager interfaces for DIDComm Messaging."""

from abc import ABC, abstractmethod
from typing import Generic, Mapping, Optional, Sequence, TypeVar, Union

from pydid import VerificationMethod

from didcomm_messaging.multiformats import multibase, multicodec


class CryptoServiceError(Exception):
    """Represents an error from a CryptoService."""


class PublicKey(ABC):
    """Key representation for CryptoService."""

    type_to_codec: Mapping[str, str] = {
        "Ed25519VerificationKey2018": "ed25519-pub",
        "X25519KeyAgreementKey2019": "x25519-pub",
        "Ed25519VerificationKey2020": "ed25519-pub",
        "X25519KeyAgreementKey2020": "x25519-pub",
    }

    @classmethod
    @abstractmethod
    def from_verification_method(cls, vm: VerificationMethod) -> "PublicKey":
        """Create a Key instance from a DID Document Verification Method."""

    @classmethod
    def key_bytes_from_verification_method(cls, vm: VerificationMethod) -> bytes:
        """Get the key bytes from a DID Document Verification Method."""
        if vm.public_key_multibase and vm.public_key_base58:
            raise ValueError(
                "Only one of public_key_multibase or public_key_base58 must be given"
            )
        if not vm.public_key_multibase and not vm.public_key_base58:
            raise ValueError(
                "One of public_key_multibase or public_key_base58 must be given)"
            )

        if vm.public_key_multibase:
            decoded = multibase.decode(vm.public_key_multibase)
            if len(decoded) == 32:
                # No multicodec prefix
                return decoded
            else:
                codec, decoded = multicodec.unwrap(decoded)
                if vm.type != "Multikey":
                    expected_codec = cls.type_to_codec.get(vm.type)
                    if not expected_codec:
                        raise ValueError("Unsupported verification method type")
                    if codec.name != expected_codec:
                        raise ValueError("Type and codec mismatch")
                return decoded

        if vm.public_key_base58:
            return multibase.decode("z" + vm.public_key_base58)

        raise ValueError("Invalid verification method")

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
    async def ecdh_es_decrypt(self, wrapper: Union[str, bytes], recip_key: S) -> bytes:
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
        wrapper: Union[str, bytes],
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
