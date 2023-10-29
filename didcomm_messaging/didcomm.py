"""Class DIDComm Messaging interface."""


from dataclasses import dataclass
from typing import Generic, Literal, Optional, Sequence, Union

from pydid import DIDUrl, VerificationMethod
from didcomm_messaging.crypto import P, S, CryptoService, SecretsManager
from didcomm_messaging.jwe import JweEnvelope, from_b64url
from didcomm_messaging.resolver import DIDResolver


@dataclass
class PackedMessageMetadata(Generic[S]):
    """Unpack result."""

    wrapper: JweEnvelope
    method: Literal["ECDH-ES", "ECDH-1PU"]
    recip_key: S
    sender_kid: Optional[str]


class DIDCommMessagingError(Exception):
    """Represents an error from the DIDComm Messaging interface."""


class PackagingService(Generic[P, S]):
    """DIDComm Messaging interface."""

    def __init__(
        self,
        resolver: DIDResolver,
        crypto: CryptoService[P, S],
        secrets: SecretsManager[S],
    ):
        """Initialize the KMS."""
        self.resolver = resolver
        self.crypto = crypto
        self.secrets = secrets

    async def extract_packed_message_metadata(  # noqa: C901
        self, enc_message: Union[str, bytes]
    ) -> PackedMessageMetadata:
        """Extract metadata from a packed DIDComm message."""
        try:
            wrapper = JweEnvelope.from_json(enc_message)
        except ValueError:
            raise DIDCommMessagingError("Invalid packed message")

        alg = wrapper.protected.get("alg")
        if not alg:
            raise DIDCommMessagingError("Missing alg header")

        method = next((m for m in ("ECDH-1PU", "ECDH-ES") if m in alg), None)
        if not method:
            raise DIDCommMessagingError(
                f"Unsupported DIDComm encryption algorithm: {alg}"
            )

        sender_kid = None
        recip_key = None
        for kid in wrapper.recipient_key_ids:
            recip_key = await self.secrets.get_secret_by_kid(kid)
            if recip_key:
                break

        if not recip_key:
            raise DIDCommMessagingError("No recognized recipient key")

        if method == "ECDH-1PU":
            sender_kid_apu = None
            apu = wrapper.protected.get("apu")
            if apu:
                try:
                    sender_kid_apu = from_b64url(apu).decode("utf-8")
                except (UnicodeDecodeError, ValueError):
                    raise DIDCommMessagingError("Invalid apu value")
            sender_kid = wrapper.protected.get("skid") or sender_kid_apu
            if sender_kid_apu and sender_kid != sender_kid_apu:
                raise DIDCommMessagingError("Mismatch between skid and apu")
            if not sender_kid:
                raise DIDCommMessagingError("Sender key ID not provided")
            # FIXME - validate apv if present?

        return PackedMessageMetadata(wrapper, method, recip_key, sender_kid)

    async def unpack(self, enc_message: Union[str, bytes]) -> bytes:
        """Unpack a DIDComm message."""
        metadata = await self.extract_packed_message_metadata(enc_message)

        if metadata.method == "ECDH-ES":
            return await self.crypto.ecdh_es_decrypt(enc_message, metadata.recip_key)

        if not metadata.sender_kid:
            raise DIDCommMessagingError("Missing sender key ID")

        sender_vm = await self.resolver.resolve_and_dereference_verification_method(
            metadata.sender_kid
        )
        sender_key = self.crypto.verification_method_to_public_key(sender_vm)

        return await self.crypto.ecdh_1pu_decrypt(
            enc_message, metadata.recip_key, sender_key
        )

    async def recip_for_kid_or_default_for_did(self, kid_or_did: str) -> P:
        """Resolve a verification method for a kid or return default recip."""
        if "#" in kid_or_did:
            vm = await self.resolver.resolve_and_dereference_verification_method(
                kid_or_did
            )
        else:
            doc = await self.resolver.resolve_and_parse(kid_or_did)
            if not doc.key_agreement:
                raise DIDCommMessagingError(
                    "No key agreement methods found; cannot determine recipient"
                )

            default = doc.key_agreement[0]
            if isinstance(default, DIDUrl):
                vm = doc.dereference(default)
                if not isinstance(vm, VerificationMethod):
                    raise DIDCommMessagingError(
                        f"Expected verification method, found: {type(vm)}"
                    )
            else:
                vm = default

        return self.crypto.verification_method_to_public_key(vm)

    async def default_sender_kid_for_did(self, did: str) -> str:
        """Determine the kid of the default sender key for a DID."""
        if "#" in did:
            return did

        doc = await self.resolver.resolve_and_parse(did)
        if not doc.key_agreement:
            raise DIDCommMessagingError(
                "No key agreement methods found; cannot determine recipient"
            )

        default = doc.key_agreement[0]
        if isinstance(default, DIDUrl):
            vm = doc.dereference(default)
            if not isinstance(vm, VerificationMethod):
                raise DIDCommMessagingError(
                    f"Expected verification method, found: {type(vm)}"
                )
        else:
            vm = default

        if not vm.id.did:
            return vm.id.as_absolute(vm.controller)
        return vm.id

    async def pack(
        self,
        message: bytes,
        to: Sequence[str],
        frm: Optional[str] = None,
        **options,
    ):
        """Pack a DIDComm message."""
        recip_keys = [await self.recip_for_kid_or_default_for_did(kid) for kid in to]
        sender_kid = await self.default_sender_kid_for_did(frm) if frm else None
        sender_key = (
            await self.secrets.get_secret_by_kid(sender_kid) if sender_kid else None
        )
        if frm and not sender_key:
            raise DIDCommMessagingError("No sender key found")

        if sender_key:
            return await self.crypto.ecdh_1pu_encrypt(recip_keys, sender_key, message)
        else:
            return await self.crypto.ecdh_es_encrypt(recip_keys, message)
