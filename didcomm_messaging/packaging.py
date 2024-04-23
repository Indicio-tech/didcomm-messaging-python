"""PackagingService interface."""

from dataclasses import dataclass
import hashlib
from typing import Generic, Literal, Optional, Sequence, Tuple, Union

from pydid import DIDUrl, VerificationMethod
from didcomm_messaging.crypto import P, S, CryptoService, SecretsManager
from didcomm_messaging.crypto.jwe import JweEnvelope, b64url, from_b64url
from didcomm_messaging.resolver import DIDResolver


@dataclass
class PackedMessageMetadata(Generic[S]):
    """Unpack result."""

    wrapper: JweEnvelope
    method: Literal["ECDH-ES", "ECDH-1PU"]
    recip_key: S
    sender_kid: Optional[str]


class PackagingServiceError(Exception):
    """Represents an error from the DIDComm Messaging interface."""


class PackagingService(Generic[P, S]):
    """DIDComm Messaging interface."""

    async def extract_packed_message_metadata(  # noqa: C901
        self, enc_message: Union[str, bytes], secrets: SecretsManager[S]
    ) -> PackedMessageMetadata:
        """Extract metadata from a packed DIDComm message."""
        try:
            wrapper = JweEnvelope.from_json(enc_message)
        except ValueError:
            raise PackagingServiceError("Invalid packed message")

        alg = wrapper.protected.get("alg")
        if not alg:
            raise PackagingServiceError("Missing alg header")

        method = next((m for m in ("ECDH-1PU", "ECDH-ES") if m in alg), None)
        if not method:
            raise PackagingServiceError(
                f"Unsupported DIDComm encryption algorithm: {alg}"
            )

        sender_kid = None
        recip_key = None
        for kid in wrapper.recipient_key_ids:
            recip_key = await secrets.get_secret_by_kid(kid)
            if recip_key:
                break

        if not recip_key:
            raise PackagingServiceError("No recognized recipient key")

        expected_apv = b64url(
            hashlib.sha256((".".join(wrapper.recipient_key_ids)).encode()).digest()
        )
        apv = wrapper.protected.get("apv")
        if not apv:
            raise PackagingServiceError("Missing apv header")
        if apv != expected_apv:
            raise PackagingServiceError("Invalid apv value")

        if method == "ECDH-1PU":
            sender_kid_apu = None
            apu = wrapper.protected.get("apu")
            if not apu:
                raise PackagingServiceError("Missing apu header")

            try:
                sender_kid_apu = from_b64url(apu).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                raise PackagingServiceError("Invalid apu value")

            sender_kid = wrapper.protected.get("skid") or sender_kid_apu
            if sender_kid != sender_kid_apu:
                raise PackagingServiceError("Mismatch between skid and apu")
            if not sender_kid:
                raise PackagingServiceError("Sender key ID not provided")

        return PackedMessageMetadata(wrapper, method, recip_key, sender_kid)

    async def unpack(
        self,
        crypto: CryptoService[P, S],
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        enc_message: Union[str, bytes],
    ) -> Tuple[bytes, PackedMessageMetadata]:
        """Unpack a DIDComm message."""
        metadata = await self.extract_packed_message_metadata(enc_message, secrets)

        if metadata.method == "ECDH-ES":
            return (
                await crypto.ecdh_es_decrypt(enc_message, metadata.recip_key),
                metadata,
            )

        if not metadata.sender_kid:
            raise PackagingServiceError("Missing sender key ID")

        sender_vm = await resolver.resolve_and_dereference_verification_method(
            metadata.sender_kid
        )
        sender_key = crypto.verification_method_to_public_key(sender_vm)

        return (
            await crypto.ecdh_1pu_decrypt(enc_message, metadata.recip_key, sender_key),
            metadata,
        )

    async def recip_for_kid_or_default_for_did(
        self, crypto: CryptoService[P, S], resolver: DIDResolver, kid_or_did: str
    ) -> P:
        """Resolve a verification method for a kid or return default recip."""
        if "#" in kid_or_did:
            vm = await resolver.resolve_and_dereference_verification_method(kid_or_did)
        else:
            doc = await resolver.resolve_and_parse(kid_or_did)
            if not doc.key_agreement:
                raise PackagingServiceError(
                    "No key agreement methods found; cannot determine recipient"
                )

            default = doc.key_agreement[0]
            if isinstance(default, DIDUrl):
                vm = doc.dereference(default)
                if not isinstance(vm, VerificationMethod):
                    raise PackagingServiceError(
                        f"Expected verification method, found: {type(vm)}"
                    )
            else:
                vm = default

        return crypto.verification_method_to_public_key(vm)

    async def default_sender_kid_for_did(self, resolver: DIDResolver, did: str) -> str:
        """Determine the kid of the default sender key for a DID."""
        if "#" in did:
            return did

        doc = await resolver.resolve_and_parse(did)
        if not doc.key_agreement:
            raise PackagingServiceError(
                "No key agreement methods found; cannot determine recipient"
            )

        default = doc.key_agreement[0]
        if isinstance(default, DIDUrl):
            vm = doc.dereference(default)
            if not isinstance(vm, VerificationMethod):
                raise PackagingServiceError(
                    f"Expected verification method, found: {type(vm)}"
                )
        else:
            vm = default

        if not vm.id.did:
            return vm.id.as_absolute(vm.controller)
        return vm.id

    async def pack(
        self,
        crypto: CryptoService[P, S],
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        message: bytes,
        to: Sequence[str],
        frm: Optional[str] = None,
        **options,
    ):
        """Pack a DIDComm message."""
        recip_keys = [
            await self.recip_for_kid_or_default_for_did(crypto, resolver, kid)
            for kid in to
        ]
        sender_kid = await self.default_sender_kid_for_did(resolver, frm) if frm else None
        sender_key = await secrets.get_secret_by_kid(sender_kid) if sender_kid else None
        if frm and not sender_key:
            raise PackagingServiceError("No sender key found")

        if sender_key:
            return await crypto.ecdh_1pu_encrypt(recip_keys, sender_key, message)
        else:
            return await crypto.ecdh_es_encrypt(recip_keys, message)
