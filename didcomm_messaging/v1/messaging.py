"""V1 messaging service."""

from dataclasses import dataclass
import json
import uuid
from typing import Generic, Optional, Sequence, Union

from pydantic import AnyUrl
from pydid import DIDDocument, VerificationMethod
from pydid.service import DIDCommV1Service

from didcomm_messaging.crypto import P, S, SecretsManager
from didcomm_messaging.resolver import DIDResolver
from didcomm_messaging.v1.crypto.base import V1CryptoService
from didcomm_messaging.v1.packaging import V1PackagingService


class V1DIDCommMessagingError(Exception):
    """Raised on error in v1 didcomm messaging."""


@dataclass
class V1PackResult:
    """Result of packing a message."""

    message: bytes
    target_service: str


@dataclass
class V1UnpackResult:
    """Result of unpacking a message."""

    unpacked: bytes
    encrypted: bool
    authenticated: bool
    recipient_kid: str
    sender_kid: Optional[str] = None

    @property
    def message(self) -> dict:
        """Return unpacked value as a dict.

        This value is used to preserve backwards compatibility.
        """
        return json.loads(self.unpacked)


@dataclass
class Target:
    """Recipient info for sending a message."""

    recipient_keys: Sequence[str]
    routing_keys: Sequence[str]
    endpoint: str


class V1DIDCommMessagingService(Generic[P, S]):
    """Main entrypoint for DIDComm Messaging."""

    def vm_to_v1_kid(self, crypto: V1CryptoService, doc: DIDDocument, ref: str) -> str:
        """Convert a verification method ref to a DIDComm v1 kid."""
        return crypto.public_key_to_v1_kid(
            crypto.verification_method_to_public_key(
                doc.dereference_as(VerificationMethod, ref)
            )
        )

    async def did_to_target(
        self, crypto: V1CryptoService[P, S], resolver: DIDResolver, did: str
    ) -> Target:
        """Resolve recipient information from a DID."""
        doc = await resolver.resolve_and_parse(did)
        services = [
            service
            for service in doc.service or []
            if isinstance(service, DIDCommV1Service)
        ]
        if not services:
            raise V1DIDCommMessagingError(f"Unable to send message to DID {did}")
        target = services[0]

        recipient_keys = [
            self.vm_to_v1_kid(crypto, doc, recip) for recip in target.recipient_keys
        ]
        routing_keys = [
            self.vm_to_v1_kid(crypto, doc, routing_key)
            for routing_key in target.routing_keys
        ]
        endpoint = target.service_endpoint
        if isinstance(endpoint, AnyUrl):
            endpoint = str(endpoint)
        if not endpoint.startswith("http") and not endpoint.startswith("ws"):
            raise V1DIDCommMessagingError(
                f"Unable to send message to endpoint {endpoint}"
            )

        return Target(recipient_keys, routing_keys, endpoint)

    async def from_did_to_kid(
        self, crypto: V1CryptoService[P, S], resolver: DIDResolver, did: str
    ) -> str:
        """Resolve our DID to a kid to be used by crypto layers."""
        doc = await resolver.resolve_and_parse(did)
        services = [
            service
            for service in doc.service or []
            if isinstance(service, DIDCommV1Service)
        ]
        if not services:
            raise V1DIDCommMessagingError(f"Unable to send message to DID {did}")
        target = services[0]

        recipient_keys = [
            self.vm_to_v1_kid(crypto, doc, recip) for recip in target.recipient_keys
        ]
        return recipient_keys[0]

    def forward_wrap(self, to: str, msg: str) -> bytes:
        """Wrap a message in a forward."""
        forward = {
            "@id": str(uuid.uuid4()),
            "@type": "https://didcomm.org/routing/1.0/forward",
            "to": to,
            "msg": msg,
        }
        return json.dumps(forward, separators=(",", ":")).encode()

    async def pack(
        self,
        crypto: V1CryptoService[P, S],
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        packaging: V1PackagingService[P, S],
        message: Union[dict, str, bytes],
        to: Union[str, Target],
        frm: Optional[str] = None,
        **options,
    ):
        """Pack a message.

        Args:
            crypto: crytpo service to use to pack the message
            resolver: resolver to use to resolve DIDs
            secrets: secrets manager to use to look up private key material
            packaging: packaging service
            routing: routing service
            message: to send; must be str, bytes, or json serializable dict
            to: recipient of the message, expressed as a DID or Target
            frm: the sender of the message, expressed as a DID or kid (base58 encoded
                public key)
            options: arbitrary values to pass to the packaging service

        Returns:
            PackResult with packed message and target services

        """
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, dict):
            message = json.dumps(message, separators=(",", ":")).encode()
        elif isinstance(message, bytes):
            pass
        else:
            raise TypeError("message must be bytes, str, or dict")

        if isinstance(to, str):
            target = await self.did_to_target(crypto, resolver, to)
        else:
            target = to

        if frm and frm.startswith("did:"):
            frm = await self.from_did_to_kid(crypto, resolver, frm) if frm else None

        encoded_message = await packaging.pack(
            crypto,
            secrets,
            message,
            target.recipient_keys,
            frm,
            **options,
        )

        if target.routing_keys:
            forward_to = target.recipient_keys[0]
            for routing_key in target.routing_keys:
                encoded_message = await packaging.pack(
                    crypto,
                    secrets,
                    self.forward_wrap(forward_to, encoded_message.to_json()),
                    [routing_key],
                )
                forward_to = routing_key

        return V1PackResult(encoded_message.to_json().encode(), target.endpoint)

    async def unpack(
        self,
        crypto: V1CryptoService[P, S],
        secrets: SecretsManager[S],
        packaging: V1PackagingService[P, S],
        encoded_message: bytes,
        **options,
    ) -> V1UnpackResult:
        """Unpack a message."""
        unpacked, recip, sender = await packaging.unpack(crypto, secrets, encoded_message)
        return V1UnpackResult(
            unpacked,
            encrypted=bool(recip),
            authenticated=bool(sender),
            recipient_kid=recip,
            sender_kid=sender,
        )


class V1DIDCommMessaging(Generic[P, S]):
    """Main entrypoint for DIDComm Messaging."""

    def __init__(
        self,
        crypto: V1CryptoService[P, S],
        secrets: SecretsManager[S],
        resolver: DIDResolver,
        packaging: V1PackagingService[P, S],
    ):
        """Initialize the DIDComm Messaging service."""
        self.crypto = crypto
        self.secrets = secrets
        self.resolver = resolver
        self.packaging = packaging
        self.dmp = V1DIDCommMessagingService()

    async def pack(
        self,
        message: Union[dict, str, bytes],
        to: Union[str, Target],
        frm: Optional[str] = None,
        **options,
    ) -> V1PackResult:
        """Pack a message.

        Args:
            message: to send; must be str, bytes, or json serializable dict
            to: recipient of the message, expressed as a DID or Target
            frm: the sender of the message, expressed as a DID or kid (base58 encoded
                public key)
            options: arbitrary values to pass to the packaging service

        Returns:
            V1PackResult with packed message and target services
        """
        return await self.dmp.pack(
            self.crypto,
            self.resolver,
            self.secrets,
            self.packaging,
            message,
            to,
            frm,
            **options,
        )

    async def unpack(
        self,
        encoded_message: bytes,
        **options,
    ) -> V1UnpackResult:
        """Unpack a message."""
        return await self.dmp.unpack(
            self.crypto,
            self.secrets,
            self.packaging,
            encoded_message,
            **options,
        )
