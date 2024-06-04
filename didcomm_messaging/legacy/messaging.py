"""Legacy messaging service."""

from dataclasses import dataclass
import json
from typing import Generic, Optional, Sequence, Union

from pydantic import AnyUrl
from pydid import VerificationMethod
from pydid.service import DIDCommV1Service

from didcomm_messaging.crypto import SecretsManager, P, S
from didcomm_messaging.legacy.base import LegacyCryptoService
from didcomm_messaging.legacy.packaging import LegacyPackagingService
from didcomm_messaging.resolver import DIDResolver


class LegacyDIDCommMessagingError(Exception):
    """Raised on error in legacy didcomm messaging."""


@dataclass
class LegacyPackResult:
    """Result of packing a message."""

    message: bytes
    target_service: str


@dataclass
class LegacyUnpackResult:
    """Result of unpacking a message."""

    unpacked: bytes
    encrytped: bool
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


class LegacyDIDCommMessagingService(Generic[P, S]):
    """Main entrypoint for DIDComm Messaging."""

    async def did_to_target(
        self, crypto: LegacyCryptoService[P, S], resolver: DIDResolver, did: str
    ) -> Target:
        """Resolve recipient information from a DID."""
        doc = await resolver.resolve_and_parse(did)
        services = [
            service
            for service in doc.service or []
            if isinstance(service, DIDCommV1Service)
        ]
        if not services:
            raise LegacyDIDCommMessagingError(f"Unable to send message to DID {did}")
        target = services[0]

        recipient_keys = [
            crypto.verification_method_to_public_key(
                doc.dereference_as(VerificationMethod, recip)
            ).kid
            for recip in target.recipient_keys
        ]
        routing_keys = [
            crypto.verification_method_to_public_key(
                doc.dereference_as(VerificationMethod, routing_key)
            ).kid
            for routing_key in target.routing_keys
        ]
        endpoint = target.service_endpoint
        if isinstance(endpoint, AnyUrl):
            endpoint = str(endpoint)
        if not endpoint.startswith("http") or not endpoint.startswith("ws"):
            raise LegacyDIDCommMessagingError(
                f"Unable to send message to endpoint {endpoint}"
            )

        return Target(recipient_keys, routing_keys, endpoint)

    def forward_wrap(self, to: str, msg: str) -> bytes:
        """Wrap a message in a forward."""
        forward = {
            "@type": "https://didcomm.org/routing/1.0/forward",
            "to": to,
            "msg": msg,
        }
        return json.dumps(forward, separators=(",", ":")).encode()

    async def pack(
        self,
        crypto: LegacyCryptoService[P, S],
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        packaging: LegacyPackagingService[P, S],
        message: Union[dict, str, bytes],
        to: str,
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
            message: to send
            to: recipient of the message, expressed as a DID
            frm: the sender of the message, expressed as a DID
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

        target = await self.did_to_target(crypto, resolver, to)

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

        return LegacyPackResult(encoded_message.to_json().encode(), target.endpoint)

    async def unpack(
        self,
        crypto: LegacyCryptoService[P, S],
        secrets: SecretsManager[S],
        packaging: LegacyPackagingService[P, S],
        encoded_message: bytes,
        **options,
    ) -> LegacyUnpackResult:
        """Unpack a message."""
        unpacked, recip, sender = await packaging.unpack(crypto, secrets, encoded_message)
        return LegacyUnpackResult(
            unpacked,
            encrytped=bool(recip),
            authenticated=bool(sender),
            recipient_kid=recip,
            sender_kid=sender,
        )


class LegacyDIDCommMessaging(Generic[P, S]):
    """Main entrypoint for DIDComm Messaging."""

    def __init__(
        self,
        crypto: LegacyCryptoService[P, S],
        secrets: SecretsManager[S],
        resolver: DIDResolver,
        packaging: LegacyPackagingService[P, S],
    ):
        """Initialize the DIDComm Messaging service."""
        self.crypto = crypto
        self.secrets = secrets
        self.resolver = resolver
        self.packaging = packaging
        self.dmp = LegacyDIDCommMessagingService()

    async def pack(
        self,
        message: Union[dict, str, bytes],
        to: str,
        frm: Optional[str] = None,
        **options,
    ) -> LegacyPackResult:
        """Pack a message.

        Args:
            message: to send
            to: recipient of the message, expressed as a KID which is a Base58
                encoded Ed25519 public key
            frm: the sender of the message, expressed as a KID which is a Base58
                encoded Ed25519 public key
            options: arbitrary values to pass to the packaging service

        Returns:
            LegacyPackResult with packed message and target services
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
    ) -> LegacyUnpackResult:
        """Unpack a message."""
        return await self.dmp.unpack(
            self.crypto,
            self.secrets,
            self.packaging,
            encoded_message,
            **options,
        )
