"""DIDComm Messaging Service."""

from dataclasses import dataclass
import json
from typing import Generic, Optional, List, Union

from pydid.service import DIDCommV2Service

from didcomm_messaging.crypto import CryptoService, SecretsManager, P, S
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import DIDResolver
from didcomm_messaging.routing import RoutingService


@dataclass
class PackResult:
    """Result of packing a message."""

    message: bytes
    target_services: List[DIDCommV2Service]

    def get_endpoint(self, protocol: str) -> str:
        """Get the first matching endpoint to send the message to."""
        return self.get_service(protocol).service_endpoint.uri

    def get_service(self, protocol: str) -> DIDCommV2Service:
        """Get the first matching service to send the message to."""
        return self.filter_services_by_protocol(protocol)[0]

    def filter_services_by_protocol(self, protocol: str) -> List[DIDCommV2Service]:
        """Get all services that start with a specific uri protocol."""
        return [
            service
            for service in self.target_services
            if service.service_endpoint.uri.startswith(protocol)
        ]


@dataclass
class UnpackResult:
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


class DIDCommMessagingService(Generic[P, S]):
    """Main entrypoint for DIDComm Messaging."""

    def service_to_target(self, service: DIDCommV2Service) -> str:
        """Convert a service to a target uri.

        This is a very simple implementation that just returns the first one.
        """
        if isinstance(service.service_endpoint, list):
            service_endpoint = service.service_endpoint[0]
        else:
            service_endpoint = service.service_endpoint

        return service_endpoint.uri

    async def pack(
        self,
        crypto: CryptoService[P, S],
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        packaging: PackagingService[P, S],
        routing: RoutingService,
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
            to: recipient of the message, expressed as a DID or a DID URL to a
                verification method
            frm: the sender of the message, expressed as a DID or a DID URL to a
                verification method
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

        encoded_message = await packaging.pack(
            crypto,
            resolver,
            secrets,
            message,
            [to],
            frm,
            **options,
        )

        forward, services = await routing.prepare_forward(
            crypto, packaging, resolver, secrets, to, encoded_message
        )
        return PackResult(forward, services)

    async def unpack(
        self,
        crypto: CryptoService[P, S],
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        packaging: PackagingService[P, S],
        encoded_message: bytes,
        **options,
    ) -> UnpackResult:
        """Unpack a message."""
        unpacked, metadata = await packaging.unpack(
            crypto, resolver, secrets, encoded_message, **options
        )
        return UnpackResult(
            unpacked,
            encrypted=bool(metadata.method),
            authenticated=bool(metadata.sender_kid),
            recipient_kid=metadata.recip_key.kid,
            sender_kid=metadata.sender_kid,
        )


class DIDCommMessaging(Generic[P, S]):
    """Main entrypoint for DIDComm Messaging."""

    def __init__(
        self,
        crypto: CryptoService[P, S],
        secrets: SecretsManager[S],
        resolver: DIDResolver,
        packaging: PackagingService[P, S],
        routing: RoutingService,
    ):
        """Initialize the DIDComm Messaging service."""
        self.crypto = crypto
        self.secrets = secrets
        self.resolver = resolver
        self.packaging = packaging
        self.routing = routing
        self.dmp = DIDCommMessagingService()

    async def pack(
        self,
        message: Union[dict, str, bytes],
        to: str,
        frm: Optional[str] = None,
        **options,
    ) -> PackResult:
        """Pack a message.

        Args:
            message: to send
            to: recipient of the message, expressed as a DID or a DID URL to a
                verification method
            frm: the sender of the message, expressed as a DID or a DID URL to a
                verification method
            options: arbitrary values to pass to the packaging service

        Returns:
            PackResult with packed message and target services
        """
        return await self.dmp.pack(
            self.crypto,
            self.resolver,
            self.secrets,
            self.packaging,
            self.routing,
            message,
            to,
            frm,
            **options,
        )

    async def unpack(
        self,
        encoded_message: bytes,
        **options,
    ) -> UnpackResult:
        """Unpack a message."""
        return await self.dmp.unpack(
            self.crypto,
            self.resolver,
            self.secrets,
            self.packaging,
            encoded_message,
            **options,
        )
