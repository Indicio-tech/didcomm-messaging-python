"""RoutingService interface."""

from typing import Tuple
from pydid.service import DIDCommV2Service
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import DIDResolver


class RoutingServiceError(Exception):
    """Raised when an error occurs in the RoutingService."""


class RoutingService:
    """RoutingService."""

    def __init__(self, packaging: PackagingService, resolver: DIDResolver):
        """Initialize the RoutingService."""
        self.packaging = packaging
        self.resolver = resolver

    async def _resolve_service(self, to: str) -> DIDCommV2Service:
        """Resolve the service endpoint for a given DID."""
        doc = await self.resolver.resolve_and_parse(to)
        if not doc.service:
            raise RoutingServiceError(f"No service endpoint found for {to}")

        first_didcomm_service = next(
            (
                service
                for service in doc.service
                if isinstance(service, DIDCommV2Service)
            ),
            None,
        )
        if not first_didcomm_service:
            raise RoutingServiceError(f"No DIDCommV2 service endpoint found for {to}")

        return first_didcomm_service

    async def prepare_forward(
        self, to: str, encoded_message: bytes
    ) -> Tuple[bytes, DIDCommV2Service]:
        """Prepare a forward message, if necessary.

        Args:
            to (str): The recipient of the message. This will be a DID.
            encoded_message (bytes): The encoded message.

        Returns:
            The encoded message, and the service endpoint to forward to.
        """
        service = await self._resolve_service(to)
        # TODO Do the stuff
        return encoded_message, service
