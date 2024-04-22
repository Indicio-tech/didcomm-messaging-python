"""RoutingService interface."""

import json
import uuid

from typing import Tuple, List, Dict, Any
from pydid.service import DIDCommV2Service
from didcomm_messaging.crypto.base import P, S, CryptoService, SecretsManager
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import DIDResolver


class RoutingServiceError(Exception):
    """Raised when an error occurs in the RoutingService."""


class RoutingService:
    """RoutingService."""

    async def _resolve_services(
        self, resolver: DIDResolver, to: str
    ) -> List[DIDCommV2Service]:
        if not await resolver.is_resolvable(to):
            return []
        did_doc = await resolver.resolve_and_parse(to)
        services = []
        if did_doc.service:  # service is not guaranteed to exist
            for did_service in did_doc.service:
                if did_service.type != "DIDCommMessaging":
                    continue
                if "didcomm/v2" in did_service.service_endpoint.accept:
                    services.append(did_service)
        if not services:
            return []
        return services

    async def is_forwardable_service(
        self, resolver: DIDResolver, service: DIDCommV2Service
    ) -> bool:
        """Determine if the uri of a service is a service we should forward to."""
        endpoint = service.service_endpoint.uri
        found_forwardable_service = await resolver.is_resolvable(endpoint)
        return found_forwardable_service

    def _create_forward_message(
        self, to: str, next_target: str, message: bytes
    ) -> Dict[Any, Any]:
        return {
            "typ": "application/didcomm-plain+json",
            "type": "https://didcomm.org/routing/2.0/forward",
            "id": str(uuid.uuid4()),
            "to": [to],
            # "expires_time": 123456, #  time to expire the forward message, in epoch time
            "body": {"next": next_target},
            "attachments": [
                {
                    "id": str(uuid.uuid4()),
                    "media_type": "application/didcomm-encrypted+json",
                    "data": {
                        "json": json.loads(message),
                    },
                },
            ],
        }

    async def prepare_forward(
        self,
        crypto: CryptoService[P, S],
        packaging: PackagingService,
        resolver: DIDResolver,
        secrets: SecretsManager[S],
        to: str,
        encoded_message: bytes,
    ) -> Tuple[bytes, DIDCommV2Service]:
        """Prepare a forward message, if necessary.

        Args:
            crypto (CryptoService[P, S]): Crypto service
            packaging (PackagingService): Packaging service
            resolver (DIDResolver): Resolver instance
            secrets (SecretsManager[S]): Secrets manager
            to (str): The recipient of the message. This will be a DID.
            encoded_message (bytes): The encoded message.

        Returns:
            The encoded message, and the services to forward to.
        """

        # Get the initial service
        services = await self._resolve_services(resolver, to)
        chain = [
            {
                "did": to,
                "service": services,
            }
        ]

        # Loop through service DIDs until we run out of DIDs to forward to
        to_did = services[0].service_endpoint.uri
        found_forwardable_service = await self.is_forwardable_service(
            resolver, services[0]
        )
        while found_forwardable_service:
            services = await self._resolve_services(resolver, to_did)
            if services:
                chain.append(
                    {
                        "did": to_did,
                        "service": services,
                    }
                )
                to_did = services[0].service_endpoint.uri
            found_forwardable_service = (
                await self.is_forwardable_service(resolver, services[0])
                if services
                else False
            )

        if not chain[-1]["service"]:
            raise RoutingServiceError(f"No DIDCommV2 service endpoint found for {to}")

        # If we didn't find any services to forward to, just bail
        if len(chain) == 1:
            return (encoded_message, chain[-1]["service"])

        # Grab our target to pack the initial message to, then pack the message
        # for the DID target
        final_destination = chain.pop(0)
        next_target = final_destination["did"]
        packed_message = encoded_message

        # Loop through the entire services chain and pack the message for each
        # layer of mediators
        for service in chain:
            # https://identity.foundation/didcomm-messaging/spec/#sender-process-to-enable-forwarding
            # Respect routing keys by adding the current DID to the front of
            # the list, then wrapping message following routing key order
            routing_keys = service["service"][0].service_endpoint.routing_keys
            routing_keys.insert(0, service["did"])  # prepend did

            # Pack for each key
            while routing_keys:
                key = routing_keys.pop()  # pop from end of list (reverse order)
                packed_message = await packaging.pack(
                    crypto,
                    resolver,
                    secrets,
                    json.dumps(
                        self._create_forward_message(key, next_target, packed_message)
                    ).encode(),
                    [key],
                )
                next_target = key

        # Return the forward-packed message as well as the last service in the
        # chain, which is the destination of the top-level forward message.
        service = final_destination["service"]
        if len(chain):
            service = chain[-1]["service"]
        return (packed_message, service)
