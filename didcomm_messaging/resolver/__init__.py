"""DID Resolver."""

from abc import ABC, abstractmethod
from typing import Dict
from pydid import DIDDocument, DIDUrl, Resource, VerificationMethod


class ResolutionError(Exception):
    """Represents an error from a DID Resolver."""


class DIDNotFound(ResolutionError):
    """Represents a DID not found error."""


class DIDMethodNotSupported(ResolutionError):
    """Represents a DID method not supported error."""


class Resolver(ABC):
    """DID Resolver interface."""

    @abstractmethod
    async def resolve(self, did: str) -> dict:
        """Resolve a DID."""

    async def resolve_and_parse(self, did: str) -> DIDDocument:
        """Resolve a DID and parse the DID document."""
        doc = await self.resolve(did)
        return DIDDocument.deserialize(doc)

    async def resolve_and_dereference(self, did_url: str) -> Resource:
        """Resolve a DID URL and dereference the identifier."""
        url = DIDUrl.parse(did_url)
        if not url.did:
            raise ResolutionError("Invalid DID URL; must be absolute")

        doc = await self.resolve_and_parse(url.did)
        return doc.dereference(url)

    async def resolve_and_dereference_verification_method(
        self, did_url: str
    ) -> VerificationMethod:
        """Resolve a DID URL and dereference the identifier."""
        resource = await self.resolve_and_dereference(did_url)
        if not isinstance(resource, VerificationMethod):
            raise ResolutionError("Resource is not a verification method")

        return resource


class PrefixResolver(Resolver):
    """DID Resolver delegates to sub-resolvers by DID prefix."""

    def __init__(self, resolvers: Dict[str, Resolver]):
        """Initialize the resolver."""
        self.resolvers = resolvers

    async def resolve(self, did: str) -> dict:
        """Resolve a DID."""
        for prefix, resolver in self.resolvers.items():
            if did.startswith(prefix):
                return await resolver.resolve(did)

        raise DIDMethodNotSupported(f"No resolver found for DID {did}")
