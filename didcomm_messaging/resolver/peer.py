"""did:peer resolver."""

from didcomm_messaging.resolver import DIDResolver

try:
    from did_peer_2 import resolve as resolve_peer_2
    from did_peer_4 import resolve as resolve_peer_4
except ImportError:
    raise ImportError(
        "did-peer-2 and did-peer-4 are required for did:peer resolution; "
        "install the did_peer extra"
    )


class Peer2(DIDResolver):
    """did:peer:2 resolver."""

    async def resolve(self, did: str) -> dict:
        """Resolve a did:peer:2 DID."""
        return resolve_peer_2(did)


class Peer4(DIDResolver):
    """did:peer:4 resolver."""

    async def resolve(self, did: str) -> dict:
        """Resolve a did:peer:4 DID."""
        return resolve_peer_4(did)
