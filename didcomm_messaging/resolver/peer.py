"""did:peer resolver."""

from didcomm_messaging.resolver import DIDResolver

try:
    from did_peer_2 import resolve as resolve_peer_2
    from did_peer_2 import PATTERN as peer_2_pattern
    from did_peer_4 import resolve as resolve_peer_4
    from did_peer_4 import LONG_PATTERN as peer_4_pattern_long
    from did_peer_4 import SHORT_PATTERN as peer_4_pattern_short
except ImportError:
    raise ImportError(
        "did-peer-2 and did-peer-4 are required for did:peer resolution; "
        "install the did_peer extra"
    )


class Peer2(DIDResolver):
    """did:peer:2 resolver."""

    async def is_resolvable(self, did: str) -> bool:
        """Check to see if a DID is resolvable."""
        return bool(peer_2_pattern.match(did))

    async def resolve(self, did: str) -> dict:
        """Resolve a did:peer:2 DID."""
        return resolve_peer_2(did)


class Peer4(DIDResolver):
    """did:peer:4 resolver."""

    async def is_resolvable(self, did: str) -> bool:
        """Check to see if a DID is resolvable."""
        return bool(peer_4_pattern_short.match(did) or peer_4_pattern_long.match(did))

    async def resolve(self, did: str) -> dict:
        """Resolve a did:peer:4 DID."""
        return resolve_peer_4(did)
