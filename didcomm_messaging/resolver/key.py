"""DID Key Resolver."""

from didcomm_messaging.resolver import DIDResolver


class DIDKey(DIDResolver):
    """did:key resolver."""

    async def is_resolvable(self, did: str) -> bool:
        """Check to see if DID is resolvable by this resolver."""
        return did.startswith("did:key:")

    async def resolve(self, did: str) -> dict:
        """Resolve a did:key."""
        _, multikey = did.split("did:key:")
        id = f"{did}#{multikey}"
        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": did,
            "verificationMethod": [
                {
                    "id": id,
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": multikey,
                }
            ],
            **{
                rel: [id]
                for rel in (
                    "authentication",
                    "assertionMethod",
                    "capabilityDelegation",
                    "capabilityInvocation",
                )
            },
        }
