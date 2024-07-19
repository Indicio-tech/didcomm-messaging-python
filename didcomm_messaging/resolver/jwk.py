"""did:jwk Resolver."""

import re
import json

from didcomm_messaging import DIDResolver
from didcomm_messaging.resolver import DIDResolutionError
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder

b64 = Base64UrlEncoder()


class JWKResolver(DIDResolver):
    """Resolve did:jwk."""

    PATTERN = re.compile(r"^did:jwk:(?P<did>.*)$")

    async def resolve(self, did: str) -> dict:
        """Resolve a did:jwk."""
        if match := self.PATTERN.match(did):
            encoded = match.group("did")
        else:
            raise DIDResolutionError(f"Invalid DID: {did}")

        jwk = json.loads(b64.decode(encoded))
        doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
            ],
            "id": f"did:jwk:{encoded}",
            "verificationMethod": [
                {
                    "id": f"did:jwk:{encoded}#0",
                    "type": "JsonWebKey2020",
                    "controller": f"did:jwk:{encoded}",
                    "publicKeyJwk": jwk,
                }
            ],
        }

        use = jwk.get("use")
        if use == "sig":
            doc.update(
                {
                    "assertionMethod": [f"did:jwk:{encoded}#0"],
                    "authentication": [f"did:jwk:{encoded}#0"],
                    "capabilityInvocation": [f"did:jwk:{encoded}#0"],
                    "capabilityDelegation": [f"did:jwk:{encoded}#0"],
                }
            )
        elif use == "enc":
            doc.update({"keyAgreement": [f"did:jwk:{encoded}#0"]})

        return doc

    async def is_resolvable(self, did: str) -> bool:
        """Return if did is resolvable by this resolver."""
        return bool(self.PATTERN.match(did))
