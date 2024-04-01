"""did:web resolver.

Resolve did:web style dids to a did document. did:web spec:
https://w3c-ccg.github.io/did-method-web/
"""

from . import DIDResolver, DIDNotFound, DIDResolutionError
from pydid import DID
from urllib.parse import urlparse
from datetime import datetime, timedelta
import urllib.request as url_request
import re
import json
import urllib

domain_regex = (
    r"((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}"
    r"\.(xn--)?([a-z0-9\._-]{1,61}|[a-z0-9-]{1,30})"
    r"(%3[aA]\d+)?"  # Port
    r"(:[a-zA-Z]+)*"  # Path
)
did_web_pattern = re.compile(rf"^did:web:{domain_regex}$")
cache = {}
TIME_TO_CACHE = 1800  # 30 minutes


class DIDWeb(DIDResolver):
    """Utility functions for building and interacting with did:web."""

    async def resolve(self, did: str) -> dict:
        """Resolve a did:web to a did document via http request."""

        # Check to see if we've seen the did recently
        if did in cache:
            if cache[did]["timestamp"] > datetime.now() + timedelta(
                seconds=-TIME_TO_CACHE
            ):
                return cache[did]["doc"]
            else:
                del cache[did]

        uri = DIDWeb._did_to_uri(did)
        headers = {
            "User-Agent": "DIDCommRelay/1.0",
        }
        request = url_request.Request(url=uri, method="GET", headers=headers)
        try:
            with url_request.urlopen(request) as response:
                doc = json.loads(response.read().decode())
                cache[did] = {
                    "timestamp": datetime.now(),
                    "doc": doc,
                }
                return doc
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise DIDNotFound(
                    f"The did:web {did} returned a 404 not found while resolving"
                )
            else:
                raise DIDResolutionError(
                    f"Unknown server error ({e.code}) while resolving did:web: {did}"
                )
        except json.decoder.JSONDecodeError as e:
            msg = str(e)
            raise DIDNotFound(f"The did:web {did} returned invalid JSON {msg}")
        except Exception as e:
            raise DIDResolutionError("Failed to fetch did document") from e

    @staticmethod
    def _did_to_uri(did: str) -> str:
        # Split the did by it's segments
        did_segments = did.split(":")

        # Get the hostname & port
        hostname = did_segments[2].lower()
        hostname = hostname.replace("%3a", ":")

        # Resolve the path portion of the DID, if there is no path, default to
        # a .well-known address
        path = ".well-known"
        if len(did_segments) > 3:
            path = "/".join(did_segments[3:])

        # Assemble the URI
        did_uri = f"https://{hostname}/{path}/did.json"

        return did_uri

    async def is_resolvable(self, did: str) -> bool:
        """Determine if the did is a valid did:web did that can be resolved."""
        if DID.is_valid(did) and did_web_pattern.match(did):
            return True
        return False

    @staticmethod
    def did_from_url(url: str) -> DID:
        """Convert a URL into a did:web did."""

        # Make sure that the URL starts with a scheme
        if not url.startswith("http"):
            url = f"https://{url}"

        # Parse it out to we can grab pieces
        parsed_url = urlparse(url)

        # Assemble the domain portion of the DID
        did = "did:web:%s" % parsed_url.netloc.replace(":", "%3A")

        # Cleanup the path
        path = parsed_url.path.replace(".well-known/did.json", "")
        path = path.replace("/did.json", "")

        # Add the path portion of the did
        if len(path) > 1:
            did += path.replace("/", ":")
        return did
