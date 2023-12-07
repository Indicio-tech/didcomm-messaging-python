import pytest

from didcomm_messaging.resolver import (
    DIDMethodNotSupported,
    DIDResolver,
    PrefixResolver,
)


class TestResolver(DIDResolver):
    async def is_resolvable(self, did: str) -> bool:
        return True

    async def resolve(self, did: str) -> dict:
        return {"did": did}


@pytest.fixture(scope="session")
def test_resolver():
    yield TestResolver()


@pytest.mark.asyncio
async def test_prefix_resolver(test_resolver: DIDResolver):
    did = "did:test:example_did"

    resolver = PrefixResolver(resolvers={"did:test:": test_resolver})

    doc = await resolver.resolve(did)
    assert doc["did"] == did

    with pytest.raises(DIDMethodNotSupported):
        await resolver.resolve("This won't work")
