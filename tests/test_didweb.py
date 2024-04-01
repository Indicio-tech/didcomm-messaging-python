import pytest


from didcomm_messaging.resolver.web import DIDWeb

DIDWEB = "did:web:example.com"
DIDWEB_URI = "https://example.com/.well-known/did.json"
DIDWEB_COMPLEX = "did:web:example.com%3A4443:DIDs:alice:relay"
DIDWEB_COMPLEX_URI = "https://example.com:4443/DIDs/alice/relay/did.json"


@pytest.mark.asyncio
async def test_didweb_from_didurl_domain():
    did = DIDWeb.did_from_url("example.com")
    assert did
    assert did == DIDWEB


@pytest.mark.asyncio
async def test_didweb_from_didurl_schema_and_domain():
    did = DIDWeb.did_from_url("https://example.com")
    assert did
    assert did == DIDWEB


@pytest.mark.asyncio
async def test_didweb_from_didurl_schema_and_domain_slash():
    did = DIDWeb.did_from_url("https://example.com/")
    assert did
    assert did == DIDWEB


@pytest.mark.asyncio
async def test_didweb_from_didurl_schema_and_domain_path():
    did = DIDWeb.did_from_url("https://example.com/did.json")
    assert did
    assert did == DIDWEB


@pytest.mark.asyncio
async def test_didweb_from_didurl_schema_and_domain_wellknown():
    did = DIDWeb.did_from_url("https://example.com/.well-known/did.json")
    assert did
    assert did == DIDWEB


@pytest.mark.asyncio
async def test_didweb_from_didurl_schema_and_domain_port_wellknown():
    did = DIDWeb.did_from_url("https://example.com:443/.well-known/did.json")
    assert did
    assert did == DIDWEB + "%3A443"


@pytest.mark.asyncio
async def test_didweb_from_didurl_schema_and_complex_domain_path():
    did = DIDWeb.did_from_url("https://example.com:4443/DIDs/alice/relay/did.json")
    assert did
    assert did == DIDWEB_COMPLEX


@pytest.mark.asyncio
async def test_didweb_to_url():
    uri = DIDWeb._did_to_uri(DIDWEB)
    assert uri
    assert uri == DIDWEB_URI


@pytest.mark.asyncio
async def test_didweb_to_url_complex():
    uri = DIDWeb._did_to_uri(DIDWEB_COMPLEX)
    assert uri
    assert uri == DIDWEB_COMPLEX_URI


@pytest.mark.asyncio
async def test_didweb_is_resolvable():
    resolver = DIDWeb()
    resolvable = await resolver.is_resolvable(DIDWEB)
    assert resolvable
    resolvable_complex = await resolver.is_resolvable(DIDWEB_COMPLEX)
    assert resolvable_complex


@pytest.mark.external_fetch
@pytest.mark.asyncio
async def test_didweb_fetch():
    did_web = "did:web:colton.wolkins.net"
    resolver = DIDWeb()
    uri = await resolver.resolve(did_web)
    print(uri)
    assert uri
    assert isinstance(uri, dict)


@pytest.mark.external_fetch
@pytest.mark.asyncio
async def test_didweb_double_fetch():
    did_web = "did:web:colton.wolkins.net"
    resolver = DIDWeb()
    uri = await resolver.resolve(did_web)
    print(uri)
    assert uri
    assert isinstance(uri, dict)
    uri = await resolver.resolve(did_web)
    assert uri
    assert isinstance(uri, dict)
