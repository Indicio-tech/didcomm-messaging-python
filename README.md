# didcomm-messaging-python

This is a minimal but flexible implementation of [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/v2.1/). To learn more about DIDComm Messaging, check out the spec or visit [didcomm.org](https://didcomm.org) to learn about DIDComm Messaging protocols defined by the community.

## Usage

https://github.com/Indicio-tech/didcomm-messaging-python/blob/f078c7def05bd98649da19b1ca47d2d2d7c26083/example.py#L1-L50

## Overview

![didcomm-messaging-python layer cake](docs/images/layers.png)

This library has the following core components (as outlined in the layer cake architecture diagram above):

### CryptoService

The CryptoService provides the core cryptographic capabilities needed to encrypt and decrypt DIDComm Messages. This service is designed to be implemented by users of this library; however, an implementation using Aries Askar is available as an extra (install the `askar` extra to use it). Additional implementations may be added as extras in the future (i.e. an implementation using [Authlib's JWE implementation](https://docs.authlib.org/en/latest/jose/jwe.html) or perhaps an implementation backed by an HSM). The service is seprate from but closely coupled with the SecretsManager. Both must use the same public and private key representations.

> [!WARNING]
> This library requires a crypto backend. You MUST provide a CryptoService and SecretsManager implementation. The Askar backend is available via the `askar` extra (install with `pip install -e ".[askar]"`).

The CryptoService interface (`didcomm_messaging.crypto.base.CryptoService`) requires:

- **`ecdh_es_encrypt(to_keys, message)`** - Encrypt a message using ECDH-ES (anonymous encryption)
- **`ecdh_es_decrypt(wrapper, recip_key)`** - Decrypt an ECDH-ES encrypted message
- **`ecdh_1pu_encrypt(to_keys, sender_key, message)`** - Encrypt using ECDH-1PU (authenticated encryption)
- **`ecdh_1pu_decrypt(wrapper, recip_key, sender_key)`** - Decrypt an ECDH-1PU encrypted message
- **`verification_method_to_public_key(vm)`** - Convert a DID Document verification method to a public key

You must also define `PublicKey` and `SecretKey` types that work with your implementation.

**Using the included AskarCryptoService:**

```python
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarKey, AskarSecretKey

crypto = AskarCryptoService()
```

The AskarCryptoService supports `Ed25519`, `X25519`, `P-256`, and `Secp256k1` key types via the Aries Askar library.

### SecretsManager

The SecretsManager is responsible for retrieving secrets for use by the CryptoService. It is notable that the secret value need not literally contain the value of a private key. For example, in the included Askar implementation, an Askar `Key` value is retrieved. This object in python _does_ permit you to retrieve the bytes of the secret key from Askar if you choose; however, this is not necessary for the operation of the library. This enables Askar to keep the private key value down in the Rust layer where it can better ensure security of the key (zeroizing memory, etc.). This is not so distant from interacting with an HSM; as long as the `SecretKey` value retrieved by the SecretsManager can be used by the CryptoService to perform the required cryptographic operations, exactly what is stored inside of the `SecretKey` object is irrelevant.

The SecretsManager interface (`didcomm_messaging.crypto.base.SecretsManager`) requires:

- **`get_secret_by_kid(kid)`** - Retrieve a secret key by its key ID. Returns `None` if not found.

**Implementing your own SecretsManager:**

```python
from didcomm_messaging.crypto.base import SecretsManager, SecretKey

class MySecretsManager(SecretsManager[MySecretKey]):
    async def get_secret_by_kid(self, kid: str) -> Optional[MySecretKey]:
        # Look up your secret by key ID
        # Return None if not found
        pass
```

**Using the included AskarSecretsManager:**

```python
from didcomm_messaging.crypto.backend.askar import AskarSecretsManager
from aries_askar import Store

store = await Store.open("my-db")
secrets = AskarSecretsManager(store)
```

The library also includes an `InMemorySecretsManager` (`didcomm_messaging.crypto.backend.basic`) for testing and simple use cases.

### DIDResolver

This component provides a fairly generic DID Resolution interface. Users of this library will provide a resolver implementation for the DID Methods they care about. Implementations of did:peer:2 and did:peer:4 are included as part of the `did_peer` extra.

The DIDResolver interface (`didcomm_messaging.resolver.DIDResolver`) requires:

- **`resolve(did)`** - Resolve a DID to a DID Document (dict)
- **`is_resolvable(did)`** - Check if a DID can be resolved

The interface also provides convenience methods:
- **`resolve_and_parse(did)`** - Returns a parsed `pydid.DIDDocument`
- **`resolve_and_dereference(did_url)`** - Dereference a DID URL to get a resource
- **`resolve_and_dereference_verification_method(did_url)`** - Dereference to a verification method

**Using PrefixResolver:**

The `PrefixResolver` delegates to sub-resolvers based on DID method prefix. This allows you to support multiple DID methods:

```python
from didcomm_messaging.resolver import PrefixResolver
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.resolver.web import DIDWeb

resolver = PrefixResolver({
    "did:peer:2": Peer2(),
    "did:peer:4": Peer4(),
    "did:web:": DIDWeb(),
})
```

**Implementing your own DIDResolver:**

```python
from didcomm_messaging.resolver import DIDResolver

class MyDIDResolver(DIDResolver):
    async def resolve(self, did: str) -> dict:
        # Resolve DID and return DID Document as dict
        pass

    async def is_resolvable(self, did: str) -> bool:
        # Check if this resolver can handle the DID
        pass
```

### PackagingService

The PackagingService is responsible for the core functions of packing and unpacking messages. It depends on the CryptoService, the SecretsManager, and the DIDResolver to accomplish this.

The PackagingService (`didcomm_messaging.packaging.PackagingService`) provides:

- **`pack(crypto, resolver, secrets, message, to, frm)`** - Pack a message for one or more recipients
  - `message`: bytes to encrypt
  - `to`: list of recipient DIDs or DID URLs
  - `frm`: sender DID (optional, for authenticated encryption)
  - Returns encrypted bytes

- **`unpack(crypto, resolver, secrets, enc_message)`** - Unpack and decrypt a message
  - Returns tuple of (plaintext bytes, `PackedMessageMetadata`)

- **`extract_packed_message_metadata(enc_message, secrets)`** - Extract metadata without decrypting

**Usage:**

```python
from didcomm_messaging.packaging import PackagingService

packaging = PackagingService()

# Pack a message
packed = await packaging.pack(
    crypto=crypto,
    resolver=resolver,
    secrets=secrets,
    message=b'{"hello": "world"}',
    to=["did:peer:2:..."],
    frm="did:peer:2:..."  # optional for authenticated encryption
)

# Unpack a message
plaintext, metadata = await packaging.unpack(
    crypto=crypto,
    resolver=resolver,
    secrets=secrets,
    enc_message=packed
)
```

### RoutingService

The RoutingService is responsible for preparing messages for forwarding to a mediator. It depends on the PackagingService and the DIDResolver to accomplish this.

The RoutingService (`didcomm_messaging.routing.RoutingService`) provides:

- **`prepare_forward(crypto, packaging, resolver, secrets, to, encoded_message)`** - Prepare a message for forwarding through mediators
  - Resolves the recipient's service endpoint
  - If the recipient is behind a mediator, wraps the message in forward messages
  - Handles multiple levels of routing (mediator chains)
  - Returns tuple of (packed message bytes, target service)

**How it works:**

1. Resolves the recipient's DID to find `DIDCommMessaging` service endpoints
2. If the service endpoint is another DID (mediator), recursively resolves
3. Creates forward messages for each layer of mediation
4. Returns the outermost packed message and the final destination service

```python
from didcomm_messaging.routing import RoutingService

routing = RoutingService()

# Prepare a message for forwarding
packed, services = await routing.prepare_forward(
    crypto=crypto,
    packaging=packaging,
    resolver=resolver,
    secrets=secrets,
    to="did:peer:2:...",  # recipient DID
    encoded_message=b'...'  # already-packed message
)
```

### DIDCommMessaging

The DIDCommMessaging interface is the main entrypoint for interacting with this library. It utilizes all the layers below to prepare messages for other parties.

**Initialization:**

```python
from didcomm_messaging import DIDCommMessaging

dmp = DIDCommMessaging(
    crypto=crypto,
    secrets=secrets,
    resolver=resolver,
    packaging=packaging,
    routing=routing,
)
```

**Pack a message:**

```python
# Pack and send a message
result = await dmp.pack(
    message={"type": "https://didcomm.org/hello/1.0/greeting", "body": {"msg": "Hello!"}},
    to="did:peer:2:...",
    frm="did:peer:2:..."  # optional
)

# Get the endpoint to send to
endpoint = result.get_endpoint("http")

# Get the packed message
packed_message = result.message
```

**Unpack a message:**

```python
result = await dmp.unpack(encoded_message)

print(result.message)       # The decrypted message as dict
print(result.authenticated) # True if sender was authenticated
print(result.sender_kid)    # Key ID of sender (if authenticated)
print(result.recipient_kid) # Key ID of recipient
```

**Return values:**

- `PackResult.message` - The packed message bytes
- `PackResult.target_services` - List of target `DIDCommV2Service` endpoints
- `PackResult.get_endpoint(protocol)` - Get endpoint by protocol (e.g., "http", "ws")
- `UnpackResult.message` - The unpacked message as dict
- `UnpackResult.authenticated` - Whether the message was authenticated (ECDH-1PU)
- `UnpackResult.encrypted` - Whether the message was encrypted
- `UnpackResult.sender_kid` - Sender's key ID (if authenticated)
- `UnpackResult.recipient_kid` - Recipient's key ID
