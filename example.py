"""Example of using DIDComm Messaging."""

from aries_askar import Key, KeyAlg
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.crypto.backend.basic import InMemorySecretsManager
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.multiformats import multibase
from didcomm_messaging.multiformats import multicodec
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.resolver import PrefixResolver
from did_peer_2 import KeySpec, generate, json


async def main():
    """An example of using DIDComm Messaging."""
    secrets = InMemorySecretsManager()
    crypto = AskarCryptoService()
    packer = PackagingService(
        PrefixResolver({"did:peer:2": Peer2(), "did:peer:4": Peer4()}), crypto, secrets
    )
    verkey = Key.generate(KeyAlg.ED25519)
    xkey = Key.generate(KeyAlg.X25519)
    did = generate(
        [
            KeySpec.verification(
                multibase.encode(
                    multicodec.wrap("ed25519-pub", verkey.get_public_bytes()),
                    "base58btc",
                )
            ),
            KeySpec.key_agreement(
                multibase.encode(
                    multicodec.wrap("x25519-pub", xkey.get_public_bytes()), "base58btc"
                )
            ),
        ],
        [],
    )
    await secrets.add_secret(AskarSecretKey(verkey, f"{did}#key-1"))
    await secrets.add_secret(AskarSecretKey(xkey, f"{did}#key-2"))
    print(did)
    packed = await packer.pack(b"hello world", [did], did)
    print(json.dumps(json.loads(packed), indent=2))
    unpacked = await packer.unpack(packed)
    print(unpacked)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
