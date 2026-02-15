"""Example of using authlib crypto with file-based secrets storage."""

import asyncio
import json
import tempfile
from pathlib import Path

from authlib.jose import OKPKey

from didcomm_messaging.crypto.backend.authlib import (
    AuthlibCryptoService,
    AuthlibSecretKey,
)
from didcomm_messaging.crypto.backend.basic import FileBasedSecretsManager
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import PrefixResolver
from didcomm_messaging.resolver.jwk import JWKResolver

b64 = Base64UrlEncoder()


def create_jwk_did(jwk: dict) -> str:
    """Create a did:jwk from a JWK dict."""
    encoded = b64.encode(json.dumps(jwk).encode())
    return f"did:jwk:{encoded}"


async def main():
    """Run the example."""
    # Create a temporary file for secrets storage
    secrets_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    secrets_path = secrets_file.name
    secrets_file.close()

    # Serializer: Convert AuthlibSecretKey to JWK dict
    def serialize_secret(secret: AuthlibSecretKey) -> dict:
        return secret.key.as_dict(is_private=True)

    # Deserializer: Convert JWK dict back to AuthlibSecretKey
    def deserialize_secret(kid: str, data: dict) -> AuthlibSecretKey:
        key = OKPKey.import_key(data)
        return AuthlibSecretKey(key, kid)

    # Create the file-based secrets manager
    secrets = FileBasedSecretsManager(secrets_path, serialize_secret, deserialize_secret)

    # Generate keys for sender and recipient
    # Using X25519 for both since it supports key agreement (encryption)
    sender_sk = OKPKey.generate_key("X25519", is_private=True)
    recipient_sk = OKPKey.generate_key("X25519", is_private=True)

    # Get JWKs and create DIDs
    # For 1PU (authenticated encryption), we need key agreement keys
    sender_jwk = {**sender_sk.as_dict(), "use": "enc"}
    recipient_jwk = {**recipient_sk.as_dict(), "use": "enc"}

    sender_did = create_jwk_did(sender_jwk)
    recipient_did = create_jwk_did(recipient_jwk)

    # Add keys to secrets manager with proper kids
    sender_secret = AuthlibSecretKey(sender_sk, f"{sender_did}#0")
    recipient_secret = AuthlibSecretKey(recipient_sk, f"{recipient_did}#0")

    await secrets.add_secret(sender_secret)
    await secrets.add_secret(recipient_secret)

    # Set up crypto and resolver
    crypto = AuthlibCryptoService()
    resolver = PrefixResolver({"did:jwk": JWKResolver()})
    packer = PackagingService()

    message = b"Hello, secure world!"

    # Pack the message using authenticated encryption (ECDH-1PU)
    # Requires both sender and recipient to have key agreement keys
    packed = await packer.pack(
        crypto=crypto,
        resolver=resolver,
        secrets=secrets,
        message=message,
        to=[recipient_did],
        frm=sender_did,
    )
    print("Packed message:")
    print(json.dumps(json.loads(packed), indent=2))

    # Flush secrets to file
    await secrets.flush()

    # Show the contents of the secrets file
    print("\nSecrets file contents:")
    with open(secrets_path) as f:
        for line in f:
            print(line.strip())

    # Create a new secrets manager that loads from the file
    # This exercises the deserializer
    print("\n--- Creating new secrets manager from file ---")
    secrets2 = FileBasedSecretsManager(secrets_path, serialize_secret, deserialize_secret)

    # Unpack the message using the newly loaded secrets
    plaintext, metadata = await packer.unpack(
        crypto=crypto,
        resolver=resolver,
        secrets=secrets2,
        enc_message=packed,
    )
    print("\nUnpacked message:")
    print(plaintext)

    # Verify the message matches
    assert plaintext == message
    print("\nSuccess! Round-trip completed with deserialized secrets.")

    # Clean up
    Path(secrets_path).unlink()


if __name__ == "__main__":
    asyncio.run(main())
