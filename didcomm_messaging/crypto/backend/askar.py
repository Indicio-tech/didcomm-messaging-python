"""Askar backend for DIDComm Messaging."""

from collections import OrderedDict
import hashlib
import json
from typing import Optional, Sequence, Union

from pydid import VerificationMethod

from didcomm_messaging.crypto.base import (
    CryptoService,
    CryptoServiceError,
    PublicKey,
    SecretKey,
    SecretsManager,
)
from didcomm_messaging.crypto.jwe import JweBuilder, JweEnvelope, JweRecipient, b64url
from didcomm_messaging.multiformats import multibase, multicodec

try:
    from aries_askar import Key, ecdh, AskarError, KeyAlg, Store
except ImportError:
    raise ImportError("Askar backend requires the 'askar' extra to be installed")


class AskarKey(PublicKey):
    """Public key implementation for Askar."""

    codec_to_alg = {
        "ed25519-pub": KeyAlg.ED25519,
        "x25519-pub": KeyAlg.X25519,
        "secp256k1-pub": KeyAlg.K256,
    }
    alg_to_codec = {v: k for k, v in codec_to_alg.items()}

    type_to_alg = {
        "Ed25519VerificationKey2018": KeyAlg.ED25519,
        "X25519KeyAgreementKey2019": KeyAlg.X25519,
        "Ed25519VerificationKey2020": KeyAlg.ED25519,
        "X25519KeyAgreementKey2020": KeyAlg.X25519,
        "EcdsaSecp256k1VerificationKey2019": KeyAlg.K256,
    }

    def __init__(self, key: Key, kid: str):
        """Initialize a new AskarKey instance."""
        self.key = key
        self._kid = kid
        self._multikey = self.key_to_multikey(key)

    @classmethod
    def key_to_multikey(cls, key: Key) -> str:
        """Get a multikey from an Askar Key instance."""
        codec = cls.alg_to_codec.get(key.algorithm)
        if not codec:
            raise ValueError("Unsupported key type")

        return multibase.encode(
            multicodec.wrap(multicodec.multicodec(codec), key.get_public_bytes()),
            "base58btc",
        )

    @classmethod
    def multikey_to_key(cls, multikey: str) -> Key:
        """Convert a multibase-encoded key to an Askar Key instance."""
        decoded = multibase.decode(multikey)
        codec, key = multicodec.unwrap(decoded)
        alg = cls.codec_to_alg.get(codec.name)
        if not alg:
            raise ValueError("Unsupported key type: {codec.name}")
        try:
            return Key.from_public_bytes(alg, key)
        except AskarError as err:
            raise ValueError("Invalid key") from err

    @classmethod
    def from_verification_method(cls, vm: VerificationMethod) -> "AskarKey":
        """Create a Key instance from a DID Document Verification Method."""
        if not vm.id.did:
            kid = vm.id.as_absolute(vm.controller)
        else:
            kid = vm.id

        if vm.type == "Multikey":
            multikey = vm.public_key_multibase
            if not multikey:
                raise ValueError("Multikey verification method missing key")

            key = cls.multikey_to_key(multikey)
            return cls(key, kid)

        if vm.type == "JsonWebKey2020":
            jwk = vm.public_key_jwk
            if not jwk:
                raise ValueError("JWK verification method missing key")
            try:
                key = Key.from_jwk(jwk)
            except AskarError as err:
                raise ValueError("Invalid JWK") from err
            return cls(key, kid)

        alg = cls.type_to_alg.get(vm.type)
        if not alg:
            raise ValueError("Unsupported verification method type: {vm_type}")

        key_bytes = cls.key_bytes_from_verification_method(vm)
        key = Key.from_public_bytes(alg, key_bytes)
        return cls(key, kid)

    @property
    def kid(self) -> str:
        """Get the key ID."""
        return self._kid

    @property
    def multikey(self) -> str:
        """Get the key in multibase format."""
        return self._multikey


class AskarSecretKey(SecretKey):
    """Secret key implementation for Askar."""

    def __init__(self, key: Key, kid: str):
        """Initialize a new AskarSecretKey instance."""
        self.key = key
        self._kid = kid

    @property
    def kid(self) -> str:
        """Get the key ID."""
        return self._kid

    def as_public_key(self) -> AskarKey:
        """Return AskarKey representation."""
        return AskarKey(self.key, self.kid)


class AskarCryptoService(CryptoService[AskarKey, AskarSecretKey]):
    """CryptoService backend implemented using Askar."""

    async def ecdh_es_encrypt(self, to_keys: Sequence[AskarKey], message: bytes) -> bytes:
        """Encode a message into DIDComm v2 anonymous encryption."""
        builder = JweBuilder(with_flatten_recipients=False)

        alg_id = "ECDH-ES+A256KW"
        enc_id = "XC20P"
        enc_alg = KeyAlg.XC20P
        wrap_alg = KeyAlg.A256KW

        if not to_keys:
            raise ValueError("No message recipients")

        try:
            cek = Key.generate(enc_alg)
        except AskarError:
            raise CryptoServiceError("Error creating content encryption key")

        apv = []
        for recip_key in to_keys:
            apv.append(recip_key.kid)
        apv.sort()
        apv = hashlib.sha256((".".join(apv)).encode()).digest()

        for recip_key in to_keys:
            try:
                epk = Key.generate(recip_key.key.algorithm, ephemeral=True)
            except AskarError:
                raise CryptoServiceError("Error creating ephemeral key")
            enc_key = ecdh.EcdhEs(alg_id, None, apv).sender_wrap_key(  # type: ignore
                wrap_alg, epk, recip_key.key, cek
            )
            builder.add_recipient(
                JweRecipient(
                    encrypted_key=enc_key.ciphertext,
                    header={
                        "kid": recip_key.kid,
                        "epk": json.loads(epk.get_jwk_public()),
                    },
                )
            )

        builder.set_protected(
            OrderedDict(
                [
                    ("typ", "application/didcomm-encrypted+json"),
                    ("alg", alg_id),
                    ("enc", enc_id),
                    ("apv", b64url(apv)),
                ]
            )
        )
        try:
            payload = cek.aead_encrypt(message, aad=builder.protected_bytes)
        except AskarError:
            raise CryptoServiceError("Error encrypting message payload")
        builder.set_payload(payload.ciphertext, payload.nonce, payload.tag)

        return builder.build().to_json().encode("utf-8")

    async def ecdh_es_decrypt(
        self,
        enc_message: Union[str, bytes],
        recip_key: AskarSecretKey,
    ) -> bytes:
        """Decode a message from DIDComm v2 anonymous encryption."""
        if isinstance(enc_message, bytes):
            wrapper = enc_message.decode("utf-8")
        wrapper = JweEnvelope.from_json(enc_message)

        alg_id = wrapper.protected.get("alg")

        if alg_id and alg_id in ("ECDH-ES+A128KW", "ECDH-ES+A256KW"):
            wrap_alg = alg_id[8:]
        else:
            raise CryptoServiceError(
                f"Missing or unsupported ECDH-ES algorithm: {alg_id}"
            )

        recip = wrapper.get_recipient(recip_key.kid)
        if not recip:
            raise CryptoServiceError(f"Recipient header not found: {recip_key.kid}")

        enc_alg = recip.header.get("enc")
        if not enc_alg or enc_alg not in (
            "A128GCM",
            "A256GCM",
            "A128CBC-HS256",
            "A256CBC-HS512",
            "XC20P",
        ):
            raise CryptoServiceError(f"Unsupported ECDH-ES content encryption: {enc_alg}")

        epk_header = recip.header.get("epk")
        if not epk_header:
            raise CryptoServiceError("Missing ephemeral key")

        try:
            epk = Key.from_jwk(epk_header)
        except AskarError:
            raise CryptoServiceError("Error loading ephemeral key")

        try:
            cek = ecdh.EcdhEs(alg_id, None, wrapper.apv_bytes).receiver_unwrap_key(  # type: ignore
                wrap_alg,
                enc_alg,
                epk,
                recip_key.key,
                recip.encrypted_key,
            )
        except AskarError:
            raise CryptoServiceError("Error decrypting content encryption key")

        try:
            plaintext = cek.aead_decrypt(
                wrapper.ciphertext,
                nonce=wrapper.iv,
                tag=wrapper.tag,
                aad=wrapper.combined_aad,
            )
        except AskarError:
            raise CryptoServiceError("Error decrypting message payload")

        return plaintext

    async def ecdh_1pu_encrypt(
        self,
        to_keys: Sequence[AskarKey],
        sender_key: AskarSecretKey,
        message: bytes,
    ) -> bytes:
        """Encode a message into DIDComm v2 authenticated encryption."""
        builder = JweBuilder(with_flatten_recipients=False)

        alg_id = "ECDH-1PU+A256KW"
        enc_id = "A256CBC-HS512"
        enc_alg = KeyAlg.A256CBC_HS512
        wrap_alg = KeyAlg.A256KW
        agree_alg = sender_key.key.algorithm

        if not to_keys:
            raise CryptoServiceError("No message recipients")

        try:
            cek = Key.generate(enc_alg)
        except AskarError:
            raise CryptoServiceError("Error creating content encryption key")

        try:
            epk = Key.generate(agree_alg, ephemeral=True)
        except AskarError:
            raise CryptoServiceError("Error creating ephemeral key")

        apu = sender_key.kid
        apv = []
        for recip_key in to_keys:
            if agree_alg:
                if agree_alg != recip_key.key.algorithm:
                    raise CryptoServiceError("Recipient key types must be consistent")
            else:
                agree_alg = recip_key.key.algorithm
            apv.append(recip_key.kid)
        apv.sort()
        apv = hashlib.sha256((".".join(apv)).encode()).digest()

        builder.set_protected(
            OrderedDict(
                [
                    ("typ", "application/didcomm+encrypted"),
                    ("alg", alg_id),
                    ("enc", enc_id),
                    ("apu", b64url(apu)),
                    ("apv", b64url(apv)),
                    ("epk", json.loads(epk.get_jwk_public())),
                    ("skid", sender_key.kid),
                ]
            )
        )
        try:
            payload = cek.aead_encrypt(message, aad=builder.protected_bytes)
        except AskarError:
            raise CryptoServiceError("Error encrypting message payload")
        builder.set_payload(payload.ciphertext, payload.nonce, payload.tag)

        for recip_key in to_keys:
            enc_key = ecdh.Ecdh1PU(alg_id, apu, apv).sender_wrap_key(
                wrap_alg, epk, sender_key.key, recip_key.key, cek, cc_tag=payload.tag
            )
            builder.add_recipient(
                JweRecipient(
                    encrypted_key=enc_key.ciphertext, header={"kid": recip_key.kid}
                )
            )

        return builder.build().to_json().encode("utf-8")

    async def ecdh_1pu_decrypt(
        self,
        enc_message: Union[str, bytes],
        recip_key: AskarSecretKey,
        sender_key: AskarKey,
    ):
        """Decode a message from DIDComm v2 authenticated encryption."""
        if isinstance(enc_message, bytes):
            wrapper = enc_message.decode("utf-8")
        wrapper = JweEnvelope.from_json(enc_message)

        alg_id = wrapper.protected.get("alg")
        if alg_id and alg_id in ("ECDH-1PU+A128KW", "ECDH-1PU+A256KW"):
            wrap_alg = alg_id[9:]
        else:
            raise CryptoServiceError(f"Unsupported ECDH-1PU algorithm: {alg_id}")

        enc_alg = wrapper.protected.get("enc")
        if not enc_alg or enc_alg not in ("A128CBC-HS256", "A256CBC-HS512"):
            raise CryptoServiceError(
                f"Unsupported ECDH-1PU content encryption: {enc_alg}"
            )

        recip = wrapper.get_recipient(recip_key.kid)
        if not recip:
            raise CryptoServiceError(f"Recipient header not found: {recip_key.kid}")

        epk_header = recip.header.get("epk")
        if not epk_header:
            raise CryptoServiceError("Missing ephemeral key")

        try:
            epk = Key.from_jwk(epk_header)
        except AskarError:
            raise CryptoServiceError("Error loading ephemeral key")

        try:
            cek = ecdh.Ecdh1PU(
                alg_id, wrapper.apu_bytes, wrapper.apv_bytes
            ).receiver_unwrap_key(  # type: ignore
                wrap_alg,
                enc_alg,
                epk,
                sender_key.key,
                recip_key.key,
                recip.encrypted_key,
                cc_tag=wrapper.tag,
            )
        except AskarError as err:
            raise CryptoServiceError("Error decrypting content encryption key") from err

        try:
            plaintext = cek.aead_decrypt(
                wrapper.ciphertext,
                nonce=wrapper.iv,
                tag=wrapper.tag,
                aad=wrapper.combined_aad,
            )
        except AskarError:
            raise CryptoServiceError("Error decrypting message payload")

        return plaintext

    @classmethod
    def verification_method_to_public_key(cls, vm: VerificationMethod) -> AskarKey:
        """Convert a verification method into a public key."""
        return AskarKey.from_verification_method(vm)


class AskarSecretsManager(SecretsManager[AskarSecretKey]):
    """Askar KMS with an Askar Store for secrets management."""

    def __init__(self, store: Store):
        """Initialize a new Askar instance."""
        self.store = store

    async def get_secret_by_kid(self, kid: str) -> Optional[AskarSecretKey]:
        """Fetch a public key by key ID."""
        async with self.store.session() as session:
            key_entry = await session.fetch_key(kid)
            if not key_entry:
                return None

        # cached_property doesn't play nice with pyright
        return AskarSecretKey(key_entry.key, kid)  # type: ignore
