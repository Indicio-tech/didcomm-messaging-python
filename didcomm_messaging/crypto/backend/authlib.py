"""Authlib implementation of DIDComm crypto."""

import hashlib
import json
from typing import Mapping, Optional, Sequence, Tuple, Union

from pydid import VerificationMethod

from didcomm_messaging.crypto.base import (
    CryptoService,
    CryptoServiceError,
    PublicKey,
    SecretKey,
)
from didcomm_messaging.multiformats import multibase, multicodec
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder


try:
    from authlib.jose import JsonWebEncryption, JsonWebKey
    from authlib.jose.rfc7517 import AsymmetricKey
    from authlib.jose.drafts import register_jwe_draft

    register_jwe_draft(JsonWebEncryption)
except ImportError:
    raise ImportError("Authlib backend requires the 'authlib' extra to be installed")

b64url = Base64UrlEncoder()


class AuthlibKey(PublicKey):
    """Authlib implementation of DIDComm PublicKey."""

    kty_crv_to_codec: Mapping[Tuple[str, Optional[str]], str] = {
        ("OKP", "Ed25519"): "ed25519-pub",
        ("OKP", "X25519"): "x25519-pub",
    }
    codec_to_kty_crv: Mapping[str, Tuple[str, str]] = {
        "ed25519-pub": ("OKP", "Ed25519"),
        "x25519-pub": ("OKP", "X25519"),
    }

    def __init__(self, key: AsymmetricKey, kid: str):
        """Initialize the AuthlibKey."""
        self.key = key
        self._kid = kid
        self._multikey = self.key_to_multikey(key)

    @property
    def kid(self) -> str:
        """Return the key ID."""
        return self._kid

    @property
    def multikey(self) -> str:
        """Return the key in multikey format."""
        return self._multikey

    @classmethod
    def key_to_multikey(cls, key: AsymmetricKey) -> str:
        """Convert an Authlib key to a multikey."""
        jwk = key.as_dict(is_private=False)
        codec = cls.kty_crv_to_codec.get((jwk["kty"], jwk.get("crv")))

        if not codec:
            raise ValueError("Unsupported key type")

        key_bytes = b64url.decode(jwk["x"])
        return multibase.encode(
            multicodec.wrap(multicodec.multicodec(codec), key_bytes), "base58btc"
        )

    @classmethod
    def multikey_to_key(cls, multikey: str) -> AsymmetricKey:
        """Convert a multikey to an Authlib key."""
        decoded = multibase.decode(multikey)
        codec, key = multicodec.unwrap(decoded)
        try:
            kty, crv = cls.codec_to_kty_crv[codec.name]
        except KeyError:
            raise ValueError(f"Unsupported key type: {codec.name}")

        jwk = {"kty": kty, "crv": crv, "x": b64url.encode(key)}

        try:
            return JsonWebKey.import_key(jwk)
        except Exception as err:
            raise ValueError("Invalid key") from err

    @classmethod
    def from_verification_method(cls, vm: VerificationMethod) -> "AuthlibKey":
        """Return a PublicKey from a verification method."""
        # TODO Reduce code duplication between this and Askar
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

        codec = cls.type_to_codec.get(vm.type)
        if not codec:
            raise ValueError("Unsupported verification method type: {vm_type}")

        try:
            kty, crv = cls.codec_to_kty_crv[codec]
        except KeyError:
            raise ValueError("Unsupported verification method type")

        key_bytes = cls.key_bytes_from_verification_method(vm)
        jwk = {"kty": kty, "crv": crv, "x": b64url.encode(key_bytes)}

        key = JsonWebKey.import_key(jwk)
        return cls(key, kid)


class AuthlibSecretKey(SecretKey):
    """Authlib implementation of SecretKey."""

    def __init__(self, key: AsymmetricKey, kid: str):
        """Initialize the AuthlibSecretKey."""
        self.key = key
        self._kid = kid

    @property
    def kid(self) -> str:
        """Return the key ID."""
        return self._kid


class AuthlibCryptoService(CryptoService[AuthlibKey, AuthlibSecretKey]):
    """Authlib implementation of CryptoService."""

    @classmethod
    def verification_method_to_public_key(cls, vm: VerificationMethod) -> AuthlibKey:
        """Return a PublicKey from a verification method."""
        return AuthlibKey.from_verification_method(vm)

    def _build_header_ecdh_1pu(
        self, to: Sequence[AuthlibKey], frm: AuthlibSecretKey, alg: str, enc: str
    ):
        skid = frm.kid
        kids = [to_key.kid for to_key in to]

        apu = b64url.encode(skid.encode())
        apv = b64url.encode(hashlib.sha256((".".join(sorted(kids))).encode()).digest())
        protected = {
            "typ": "application/didcomm-encrypted+json",
            "alg": alg,
            "enc": enc,
            "apu": apu,
            "apv": apv,
            "skid": skid,
        }
        recipients = [{"header": {"kid": kid}} for kid in kids]
        return {"protected": protected, "recipients": recipients}

    def _build_header_ecdh_es(self, to: Sequence[AuthlibKey], alg: str, enc: str):
        kids = [to_key.kid for to_key in to]

        apv = b64url.encode(hashlib.sha256((".".join(sorted(kids))).encode()).digest())
        protected = {
            "typ": "application/didcomm-encrypted+json",
            "alg": alg,
            "enc": enc,
            "apv": apv,
        }
        recipients = [{"header": {"kid": kid}} for kid in kids]
        return {"protected": protected, "recipients": recipients}

    async def ecdh_es_encrypt(
        self, to_keys: Sequence[AuthlibKey], message: bytes
    ) -> bytes:
        """Encrypt a message using ECDH-ES."""
        header = self._build_header_ecdh_es(to_keys, "ECDH-ES+A256KW", "XC20P")
        jwe = JsonWebEncryption()
        res = jwe.serialize_json(header, message, [value.key for value in to_keys])
        return json.dumps(res).encode()

    async def ecdh_es_decrypt(
        self, enc_message: Union[str, bytes], recip_key: AuthlibSecretKey
    ) -> bytes:
        """Decrypt a message using ECDH-ES."""
        try:
            jwe = JsonWebEncryption()
            res = jwe.deserialize_json(enc_message, recip_key.key)
        except Exception as err:
            raise CryptoServiceError("Invalid JWE") from err

        return res["payload"]

    async def ecdh_1pu_encrypt(
        self,
        to_keys: Sequence[AuthlibKey],
        sender_key: AuthlibSecretKey,
        message: bytes,
    ) -> bytes:
        """Encrypt a message using ECDH-1PU."""
        header = self._build_header_ecdh_1pu(
            to_keys, sender_key, "ECDH-1PU+A256KW", "A256CBC-HS512"
        )
        jwe = JsonWebEncryption()
        res = jwe.serialize_json(
            header, message, [value.key for value in to_keys], sender_key=sender_key.key
        )
        return json.dumps(res).encode()

    async def ecdh_1pu_decrypt(
        self,
        enc_message: Union[str, bytes],
        recip_key: AuthlibSecretKey,
        sender_key: AuthlibKey,
    ) -> bytes:
        """Decrypt a message using ECDH-1PU."""
        try:
            jwe = JsonWebEncryption()
            res = jwe.deserialize_json(
                enc_message, recip_key.key, sender_key=sender_key.key
            )
        except Exception as err:
            raise CryptoServiceError("Invalid JWE") from err

        return res["payload"]
