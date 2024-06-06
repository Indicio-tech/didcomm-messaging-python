"""JSON Web Encryption utilities."""

import binascii
from dataclasses import dataclass, field
import json
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from didcomm_messaging.multiformats.multibase import Base64UrlEncoder

IDENT_ENC_KEY = "encrypted_key"
IDENT_HEADER = "header"
IDENT_PROTECTED = "protected"
IDENT_RECIPIENTS = "recipients"


_base64url = Base64UrlEncoder()


def b64url(value: Union[bytes, str]) -> str:
    """Encode a string or bytes value as unpadded base64-URL."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _base64url.encode(value)


def from_b64url(value: str) -> bytes:
    """Decode an unpadded base64-URL value."""
    try:
        return _base64url.decode(value)
    except binascii.Error:
        raise ValueError("Error decoding base64 value")


class JweRecipient:
    """A single message recipient."""

    def __init__(self, *, encrypted_key: bytes, header: Optional[dict] = None):
        """Initialize the JWE recipient."""
        self.encrypted_key = encrypted_key
        self.header = header or {}

    @classmethod
    def deserialize(cls, entry: Mapping[str, Any]) -> "JweRecipient":
        """Deserialize a JWE recipient from a mapping."""
        if "encrypted_key" not in entry:
            raise ValueError("Invalid JWE recipient: missing encrypted_key")

        encrypyted_key = from_b64url(entry["encrypted_key"])

        if "header" in entry:
            if not isinstance(entry["header"], dict):
                raise ValueError("Invalid JWE recipient: invalid header")
            return cls(encrypted_key=encrypyted_key, header=entry["header"])

        return cls(encrypted_key=encrypyted_key)

    def serialize(self) -> dict:
        """Serialize the JWE recipient to a mapping."""
        ret: OrderedDict[str, Any] = OrderedDict(
            [("encrypted_key", b64url(self.encrypted_key))]
        )
        if self.header:
            ret["header"] = self.header
        return ret


class JweBuilder:
    """Builder for JWE envelopes."""

    def __init__(
        self,
        with_protected_recipients: bool = False,
        with_flatten_recipients: bool = True,
    ):
        """Initialize the JWE builder."""
        self._with_protected_recipients = with_protected_recipients
        self._with_flatten_recipients = with_flatten_recipients
        self._recipients: List[JweRecipient] = []
        self._protected: Optional[OrderedDict] = None
        self._unprotected: Optional[OrderedDict] = None
        self._protected_b64: Optional[bytes] = None
        self._ciphertext: Optional[bytes] = None
        self._iv: Optional[bytes] = None
        self._tag: Optional[bytes] = None
        self._aad: Optional[bytes] = None

    def add_recipient(self, recip: JweRecipient):
        """Add a recipient to the JWE envelope."""
        self._recipients.append(recip)

    @property
    def recipients_json(self) -> List[Dict[str, Any]]:
        """Encode the current recipients for JSON."""
        return [recip.serialize() for recip in self._recipients]

    @property
    def protected_bytes(self) -> bytes:
        """Access the protected data encoded as bytes."""
        assert self._protected_b64
        return self._protected_b64

    def set_protected(
        self,
        protected: Mapping[str, Any],
    ):
        """Set the protected headers of the JWE envelope."""
        protected = OrderedDict(protected.items())
        if self._with_protected_recipients:
            recipients = self.recipients_json
            if self._with_flatten_recipients and len(recipients) == 1:
                protected.update(recipients[0])
            elif recipients:
                protected[IDENT_RECIPIENTS] = recipients
            else:
                raise ValueError("Missing message recipients")
        self._protected = protected
        self._protected_b64 = b64url(json.dumps(protected)).encode("utf-8")

    def set_unprotected(self, unprotected: OrderedDict):
        """Set the unprotected headers of the JWE envelope."""
        self._unprotected = unprotected

    def set_payload(
        self, ciphertext: bytes, iv: bytes, tag: bytes, aad: Optional[bytes] = None
    ):
        """Set the payload of the JWE envelope."""
        self._ciphertext = ciphertext
        self._iv = iv
        self._tag = tag
        self._aad = aad

    def build(self):
        """Build the JWE envelope."""
        if not self._ciphertext:
            raise ValueError("Missing payload for JWE")

        if not self._iv:
            raise ValueError("Missing iv (nonce) for JWE")

        if not self._tag:
            raise ValueError("Missing tag for JWE")

        if not self._recipients:
            raise ValueError("Missing recipients for JWE")

        if not self._protected:
            raise ValueError("Missing protected headers for JWE")

        if not self._protected_b64:
            raise ValueError("Missing encoded protected headers for JWE")

        return JweEnvelope(
            protected=self._protected,
            protected_b64=self._protected_b64,
            ciphertext=self._ciphertext,
            iv=self._iv,
            tag=self._tag,
            aad=self._aad,
            unprotected=self._unprotected,
            recipients=self._recipients,
            with_flatten_recipients=self._with_flatten_recipients,
            with_protected_recipients=self._with_protected_recipients,
        )


@dataclass
class JweEnvelope:
    """JWE envelope instance."""

    recipients: List[JweRecipient]
    protected: dict
    protected_b64: bytes
    ciphertext: bytes
    iv: bytes
    tag: bytes
    aad: Optional[bytes] = None
    unprotected: Optional[dict] = field(default_factory=OrderedDict)
    with_protected_recipients: bool = False
    with_flatten_recipients: bool = True

    @classmethod
    def from_json(cls, message: Union[bytes, str]) -> "JweEnvelope":
        """Decode a JWE envelope from a JSON string or bytes value."""
        try:
            return cls._deserialize(json.loads(message))
        except json.JSONDecodeError:
            raise ValueError("Invalid JWE: not JSON")

    @classmethod
    def deserialize(cls, message: Mapping[str, Any]) -> "JweEnvelope":  # noqa: C901
        """Deserialize a JWE envelope from a mapping."""
        # Basic validation

        if not isinstance(message, dict):
            raise ValueError("Invalid JWE: not a mapping")

        # Validate protected
        if "protected" not in message:
            raise ValueError("Invalid JWE: missing protected header")

        if not isinstance(message["protected"], str):
            raise ValueError("Invalid JWE: invalid protected header")

        # validate unprotected
        if "unprotected" in message and not isinstance(message["unprotected"], dict):
            raise ValueError("Invalid JWE: invalid unprotected header")

        # validate recipients
        if "recipients" in message:
            if not isinstance(message["recipients"], list):
                raise ValueError("Invalid JWE: invalid recipients")
            for recip in message["recipients"]:
                if not isinstance(recip, dict):
                    raise ValueError("Invalid JWE: invalid recipient")

        # validate ciphertext
        if "ciphertext" not in message:
            raise ValueError("Invalid JWE: missing ciphertext")

        if not isinstance(message["ciphertext"], str):
            raise ValueError("Invalid JWE: invalid ciphertext")

        # validate iv
        if "iv" not in message:
            raise ValueError("Invalid JWE: missing iv")

        if not isinstance(message["iv"], str):
            raise ValueError("Invalid JWE: invalid iv")

        # validate tag
        if "tag" not in message:
            raise ValueError("Invalid JWE: missing tag")

        if not isinstance(message["tag"], str):
            raise ValueError("Invalid JWE: invalid tag")

        # validate aad
        if "aad" in message and not isinstance(message["aad"], str):
            raise ValueError("Invalid JWE: invalid aad")

        # validate header
        if "header" in message:
            if not isinstance(message["header"], dict):
                raise ValueError("Invalid JWE: invalid header")

        # validate encrypted_key
        if "encrypted_key" in message and not isinstance(message["encrypted_key"], str):
            raise ValueError("Invalid JWE: invalid encrypted_key")

        return cls._deserialize(message)

    @classmethod
    def _deserialize(cls, parsed: Mapping[str, Any]) -> "JweEnvelope":  # noqa: C901
        protected_b64 = parsed[IDENT_PROTECTED]
        try:
            protected: dict = json.loads(from_b64url(protected_b64))
        except json.JSONDecodeError:
            raise ValueError("Invalid JWE: invalid JSON for protected headers") from None
        unprotected = parsed.get("unprotected") or {}
        if protected.keys() & unprotected.keys():
            raise ValueError("Invalid JWE: duplicate header")

        encrypted_key = protected.get(IDENT_ENC_KEY) or parsed.get(IDENT_ENC_KEY)
        recipients = None
        protected_recipients = False
        flat_recipients = False

        if IDENT_RECIPIENTS in protected:
            recipients = protected.pop(IDENT_RECIPIENTS)
            if IDENT_RECIPIENTS in parsed:
                raise ValueError("Invalid JWE: duplicate recipients block")
            protected_recipients = True
        elif IDENT_RECIPIENTS in parsed:
            recipients = parsed[IDENT_RECIPIENTS]

        if IDENT_ENC_KEY in protected:
            encrypted_key = from_b64url(protected.pop(IDENT_ENC_KEY))
            header = protected.pop(IDENT_HEADER) if IDENT_HEADER in protected else None
            protected_recipients = True
        elif IDENT_ENC_KEY in parsed:
            encrypted_key = parsed[IDENT_ENC_KEY]
            header = parsed.get(IDENT_HEADER)
        else:
            header = None

        if recipients:
            if encrypted_key:
                raise ValueError("Invalid JWE: flattened form with 'recipients'")
            recipients = [JweRecipient.deserialize(recip) for recip in recipients]
        elif encrypted_key:
            recipients = [
                JweRecipient(
                    encrypted_key=encrypted_key,
                    header=header,
                )
            ]
            flat_recipients = True
        else:
            raise ValueError("Invalid JWE: no recipients")

        all_h = protected.keys() | unprotected.keys()
        for recip in recipients:
            if recip.header and recip.header.keys() & all_h:
                raise ValueError("Invalid JWE: duplicate header")

        ciphertext = from_b64url(parsed["ciphertext"])
        iv = from_b64url(parsed["iv"])
        tag = from_b64url(parsed["tag"])
        aad = from_b64url(parsed["aad"]) if "aad" in parsed else None

        inst = cls(
            recipients=recipients,
            protected=protected,
            protected_b64=protected_b64.encode(),
            unprotected=unprotected,
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            aad=aad,
            with_protected_recipients=protected_recipients,
            with_flatten_recipients=flat_recipients,
        )

        return inst

    def serialize(self) -> dict:  # noqa: C901
        """Serialize the JWE envelope to a mapping."""
        if self.protected_b64 is None:
            raise ValueError("Missing protected: use set_protected")
        if self.ciphertext is None:
            raise ValueError("Missing ciphertext for JWE")
        if self.iv is None:
            raise ValueError("Missing iv (nonce) for JWE")
        if self.tag is None:
            raise ValueError("Missing tag for JWE")
        env = OrderedDict()
        env["protected"] = self.protected_b64.decode("utf-8")
        if self.unprotected:
            env["unprotected"] = self.unprotected.copy()
        if not self.with_protected_recipients:
            recipients = self.recipients_json
            if self.with_flatten_recipients and len(recipients) == 1:
                for k in recipients[0]:
                    env[k] = recipients[0][k]
            elif recipients:
                env[IDENT_RECIPIENTS] = recipients
            else:
                raise ValueError("Missing message recipients")
        env["iv"] = b64url(self.iv)
        env["ciphertext"] = b64url(self.ciphertext)
        env["tag"] = b64url(self.tag)
        if self.aad:
            env["aad"] = b64url(self.aad)
        return env

    def to_json(self) -> str:
        """Serialize the JWE envelope to a JSON string."""
        return json.dumps(self.serialize())

    def get_recipients(self) -> Iterable[JweRecipient]:
        """Accessor for an iterator over the JWE recipients.

        The headers for each recipient include protected and unprotected headers from the
        outer envelope.
        """
        header = self.protected.copy()
        header.update(self.unprotected or {})
        for recip in self.recipients:
            if recip.header:
                recip_h = header.copy()
                recip_h.update(recip.header)
                yield JweRecipient(encrypted_key=recip.encrypted_key, header=recip_h)
            else:
                yield JweRecipient(encrypted_key=recip.encrypted_key, header=header)

    @property
    def recipients_json(self) -> List[Dict[str, Any]]:
        """Encode the current recipients for JSON."""
        return [recip.serialize() for recip in self.recipients]

    @property
    def recipient_key_ids(self) -> Iterable[str]:
        """Accessor for an iterator over the JWE recipient key identifiers."""
        for recip in self.recipients:
            if recip.header and "kid" in recip.header:
                yield recip.header["kid"]

    def get_recipient(self, kid: str) -> JweRecipient:
        """Find a recipient by key ID."""
        for recip in self.recipients:
            if recip.header and recip.header.get("kid") == kid:
                header = self.protected.copy()
                header.update(self.unprotected or {})
                header.update(recip.header)
                return JweRecipient(encrypted_key=recip.encrypted_key, header=header)
        raise ValueError(f"Unknown recipient: {kid}")

    @property
    def combined_aad(self) -> bytes:
        """Accessor for the additional authenticated data."""
        aad = self.protected_b64
        if self.aad:
            aad += b"." + b64url(self.aad).encode("utf-8")
        return aad

    @property
    def apu_bytes(self) -> bytes:
        """Accessor for the Agreement PartyUInfo."""
        if "apu" in self.protected:
            return from_b64url(self.protected["apu"])
        raise ValueError("Missing apu")

    @property
    def apv_bytes(self) -> bytes:
        """Accessor for the Agreement PartyVInfo."""
        if "apv" in self.protected:
            return from_b64url(self.protected["apv"])
        raise ValueError("Missing apv")
