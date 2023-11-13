"""MultiBase encoding and decoding utilities."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import ClassVar, Literal, Union


class MultibaseEncoder(ABC):
    """Encoding details."""

    name: ClassVar[str]
    character: ClassVar[str]

    @abstractmethod
    def encode(self, value: bytes) -> str:
        """Encode a byte string using this encoding."""

    @abstractmethod
    def decode(self, value: str) -> bytes:
        """Decode a string using this encoding."""


class Base58BtcEncoder(MultibaseEncoder):
    """Base58BTC encoding."""

    name = "base58btc"
    character = "z"

    def encode(self, value: bytes) -> str:
        """Encode a byte string using the base58btc encoding."""
        import base58

        return base58.b58encode(value).decode()

    def decode(self, value: str) -> bytes:
        """Decode a multibase encoded string."""
        import base58

        return base58.b58decode(value)


class Base64UrlEncoder(MultibaseEncoder):
    """Base64URL encoding."""

    name = "base64url"
    character = "u"

    def encode(self, value: bytes) -> str:
        """Encode a byte string using the base64url encoding."""
        import base64

        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    def decode(self, value: str) -> bytes:
        """Decode a base64url encoded string."""
        import base64

        # Ensure correct padding
        padding_needed = 4 - (len(value) % 4)
        if padding_needed != 4:
            value += "=" * padding_needed

        return base64.urlsafe_b64decode(value)


class Base64Encoder(MultibaseEncoder):
    """Base64URL encoding."""

    name = "base64"
    character = "m"

    def encode(self, value: bytes) -> str:
        """Encode a byte string using the base64 encoding."""
        import base64

        return base64.b64encode(value).decode().rstrip("=")

    def decode(self, value: str) -> bytes:
        """Decode a base64 encoded string."""
        import base64

        # Ensure correct padding
        padding_needed = 4 - (len(value) % 4)
        if padding_needed != 4:
            value += "=" * padding_needed

        return base64.b64decode(value)


class Encoding(Enum):
    """Enum for supported encodings."""

    base58btc = Base58BtcEncoder()
    # Insert additional encodings here

    @classmethod
    def from_name(cls, name: str) -> MultibaseEncoder:
        """Get encoding from name."""
        for encoding in cls:
            if encoding.value.name == name:
                return encoding.value
        raise ValueError(f"Unsupported encoding: {name}")

    @classmethod
    def from_character(cls, character: str) -> MultibaseEncoder:
        """Get encoding from character."""
        for encoding in cls:
            if encoding.value.character == character:
                return encoding.value
        raise ValueError(f"Unsupported encoding: {character}")


EncodingStr = Literal[
    "base58btc",
    # Insert additional encoding names here
]


def encode(value: bytes, encoding: Union[Encoding, EncodingStr]) -> str:
    """Encode a byte string using the given encoding.

    Args:
        value: The byte string to encode
        encoding: The encoding to use

    Returns:
        The encoded string
    """
    if isinstance(encoding, str):
        encoder = Encoding.from_name(encoding)
    elif isinstance(encoding, Encoding):
        encoder = encoding.value
    else:
        raise TypeError("encoding must be an Encoding or EncodingStr")

    return encoder.character + encoder.encode(value)


def decode(value: str) -> bytes:
    """Decode a multibase encoded string.

    Args:
        value: The string to decode

    Returns:
        The decoded byte string
    """
    encoding = value[0]
    encoded = value[1:]
    encoder = Encoding.from_character(encoding)

    return encoder.decode(encoded)
