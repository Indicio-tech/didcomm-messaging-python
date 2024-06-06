"""Utilities for DIDComm v1."""

import base58
from didcomm_messaging.multiformats import multibase, multicodec


def v1_kid_to_multikey(kid: str) -> str:
    """Convert a kid to a multikey value."""
    decoded = base58.b58decode(kid)
    if len(decoded) != 32:
        raise ValueError("Invalid kid; does not represent base58 encoded ed25519 pub key")

    return multibase.encode(multicodec.wrap("ed25519-pub", decoded), "base58btc")
