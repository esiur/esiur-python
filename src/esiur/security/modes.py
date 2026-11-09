"""Handshake negotiation modes (ports of esiur-ts ``AuthenticationMode`` / ``EncryptionMode``)."""

from __future__ import annotations

import enum


class AuthenticationMode(enum.IntEnum):
    """Which parties prove identity during the handshake."""

    NONE = 0x0
    INITIALIZER_IDENTITY = 0x1
    RESPONDER_IDENTITY = 0x2
    DUAL_IDENTITY = 0x3


class EncryptionMode(enum.IntEnum):
    """Transport encryption mode."""

    NONE = 0
    ENCRYPT_WITH_SESSION_KEY = 1
    ENCRYPT_WITH_SESSION_KEY_AND_ADDRESS = 2
