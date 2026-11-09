"""The pieces of an authentication exchange (port of esiur-ts ``security/Authentication*``).

An :class:`AuthenticationProvider` is registered under the name of its protocol; for every
connection it creates an :class:`AuthenticationHandler`, a small state machine that is fed what
the peer sent and answers with what to send back, until it succeeds (with a session key) or fails.
"""

from __future__ import annotations

import enum
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Any

from esiur.core import ExceptionCode

from .modes import AuthenticationMode, EncryptionMode


class AuthenticationDirection(enum.IntEnum):
    """Which side of the exchange a handler plays."""

    INITIATOR = 0
    RESPONDER = 1


class AuthenticationRuling(enum.IntEnum):
    """What one handler step concluded."""

    FAILED = 0
    IN_PROGRESS = 1
    SUCCEEDED = 2


class AuthenticationMaterialType(enum.IntEnum):
    SECRET = 0
    KEY = 1
    IDENTITY = 2
    DATA = 3


@dataclass(frozen=True, slots=True)
class AuthenticationMaterial:
    type: AuthenticationMaterialType
    value: Any


@dataclass(frozen=True, slots=True)
class AuthenticationContext:
    """What a provider needs to create the handler of one connection."""

    direction: AuthenticationDirection
    mode: AuthenticationMode
    domain: str | None = None
    initiator_identity: str | None = None
    responder_identity: str | None = None
    materials: tuple[AuthenticationMaterial, ...] = ()
    host_name: str | None = None


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    """The outcome of one handler step. ``authentication_data`` is what to send to the peer
    (``None`` for nothing); on success ``session_key`` is the secret both sides derived."""

    ruling: AuthenticationRuling
    authentication_data: Any = None
    local_identity: str | None = None
    remote_identity: str | None = None
    session_key: bytes | None = None
    exception_code: ExceptionCode | None = None
    exception_message: str | None = None


class AuthenticationHandler:
    """The per-connection state machine of an authentication protocol."""

    #: The protocol's name, as announced in the ``AuthenticationProtocol`` header.
    protocol: str = ""

    def process(self, authentication_data: Any) -> AuthenticationResult:
        """Take what the peer sent (``None`` at the start of the initiator's side) and decide
        the next step."""
        raise NotImplementedError


class AuthenticationProvider:
    """Creates the handlers of one authentication protocol and hears about its sessions."""

    #: The protocol's name; peers select a provider by it.
    default_name: str = ""

    def create_handler(self, context: AuthenticationContext) -> AuthenticationHandler | None:
        """A handler for one connection, or ``None`` if ``context`` is not supported."""
        raise NotImplementedError

    def login(self, session: AuthenticationSession) -> bool | Awaitable[bool] | None:
        """A session was authenticated. May be a coroutine function."""
        return None

    def logout(self, session: AuthenticationSession) -> bool | Awaitable[bool] | None:
        """An authenticated session ended."""
        return None


@dataclass(eq=False)
class AuthenticationSession:
    """What is known about an authenticated peer: the object permissions managers receive."""

    authentication_mode: AuthenticationMode = AuthenticationMode.NONE
    local_headers: dict[int, Any] = field(default_factory=dict)
    remote_headers: dict[int, Any] = field(default_factory=dict)
    local_identity: str | None = None
    remote_identity: str | None = None
    #: The secret derived by the authentication protocol, if it derives one.
    key: bytes | None = None
    authenticated: bool = False
    #: Free-form state for providers and managers.
    variables: dict[str, Any] = field(default_factory=dict)
    encryption_mode: EncryptionMode = EncryptionMode.NONE
    #: True once records are actually protected in both directions.
    encryption_active: bool = False
    #: Budgets the peer advertised; 0 means none was advertised.
    remote_maximum_packet_size: int = 0
    remote_maximum_allocation_size: int = 0
    remote_maximum_collection_items: int = 0
    remote_maximum_type_metadata_depth: int = 0
    remote_maximum_encrypted_record_size: int = 0
