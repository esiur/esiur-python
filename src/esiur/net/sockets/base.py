"""The transport abstraction (ports of esiur-ts ``ISocket``, ``SocketState`` and
``INetworkReceiver``).

A socket pushes events to its ``receiver`` from the event loop; the receiver sends through
``send``, which never blocks (bytes are queued and written in order).
"""

from __future__ import annotations

import enum
import logging
from typing import Protocol

logger = logging.getLogger("esiur.net")


class SocketState(enum.IntEnum):
    INITIAL = 0
    LISTENING = 1
    CONNECTING = 2
    ESTABLISHED = 3
    CLOSED = 4


class INetworkReceiver(Protocol):
    """Receives the events of a socket."""

    def network_connect(self, sender: ISocket) -> None: ...

    def network_receive(self, sender: ISocket, data: bytes) -> None:
        """Bytes arrived. They are a slice of the stream: packets may span several calls."""

    def network_close(self, sender: ISocket) -> None:
        """The socket closed, from either side. Called exactly once."""


class ISocket(Protocol):
    state: SocketState
    receiver: INetworkReceiver | None

    async def connect(self, url: str) -> None:
        """Connect a client socket; returns once it is established. Raises ``OSError`` or
        ``AsyncException`` when it cannot be."""

    def send(self, data: bytes) -> None:
        """Queue ``data`` for the peer. Bytes are written in the order they were queued."""

    def close(self) -> None:
        """Close the socket. Idempotent; ``receiver.network_close`` follows."""
