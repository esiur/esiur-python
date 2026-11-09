"""An in-memory socket pair, for testing connections without a network."""

from __future__ import annotations

import asyncio

from esiur.net.sockets import INetworkReceiver, SocketState


class MemorySocket:
    """One end of a pair. Bytes sent on one end arrive on the other on a later loop iteration,
    optionally split into ``chunk``-byte pieces to exercise stream fragmentation."""

    def __init__(self, chunk: int | None = None) -> None:
        self.state = SocketState.ESTABLISHED
        self.receiver: INetworkReceiver | None = None
        self.peer: MemorySocket | None = None
        self.chunk = chunk
        self.sent: list[bytes] = []
        self._close_notified = False

    @classmethod
    def pair(cls, chunk: int | None = None) -> tuple[MemorySocket, MemorySocket]:
        a, b = cls(chunk), cls(chunk)
        a.peer, b.peer = b, a
        return a, b

    async def connect(self, url: str) -> None:  # pragma: no cover - always established
        pass

    def send(self, data: bytes) -> None:
        if self.state != SocketState.ESTABLISHED:
            return
        self.sent.append(data)
        assert self.peer is not None
        size = self.chunk or len(data)
        loop = asyncio.get_running_loop()
        for start in range(0, len(data), size):
            loop.call_soon(self.peer._deliver, data[start : start + size])

    def _deliver(self, data: bytes) -> None:
        if self.state == SocketState.CLOSED or self.receiver is None:
            return
        self.receiver.network_receive(self, data)

    def close(self) -> None:
        if self.state == SocketState.CLOSED:
            return
        self.state = SocketState.CLOSED
        loop = asyncio.get_running_loop()
        loop.call_soon(self._notify_close)
        if self.peer is not None:
            loop.call_soon(self.peer.close)

    def _notify_close(self) -> None:
        if not self._close_notified and self.receiver is not None:
            self._close_notified = True
            self.receiver.network_close(self)
