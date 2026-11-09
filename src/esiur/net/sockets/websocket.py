"""WebSocket transport (port of esiur-ts ``WSocket``), on the optional ``websockets`` package.

Install it with ``pip install esiur[websockets]``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from esiur.core import AsyncException, ErrorType, ExceptionCode

from .base import INetworkReceiver, SocketState, logger

#: The subprotocol every EP WebSocket peer must negotiate (esiur-dotnet requires it too).
EP_SUBPROTOCOL = "EP"
_DEFAULT_MAXIMUM_MESSAGE_SIZE = 8 * 1024 * 1024 + 1024


class WebSocketSocket:
    """EP over a WebSocket: each binary message carries part of the byte stream."""

    def __init__(self, *, maximum_message_size: int | None = _DEFAULT_MAXIMUM_MESSAGE_SIZE) -> None:
        self.state = SocketState.INITIAL
        self.receiver: INetworkReceiver | None = None
        self._maximum_message_size = maximum_message_size
        self._ws: Any = None
        self._outbound: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._tasks: list[asyncio.Task[None]] = []
        self._close_notified = False

    @classmethod
    def from_connection(
        cls, ws: Any, *, maximum_message_size: int | None = _DEFAULT_MAXIMUM_MESSAGE_SIZE
    ) -> WebSocketSocket:
        """Wrap a connection a server accepted. Call :meth:`start` once its receiver is
        assigned."""
        socket = cls(maximum_message_size=maximum_message_size)
        socket._ws = ws
        socket.state = SocketState.ESTABLISHED
        return socket

    async def connect(self, url: str) -> None:
        try:
            from websockets.asyncio.client import connect as ws_connect
            from websockets.typing import Subprotocol
        except ImportError:
            raise ImportError(
                "WebSocket transport needs the 'websockets' package: pip install esiur[websockets]"
            ) from None

        self.state = SocketState.CONNECTING
        try:
            ws = await ws_connect(
                url, subprotocols=[Subprotocol(EP_SUBPROTOCOL)], max_size=self._maximum_message_size
            )
        except BaseException:
            self.state = SocketState.CLOSED
            raise
        if ws.subprotocol != EP_SUBPROTOCOL:
            await ws.close()
            self.state = SocketState.CLOSED
            raise AsyncException(
                ErrorType.MANAGEMENT,
                ExceptionCode.HOST_NOT_REACHABLE,
                f"The server did not negotiate the required '{EP_SUBPROTOCOL}' WebSocket "
                f"subprotocol (got {ws.subprotocol!r}).",
            )
        if self.state != SocketState.CONNECTING:  # closed while connecting
            await ws.close()
            raise ConnectionAbortedError(f"The connection to {url} was closed while connecting.")
        self._ws = ws
        self.state = SocketState.ESTABLISHED
        if self.receiver is not None:
            self.receiver.network_connect(self)
        self.start()

    def start(self) -> None:
        """Begin delivering received bytes to the receiver."""
        if not self._tasks:
            loop = asyncio.get_running_loop()
            self._tasks = [
                loop.create_task(self._read_loop()),
                loop.create_task(self._write_loop()),
            ]

    async def _read_loop(self) -> None:
        try:
            async for message in self._ws:
                data = message if isinstance(message, bytes) else message.encode()
                if data and self.receiver is not None:
                    self._deliver(data)
        except Exception:
            logger.debug("EP WebSocket connection dropped", exc_info=True)
        finally:
            self._closed()

    def _deliver(self, data: bytes) -> None:
        assert self.receiver is not None
        try:
            self.receiver.network_receive(self, data)
        except Exception:
            logger.exception("EP receiver failed")
            self.close()

    async def _write_loop(self) -> None:
        try:
            while (data := await self._outbound.get()) is not None:
                await self._ws.send(data)
            await self._ws.close()  # an orderly close, after everything queued was sent
        except Exception:
            logger.debug("EP WebSocket write ended", exc_info=True)
        finally:
            self._closed()

    def send(self, data: bytes) -> None:
        if self.state != SocketState.ESTABLISHED:
            return
        self._outbound.put_nowait(data)

    def close(self) -> None:
        if self.state == SocketState.CLOSED:
            return
        self.state = SocketState.CLOSED
        if not self._tasks:
            self._closed()
            return
        self._outbound.put_nowait(None)  # flush what is queued, then close the socket

    def _closed(self) -> None:
        self.state = SocketState.CLOSED
        if self._close_notified:
            return
        self._close_notified = True
        for task in self._tasks:
            if task is not asyncio.current_task():
                task.cancel()
        if self.receiver is not None:
            self.receiver.network_close(self)
