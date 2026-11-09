"""Raw TCP transport (port of esiur-ts ``TcpSocket``): what esiur-dotnet's native ``TcpServer``
speaks."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from .base import INetworkReceiver, SocketState, logger

_READ_SIZE = 64 * 1024


class TcpSocket:
    """EP over TCP. ``url`` is ``tcp://host:port``. An already-accepted connection is wrapped
    with :meth:`from_streams`."""

    def __init__(self) -> None:
        self.state = SocketState.INITIAL
        self.receiver: INetworkReceiver | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task[None] | None = None
        self._close_notified = False

    @classmethod
    def from_streams(cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> TcpSocket:
        """Wrap an accepted connection. Call :meth:`start` once its receiver is assigned."""
        socket = cls()
        socket._reader, socket._writer = reader, writer
        socket.state = SocketState.ESTABLISHED
        return socket

    async def connect(self, url: str) -> None:
        host, port = _parse_url(url)
        self.state = SocketState.CONNECTING
        try:
            self._reader, self._writer = await asyncio.open_connection(host, port)
        except BaseException:
            self.state = SocketState.CLOSED
            raise
        if self.state != SocketState.CONNECTING:  # closed while connecting
            self._writer.close()
            raise ConnectionAbortedError(f"The connection to {url} was closed while connecting.")
        self.state = SocketState.ESTABLISHED
        if self.receiver is not None:
            self.receiver.network_connect(self)
        self.start()

    def start(self) -> None:
        """Begin delivering received bytes to the receiver."""
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._read_loop())

    async def _read_loop(self) -> None:
        assert self._reader is not None
        try:
            while data := await self._reader.read(_READ_SIZE):
                if self.receiver is not None:
                    self._deliver(data)
        except OSError:
            pass  # the peer went away
        finally:
            self._closed()

    def _deliver(self, data: bytes) -> None:
        assert self.receiver is not None
        try:
            self.receiver.network_receive(self, data)
        except Exception:
            logger.exception("EP receiver failed")
            self.close()

    def send(self, data: bytes) -> None:
        if self._writer is None or self.state != SocketState.ESTABLISHED:
            return
        self._writer.write(data)

    def close(self) -> None:
        if self.state == SocketState.CLOSED:
            return
        self.state = SocketState.CLOSED
        if self._writer is not None:
            self._writer.close()
        if self._task is None:  # no read loop will report the close
            self._closed()

    def _closed(self) -> None:
        self.state = SocketState.CLOSED
        if self._close_notified:
            return
        self._close_notified = True
        if self._writer is not None:
            self._writer.close()
        if self.receiver is not None:
            self.receiver.network_close(self)


def _parse_url(url: str) -> tuple[str, int]:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError(f"Invalid TCP URL: {url}") from None
    if parts.scheme != "tcp" or not parts.hostname or not port:
        raise ValueError(f"Invalid TCP URL: {url}")
    return parts.hostname, port
