"""Serving a warehouse to peers (port of the listening half of esiur-ts ``EpServer``).

::

    warehouse = Warehouse()
    ...
    server = await EpServer.listen(warehouse, port=51018)          # WebSocket, subprotocol "EP"
    tcp = await EpServer.listen(warehouse, port=51019, transport="tcp")
    ...
    await server.close()

Every accepted socket becomes an :class:`EpConnection` that runs the responder handshake and then
answers the peer's requests for the warehouse's resources.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from typing import Any, Literal

from esiur.resource import Warehouse
from esiur.security.authentication import AuthenticationProvider
from esiur.security.encryption import EncryptionProvider

from .configuration import ParserConfiguration
from .connection import EpConnection
from .endpoint import ESIUR_DEFAULT_PORT
from .sockets import EP_SUBPROTOCOL, ISocket, TcpSocket, WebSocketSocket

logger = logging.getLogger("esiur.net")

Transport = Literal["ws", "tcp"]


class EpServer:
    """Accepts EP connections and serves a :class:`~esiur.resource.Warehouse` to them."""

    def __init__(
        self,
        warehouse: Warehouse,
        *,
        allow_unauthorized: bool = True,
        authentication_timeout: float | None = 30.0,
        parser: ParserConfiguration | None = None,
        authentication_provider: AuthenticationProvider | None = None,
        encryption_providers: Iterable[EncryptionProvider] = (),
    ) -> None:
        self.warehouse = warehouse
        if authentication_provider is not None:
            warehouse.register_authentication_provider(authentication_provider)
        for provider in encryption_providers:
            if warehouse.try_get_encryption_provider(provider.default_name) is None:
                warehouse.register_encryption_provider(provider)
        self.allow_unauthorized = allow_unauthorized
        self.authentication_timeout = authentication_timeout
        self.parser = parser or ParserConfiguration()
        #: The live peer connections.
        self.connections: set[EpConnection] = set()
        self._listeners: list[Any] = []
        self._ports: list[int] = []

    @classmethod
    async def listen(
        cls,
        warehouse: Warehouse,
        *,
        host: str = "127.0.0.1",
        port: int = ESIUR_DEFAULT_PORT,
        transport: Transport = "ws",
        allow_unauthorized: bool = True,
        authentication_timeout: float | None = 30.0,
        parser: ParserConfiguration | None = None,
        authentication_provider: AuthenticationProvider | None = None,
        encryption_providers: Iterable[EncryptionProvider] = (),
    ) -> EpServer:
        """Create a server and start listening (``port=0`` picks a free port; see :attr:`port`).

        ``allow_unauthorized=False`` refuses anonymous peers. Peers authenticate with the
        providers registered on the warehouse (``authentication_provider`` registers one) and
        encrypt with its encryption providers (``encryption_providers`` registers them)."""
        server = cls(
            warehouse,
            allow_unauthorized=allow_unauthorized,
            authentication_timeout=authentication_timeout,
            parser=parser,
            authentication_provider=authentication_provider,
            encryption_providers=encryption_providers,
        )
        await server.add_listener(transport, host, port)
        return server

    @property
    def port(self) -> int:
        """The port of the first listener."""
        return self._ports[0]

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(self._ports)

    async def add_listener(
        self, transport: Transport = "ws", host: str = "127.0.0.1", port: int = ESIUR_DEFAULT_PORT
    ) -> int:
        """Listen on one more transport; returns the bound port."""
        if not 0 <= port <= 65535:
            raise ValueError("The port must be from 0 through 65535.")
        if transport == "tcp":
            listener = await asyncio.start_server(self._accept_tcp, host, port)
            bound = listener.sockets[0].getsockname()[1]
        elif transport == "ws":
            bound, listener = await self._listen_websocket(host, port)
        else:
            raise ValueError(f"Unsupported EP transport '{transport}'.")
        self._listeners.append(listener)
        self._ports.append(bound)
        return int(bound)

    async def _listen_websocket(self, host: str, port: int) -> tuple[int, Any]:
        try:
            from websockets.asyncio.server import serve
            from websockets.typing import Subprotocol
        except ImportError:
            raise ImportError(
                "WebSocket transport needs the 'websockets' package: pip install esiur[websockets]"
            ) from None
        listener = await serve(
            self._accept_websocket,
            host,
            port,
            subprotocols=[Subprotocol(EP_SUBPROTOCOL)],
            max_size=self.parser.maximum_encrypted_record_size or None,
        )
        return int(next(iter(listener.sockets)).getsockname()[1]), listener

    # ---- accepting ------------------------------------------------------------------------

    def accept(self, socket: ISocket) -> EpConnection:
        """Serve an already established socket (the listeners call this for what they accept;
        call it directly to serve a transport this class does not listen on)."""
        connection = EpConnection(
            parser=self.parser,
            allow_unauthorized=self.allow_unauthorized,
            authentication_timeout=self.authentication_timeout,
            warehouse=self.warehouse,
        )
        connection.start_responder_handshake()  # wait for the peer's Initialize
        connection.assign(socket)
        self.connections.add(connection)
        connection.on_close.append(self.connections.discard)
        return connection

    async def _accept_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        socket = TcpSocket.from_streams(reader, writer)
        self.accept(socket)
        socket.start()

    async def _accept_websocket(self, ws: Any) -> None:
        if ws.subprotocol != EP_SUBPROTOCOL:
            await ws.close(1002, f"The '{EP_SUBPROTOCOL}' WebSocket subprotocol is required.")
            return
        socket = WebSocketSocket.from_connection(
            ws, maximum_message_size=self.parser.maximum_encrypted_record_size or None
        )
        connection = self.accept(socket)
        socket.start()
        # The WebSocket closes when this handler returns, so hold it open for the session.
        await connection.wait_closed()

    # ---- shutting down --------------------------------------------------------------------

    async def close(self) -> None:
        """Stop listening and close every connection."""
        listeners, self._listeners = self._listeners, []
        for listener in listeners:
            listener.close()
        connections = list(self.connections)
        for connection in connections:
            connection.close()
        for connection in connections:
            await connection.wait_closed()
        for listener in listeners:
            await listener.wait_closed()
        self._ports.clear()

    async def __aenter__(self) -> EpServer:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
