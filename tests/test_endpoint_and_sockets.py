import asyncio

import pytest

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.net import ESIUR_DEFAULT_PORT, EpConnection, normalize_endpoint
from esiur.net.endpoint import websocket_url
from esiur.net.packets import EpPacketRequest
from esiur.net.sockets import SocketState, TcpSocket

# ---------------------------------------------------------------------------- endpoints ----


def test_a_missing_port_becomes_the_esiur_default() -> None:
    assert ESIUR_DEFAULT_PORT == 51018
    assert normalize_endpoint("ws://127.0.0.1/esiur") == "ws://127.0.0.1:51018/esiur"
    assert normalize_endpoint("ep://[::1]/sys/resource") == "ep://[::1]:51018/sys/resource"
    assert normalize_endpoint("tcp://host") == "tcp://host:51018"
    assert normalize_endpoint("ws://user:pw@host") == "ws://user:pw@host:51018"


def test_an_explicit_port_is_kept() -> None:
    assert normalize_endpoint("ws://127.0.0.1:8080/esiur") == "ws://127.0.0.1:8080/esiur"
    assert normalize_endpoint("wss://host:443") == "wss://host:443"
    assert normalize_endpoint("ws://[::1]:80") == "ws://[::1]:80"


def test_http_endpoints_keep_their_scheme_port() -> None:
    assert normalize_endpoint("https://host/ep") == "https://host/ep"


@pytest.mark.parametrize("bad", ["", "host", "ws://", "ws://host:0", "ws://host:99999", "ws://host:x"])
def test_invalid_endpoints_are_rejected(bad: str) -> None:
    with pytest.raises(ValueError, match="EP endpoint"):
        normalize_endpoint(bad)


def test_ep_schemes_are_websockets() -> None:
    assert websocket_url("ep://h:1/x") == "ws://h:1/x"
    assert websocket_url("eps://h:1/x") == "wss://h:1/x"
    assert websocket_url("tcp://h:1") == "tcp://h:1"


async def test_connecting_to_an_unsupported_scheme_is_an_error() -> None:
    with pytest.raises(ValueError, match="Unsupported EP transport"):
        await EpConnection.connect("ftp://host:21")


# ------------------------------------------------------------------------------ TCP -------


async def serve() -> tuple[asyncio.Server, list[EpConnection], int]:
    connections: list[EpConnection] = []

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        socket = TcpSocket.from_streams(reader, writer)
        server = EpConnection()

        def echo(conn: EpConnection, action: int, callback_id: int, tdu: object) -> None:
            from esiur.net.packets import EpPacketReply

            conn.send_reply(EpPacketReply.COMPLETED, callback_id, conn.decode(tdu))  # type: ignore[arg-type]

        server.on_request = echo
        server.start_responder_handshake()
        server.assign(socket)
        socket.start()
        connections.append(server)

    listener = await asyncio.start_server(accept, "127.0.0.1", 0)
    return listener, connections, listener.sockets[0].getsockname()[1]


async def test_tcp_client_and_server_exchange_requests() -> None:
    listener, connections, port = await serve()
    async with listener, await EpConnection.connect(f"tcp://127.0.0.1:{port}") as client:
        assert client.is_authenticated
        assert await client.send_request(EpPacketRequest.QUERY, [1, "two"]) == [1, "two"]
        big = bytes(range(256)) * 2000  # larger than one TCP read
        assert await client.send_request(EpPacketRequest.QUERY, big) == big
        assert connections[0].remote_headers[1] == "127.0.0.1"  # the domain defaults to the host
    await asyncio.wait_for(connections[0].wait_closed(), 2)


async def test_tcp_connect_failure_is_reported() -> None:
    listener = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    listener.close()
    await listener.wait_closed()
    with pytest.raises(OSError):
        await EpConnection.connect(f"tcp://127.0.0.1:{port}", connect_timeout=2)


async def test_a_server_that_hangs_up_during_the_handshake_fails_connect() -> None:
    async def hang_up(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    listener = await asyncio.start_server(hang_up, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    async with listener:
        with pytest.raises(AsyncException) as failed:
            await EpConnection.connect(f"tcp://127.0.0.1:{port}")
    assert failed.value.type == ErrorType.MANAGEMENT
    assert failed.value.code == ExceptionCode.HOST_NOT_REACHABLE


def test_tcp_urls_are_validated() -> None:
    with pytest.raises(ValueError, match="Invalid TCP URL"):
        asyncio.run(TcpSocket().connect("tcp://host-without-port"))
    with pytest.raises(ValueError, match="Invalid TCP URL"):
        asyncio.run(TcpSocket().connect("ws://host:1"))


async def test_closing_a_socket_that_never_connected_still_reports_it() -> None:
    socket = TcpSocket()
    closed: list[object] = []

    class Receiver:
        def network_connect(self, sender: object) -> None: ...
        def network_receive(self, sender: object, data: bytes) -> None: ...
        def network_close(self, sender: object) -> None:
            closed.append(sender)

    socket.receiver = Receiver()
    socket.close()
    socket.close()  # idempotent
    assert closed == [socket] and socket.state == SocketState.CLOSED
