import asyncio
import dataclasses
from typing import Any

import pytest
from memory_socket import MemorySocket

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.data import ParsedTdu, TypeRegistry, compose
from esiur.net import EpConnection, ParserConfiguration
from esiur.net.packets import (
    EpAuthPacket,
    EpAuthPacketHeader,
    EpAuthPacketMethod,
    EpPacket,
    EpPacketNotification,
    EpPacketReply,
    EpPacketRequest,
)
from esiur.security import AuthenticationMode, EncryptionMode


async def handshake(
    chunk: int | None = None,
    *,
    client: EpConnection | None = None,
    server: EpConnection | None = None,
) -> tuple[EpConnection, EpConnection]:
    """A client and a server connected in memory, with the handshake done."""
    client = client or EpConnection()
    server = server or EpConnection()
    a, b = MemorySocket.pair(chunk)
    server.start_responder_handshake()
    server.assign(b)
    client.start_initiator_handshake("example.test")
    client.assign(a)
    await client.when_ready()
    return client, server


def echo_server(server: EpConnection) -> None:
    def handle(conn: EpConnection, action: int, callback_id: int, tdu: ParsedTdu | None) -> None:
        conn.send_reply(EpPacketReply.COMPLETED, callback_id, conn.decode(tdu))

    server.on_request = handle


# ------------------------------------------------------------------------------- handshake --


async def test_the_handshake_exchanges_domain_and_limits() -> None:
    client, server = await handshake()
    assert client.is_authenticated and server.is_authenticated
    assert server.remote_headers[EpAuthPacketHeader.DOMAIN] == "example.test"
    assert server.remote_limit(EpAuthPacketHeader.MAXIMUM_PACKET_SIZE) == 8 * 1024 * 1024
    assert client.remote_limit(EpAuthPacketHeader.MAXIMUM_COLLECTION_ITEMS) == 65_536
    assert client.remote_limit(EpAuthPacketHeader.CIPHER_TYPE) == 0  # not advertised


async def test_the_handshake_survives_a_byte_at_a_time_transport() -> None:
    client, server = await handshake(chunk=1)
    echo_server(server)
    assert await client.send_request(EpPacketRequest.QUERY, "slow") == "slow"


async def test_a_server_that_forbids_anonymous_peers_refuses_the_client() -> None:
    client = EpConnection()
    server = EpConnection(allow_unauthorized=False)
    with pytest.raises(AsyncException, match="Unauthorized access not allowed") as refused:
        await handshake(client=client, server=server)
    assert refused.value.code == ExceptionCode.ACCESS_DENIED
    await asyncio.wait_for(client.wait_closed(), 1)
    await asyncio.wait_for(server.wait_closed(), 1)


class _Wire:
    """A peer that is a test script rather than a connection."""

    def __init__(self) -> None:
        self.received = bytearray()
        self.closed = False
        self.socket, self.far = MemorySocket.pair()
        self.far.receiver = self

    def network_connect(self, sender: Any) -> None: ...

    def network_receive(self, sender: Any, data: bytes) -> None:
        self.received += data

    def network_close(self, sender: Any) -> None:
        self.closed = True

    def send(self, data: bytes) -> None:
        self.far.send(data)

    def packets(self) -> list[EpAuthPacket]:
        packets, offset, data = [], 0, bytes(self.received)
        while offset < len(data):
            packet = EpAuthPacket()
            used = packet.parse(data, offset)
            if used < 0:
                break
            packets.append(packet)
            offset += used
        return packets


async def settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


@pytest.mark.parametrize(
    ("auth_mode", "encryption_mode", "expected"),
    [
        (AuthenticationMode.INITIALIZER_IDENTITY, EncryptionMode.NONE, EpAuthPacketMethod.NOT_SUPPORTED),
        (AuthenticationMode.DUAL_IDENTITY, EncryptionMode.NONE, EpAuthPacketMethod.NOT_SUPPORTED),
        (
            AuthenticationMode.INITIALIZER_IDENTITY,
            EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
            EpAuthPacketMethod.ERROR_MUST_ENCRYPT,
        ),
        (AuthenticationMode.NONE, EncryptionMode.ENCRYPT_WITH_SESSION_KEY, EpAuthPacketMethod.ERROR_MUST_ENCRYPT),
    ],
)
async def test_a_server_refuses_what_this_version_cannot_do(
    auth_mode: int, encryption_mode: int, expected: int
) -> None:
    server = EpConnection()
    wire = _Wire()
    server.start_responder_handshake()
    server.assign(wire.socket)
    wire.send(EpAuthPacket.compose_initialize(auth_mode, encryption_mode))
    await settle()
    assert [p.method for p in wire.packets()] == [expected]
    await asyncio.wait_for(server.wait_closed(), 1)
    await settle()
    assert wire.closed and not server.is_authenticated


async def test_a_stalled_handshake_times_out() -> None:
    server = EpConnection(authentication_timeout=0.05)
    wire = _Wire()
    server.start_responder_handshake()
    server.assign(wire.socket)  # the peer never sends Initialize
    await asyncio.wait_for(server.wait_closed(), 1)
    await settle()
    assert wire.closed

    client = EpConnection(authentication_timeout=0.05)
    silent = _Wire()
    client.start_initiator_handshake("x")
    client.assign(silent.socket)
    with pytest.raises(AsyncException) as stalled:
        await client.when_ready()
    assert stalled.value.code == ExceptionCode.TIMEOUT


async def test_the_server_reports_an_error_the_client_understands() -> None:
    client = EpConnection()
    wire = _Wire()
    client.start_initiator_handshake("x")
    client.assign(wire.socket)
    await settle()
    wire.send(EpAuthPacket.compose_method(EpAuthPacketMethod.ERROR_TERMINATE, compose("go away")))
    with pytest.raises(AsyncException, match="go away"):
        await client.when_ready()


async def test_an_unexpected_handshake_step_fails_the_handshake() -> None:
    client = EpConnection()
    wire = _Wire()
    client.start_initiator_handshake("x")
    client.assign(wire.socket)
    await settle()
    wire.send(EpAuthPacket.compose_method(EpAuthPacketMethod.HANDSHAKE, compose(b"data")))
    with pytest.raises(AsyncException, match="not initialized"):
        await client.when_ready()
    await settle()
    assert EpAuthPacketMethod.ERROR_TERMINATE in [p.method for p in wire.packets()]


async def test_a_packet_may_follow_the_handshake_in_the_same_chunk() -> None:
    client = EpConnection()
    seen: list[Any] = []
    client.on_notification = lambda conn, action, tdu: seen.append((action, conn.decode(tdu)))
    wire = _Wire()
    client.start_initiator_handshake("x")
    client.assign(wire.socket)
    await settle()
    wire.send(
        EpAuthPacket.compose_method(EpAuthPacketMethod.SESSION_ESTABLISHED)
        + EpPacket.compose_notification(EpPacketNotification.RESOURCE_MOVED, compose("hi"))
    )
    await client.when_ready()
    await settle()
    assert seen == [(EpPacketNotification.RESOURCE_MOVED, "hi")]


# --------------------------------------------------------------------- requests and replies --


async def test_a_request_gets_its_reply() -> None:
    client, server = await handshake()
    echo_server(server)
    assert await client.send_request(EpPacketRequest.QUERY, {"a": [1, 2]}) == {"a": [1, 2]}
    assert await client.send_request(EpPacketRequest.QUERY) is None


async def test_several_arguments_travel_as_a_list() -> None:
    client, server = await handshake()
    echo_server(server)
    assert await client.send_request(EpPacketRequest.INVOKE_FUNCTION, 1, "two", None) == [
        1,
        "two",
        None,
    ]


async def test_replies_are_matched_by_callback_id_in_any_order() -> None:
    client, server = await handshake()
    held: list[tuple[int, Any]] = []
    server.on_request = lambda conn, action, cb, tdu: held.append((cb, conn.decode(tdu)))
    first = client.send_request(EpPacketRequest.QUERY, "first")
    second = client.send_request(EpPacketRequest.QUERY, "second")
    await settle()
    assert [value for _, value in held] == ["first", "second"]
    server.send_reply(EpPacketReply.COMPLETED, held[1][0], "answer 2")
    server.send_reply(EpPacketReply.COMPLETED, held[0][0], "answer 1")
    assert await asyncio.gather(first, second) == ["answer 1", "answer 2"]


async def test_error_replies_raise_with_their_category_and_code() -> None:
    client, server = await handshake()

    def handle(conn: EpConnection, action: int, cb: int, tdu: ParsedTdu | None) -> None:
        if conn.decode(tdu) == "denied":
            conn.send_error(ErrorType.MANAGEMENT, cb, ExceptionCode.ACCESS_DENIED, "no")
        elif conn.decode(tdu) == "failed":
            conn.send_error(ErrorType.EXCEPTION, cb, 9999, "boom")
        else:
            conn.send_reply(EpPacketReply.EXECUTION_ERROR, cb)  # no arguments at all

    server.on_request = handle
    with pytest.raises(AsyncException) as denied:
        await client.send_request(EpPacketRequest.QUERY, "denied")
    assert (denied.value.type, denied.value.code) == (ErrorType.MANAGEMENT, ExceptionCode.ACCESS_DENIED)
    assert denied.value.message == "no" and str(denied.value) == "ACCESS_DENIED: no"
    with pytest.raises(AsyncException) as failed:
        await client.send_request(EpPacketRequest.QUERY, "failed")
    assert (failed.value.type, failed.value.code, failed.value.message) == (
        ErrorType.EXCEPTION,
        9999,
        "boom",
    )
    with pytest.raises(AsyncException) as bare:
        await client.send_request(EpPacketRequest.QUERY, "other")
    assert (bare.value.code, bare.value.message) == (ExceptionCode.RUNTIME_EXCEPTION, "")


async def test_progress_warnings_and_chunks_reach_the_callbacks_before_the_result() -> None:
    client, server = await handshake()

    def handle(conn: EpConnection, action: int, cb: int, tdu: ParsedTdu | None) -> None:
        conn.send_progress(cb, 1, 4)
        conn.send_error(ErrorType.WARNING, cb, ExceptionCode.NOT_ALLOWED, "careful")
        conn.send_reply(EpPacketReply.STREAM, cb)
        conn.send_reply(EpPacketReply.CHUNK, cb, "part 1")
        conn.send_reply(EpPacketReply.PROPAGATED, cb, {"node": 7})
        conn.send_reply(EpPacketReply.CHUNK, cb, "part 2")
        conn.send_progress(cb, 4, 4)
        conn.send_reply(EpPacketReply.COMPLETED, cb, "done")

    server.on_request = handle
    events: list[Any] = []
    result = await client.send_request(
        EpPacketRequest.INVOKE_FUNCTION,
        on_progress=lambda value, maximum: events.append(("progress", value, maximum)),
        on_warning=lambda code, message: events.append(("warning", code, message)),
        on_chunk=lambda chunk: events.append(("chunk", chunk)),
        on_propagated=lambda value: events.append(("propagated", value)),
    )
    assert result == "done"
    assert events == [
        ("progress", 1, 4),
        ("warning", ExceptionCode.NOT_ALLOWED, "careful"),
        ("chunk", "part 1"),
        ("propagated", {"node": 7}),
        ("chunk", "part 2"),
        ("progress", 4, 4),
    ]


async def test_a_failing_callback_does_not_stop_the_connection() -> None:
    client, server = await handshake()

    def handle(conn: EpConnection, action: int, cb: int, tdu: ParsedTdu | None) -> None:
        conn.send_progress(cb, 1, 2)
        conn.send_reply(EpPacketReply.COMPLETED, cb, "fine")

    def broken(value: int, maximum: int) -> None:
        raise RuntimeError("callback bug")

    server.on_request = handle
    assert await client.send_request(EpPacketRequest.QUERY, on_progress=broken) == "fine"


async def test_a_request_nobody_handles_is_answered_with_an_error() -> None:
    client, _ = await handshake()
    with pytest.raises(AsyncException) as unhandled:
        await client.send_request(EpPacketRequest.KEEP_ALIVE)
    assert unhandled.value.code == ExceptionCode.NOT_IMPLEMENTED


async def test_async_handlers_may_answer_later() -> None:
    client, server = await handshake()

    async def handle(conn: EpConnection, action: int, cb: int, tdu: ParsedTdu | None) -> None:
        await asyncio.sleep(0.01)
        conn.send_reply(EpPacketReply.COMPLETED, cb, "late")

    server.on_request = handle
    assert await client.send_request(EpPacketRequest.QUERY) == "late"


async def test_notifications_reach_the_handler() -> None:
    client, server = await handshake()
    seen: list[Any] = []
    client.on_notification = lambda conn, action, tdu: seen.append((action, conn.decode(tdu)))
    server.send_notification(EpPacketNotification.RESOURCE_DESTROYED, [1, "x"])
    server.send_notification(EpPacketNotification.SYSTEM_FAILURE)
    await settle()
    assert seen == [
        (EpPacketNotification.RESOURCE_DESTROYED, [1, "x"]),
        (EpPacketNotification.SYSTEM_FAILURE, None),
    ]


async def test_a_cancelled_request_ignores_its_late_reply() -> None:
    client, server = await handshake()
    held: list[int] = []
    server.on_request = lambda conn, action, cb, tdu: held.append(cb)
    request = client.send_request(EpPacketRequest.QUERY)
    await settle()
    request.cancel()
    await settle()
    server.send_reply(EpPacketReply.COMPLETED, held[0], "too late")
    await settle()
    echo_server(server)
    assert await client.send_request(EpPacketRequest.QUERY, "still works") == "still works"


async def test_callback_ids_wrap_and_skip_ids_in_use() -> None:
    client, server = await handshake()
    held: list[int] = []
    server.on_request = lambda conn, action, cb, tdu: held.append(cb)
    client._callback_counter = 0xFFFF_FFFE
    client.send_request(EpPacketRequest.QUERY)
    client.send_request(EpPacketRequest.QUERY)
    client.send_request(EpPacketRequest.QUERY)
    await settle()
    assert held == [0xFFFF_FFFF, 1, 2]  # 0 is never used


async def test_records_and_enums_use_the_connections_registry() -> None:
    @dataclasses.dataclass
    class Point:
        x: int = 0
        y: int = 0

    def registry() -> TypeRegistry:
        types = TypeRegistry()
        types.register_record(Point)
        return types

    client, server = await handshake(
        client=EpConnection(registry=registry()), server=EpConnection(registry=registry())
    )
    echo_server(server)
    assert await client.send_request(EpPacketRequest.QUERY, Point(3, -4)) == Point(3, -4)


async def test_a_value_the_peer_cannot_accept_is_refused_before_sending() -> None:
    server = EpConnection(parser=ParserConfiguration(maximum_packet_size=100))
    client, server = await handshake(server=server)
    echo_server(server)
    assert client.remote_limit(EpAuthPacketHeader.MAXIMUM_PACKET_SIZE) == 100
    with pytest.raises(AsyncException) as refused:
        await client.send_request(EpPacketRequest.QUERY, b"x" * 1000)
    assert refused.value.code == ExceptionCode.PARSER_LIMIT_EXCEEDED
    assert await client.send_request(EpPacketRequest.QUERY, b"x" * 90) == b"x" * 90


async def test_arguments_that_cannot_be_composed_fail_the_request() -> None:
    client, _ = await handshake()
    with pytest.raises(AsyncException):
        await client.send_request(EpPacketRequest.QUERY, object())


async def test_an_undecodable_reply_fails_only_its_request() -> None:
    client, server = await handshake()
    held: list[int] = []
    server.on_request = lambda conn, action, cb, tdu: held.append(cb)
    first = client.send_request(EpPacketRequest.QUERY)
    await settle()
    # A list whose only element is cut short: well framed, but not a value.
    server.send(EpPacket.compose_reply(EpPacketReply.COMPLETED, held[0], bytes([0x4A, 1, 0x09])))
    with pytest.raises(AsyncException) as undecodable:
        await first
    assert undecodable.value.code == ExceptionCode.PARSE_ERROR
    echo_server(server)
    assert await client.send_request(EpPacketRequest.QUERY, 1) == 1


# ------------------------------------------------------------------------------ closing ----


async def test_closing_fails_every_pending_request() -> None:
    client, server = await handshake()
    server.on_request = lambda *args: None
    pending = [client.send_request(EpPacketRequest.QUERY) for _ in range(3)]
    await settle()
    closed: list[EpConnection] = []
    client.on_close.append(closed.append)
    client.close()
    for request in pending:
        with pytest.raises(AsyncException) as lost:
            await request
        assert lost.value.code == ExceptionCode.HOST_NOT_REACHABLE
    await asyncio.wait_for(server.wait_closed(), 1)
    assert closed == [client] and not client.is_connected


async def test_a_request_on_a_closed_connection_fails_at_once() -> None:
    client, server = await handshake()
    server.close()
    await asyncio.wait_for(client.wait_closed(), 1)
    with pytest.raises(AsyncException) as down:
        await client.send_request(EpPacketRequest.QUERY)
    assert down.value.code == ExceptionCode.HOST_NOT_REACHABLE


async def test_closing_during_the_handshake_fails_it() -> None:
    client = EpConnection()
    wire = _Wire()
    client.start_initiator_handshake("x")
    client.assign(wire.socket)
    await settle()
    wire.far.close()
    with pytest.raises(AsyncException, match="closed during handshake"):
        await client.when_ready()


async def test_malformed_input_closes_the_connection() -> None:
    client, _server = await handshake()
    wire = _Wire()
    broken = EpConnection(parser=ParserConfiguration(maximum_packet_size=1000))
    broken.assign(wire.socket)
    # A value that declares 16 MiB, far beyond this connection's budget.
    wire.send(bytes([0x20, 0x59, 0x01, 0x00, 0x00]))
    await asyncio.wait_for(broken.wait_closed(), 1)
    await settle()
    assert wire.closed
    assert client.is_connected  # unrelated connections are unaffected


async def test_async_with_closes_the_connection() -> None:
    client, server = await handshake()
    async with client:
        pass
    assert not client.is_connected
    await asyncio.wait_for(server.wait_closed(), 1)
