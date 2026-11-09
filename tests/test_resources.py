"""Remote resources, against a scripted peer (the real esiur-ts server is in
test_interop_resources.py)."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from typing import Any

import pytest
from memory_socket import MemorySocket

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.data import (
    EventDefFlags,
    EventDefInfo,
    FunctionDefFlags,
    FunctionDefInfo,
    ParsedTdu,
    PropertyDefFlags,
    PropertyDefInfo,
    ResourceId,
    StreamMode,
    TypeDefInfo,
    UInt8,
    compose,
    parse,
    t,
)
from esiur.net import EpConnection, EpResource
from esiur.net.packets import EpPacketNotification, EpPacketReply, EpPacketRequest
from esiur.resource import ResourceCursor, TypeDef

GENERATION = uuid.UUID(int=0x1234)
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

INFO = TypeDefInfo(
    id=7,
    name="Thing",
    properties=[
        PropertyDefInfo(index=0, name="count", value_type=t.i32),
        PropertyDefInfo(index=1, name="friend", value_type=t.resource),
        PropertyDefInfo(
            index=2, name="serial", value_type=t.string, flags=PropertyDefFlags.READ_ONLY
        ),
    ],
    functions=[
        FunctionDefInfo(index=0, name="sayHi", return_type=t.string),
        FunctionDefInfo(index=1, name="Stream", stream_mode=StreamMode.PUSH),
        FunctionDefInfo(index=2, name="build", flags=FunctionDefFlags.STATIC),
    ],
    events=[
        EventDefInfo(index=0, name="ping"),
        EventDefInfo(index=1, name="tick", flags=EventDefFlags.AUTO_DELIVERED),
    ],
)


def values_blob(count: int = 0, friend: Any = None, serial: str = "s-1") -> bytes:
    """The ``(age, date, value)`` triple of each property, as an attach reply carries them."""
    parts = []
    for value in (count, friend, serial):
        parts += [compose(1), compose(EPOCH), compose(value)]
    return b"".join(parts)


class Node:
    """The peer, scripted: a connection whose requests are answered from tables."""

    def __init__(self) -> None:
        self.requests: list[tuple[int, Any]] = []
        self.attach_delay: dict[int, float] = {}
        self.attach_values: dict[int, bytes] = {}
        self.fail_attach: set[int] = set()
        self.typedef_as_raw = True
        self.connection = EpConnection()
        self.connection.on_request = self.handle
        self.client = EpConnection()

    async def start(self) -> EpConnection:
        a, b = MemorySocket.pair()
        self.connection.start_responder_handshake()
        self.connection.assign(b)
        self.client.start_initiator_handshake("x")
        self.client.assign(a)
        await self.client.when_ready()
        return self.client

    def handle(self, conn: EpConnection, action: int, callback_id: int, tdu: ParsedTdu | None) -> None:
        value = conn.decode(tdu)
        self.requests.append((action, value))
        asyncio.get_running_loop().create_task(self.answer(conn, action, callback_id, value))

    async def answer(self, conn: EpConnection, action: int, cb: int, value: Any) -> None:
        if action == EpPacketRequest.ATTACH_RESOURCE:
            await asyncio.sleep(self.attach_delay.get(value, 0))
            if value in self.fail_attach:
                conn.send_error(ErrorType.MANAGEMENT, cb, ExceptionCode.ATTACH_DENIED, "no")
                return
            raw = self.attach_values.get(value, values_blob())
            conn.send_reply(
                EpPacketReply.COMPLETED, cb, 7, GENERATION.bytes, 5, f"sys/{value}", UInt8(0), raw
            )
        elif action in (EpPacketRequest.TYPEDEF_BY_ID, EpPacketRequest.TYPEDEF_BY_RESOURCE_ID):
            conn.send_reply(EpPacketReply.COMPLETED, cb, compose(INFO) if self.typedef_as_raw else INFO)
        elif action == EpPacketRequest.SUBSCRIBE:
            conn.send_reply(EpPacketReply.COMPLETED, cb, GENERATION.bytes, 5)
        else:
            conn.send_reply(EpPacketReply.COMPLETED, cb, value)

    def notify(
        self, action: int, instance: int, revision: int, index: int, value: Any,
        generation: uuid.UUID = GENERATION,
    ) -> None:
        self.connection.send_notification(
            action, instance, generation.bytes, revision, EPOCH, UInt8(index), value
        )

    def sent(self, action: int) -> list[Any]:
        return [value for kind, value in self.requests if kind == action]


async def settle(times: int = 10) -> None:
    for _ in range(times):
        await asyncio.sleep(0)


# ------------------------------------------------------------------ small building blocks --


def test_resource_references_use_the_narrowest_form() -> None:
    assert compose(ResourceId(True, 5)) == bytes([0x0B, 5])
    assert compose(ResourceId(False, 5)) == bytes([0x0C, 5])
    assert compose(ResourceId(True, 300)) == bytes([0x13, 0x2C, 0x01])
    assert compose(ResourceId(False, 70000)) == bytes([0x1C, 0x70, 0x11, 0x01, 0x00])
    for reference in (ResourceId(True, 0), ResourceId(False, 0xFFFF_FFFF)):
        assert parse(compose(reference)) == reference
    with pytest.raises(ValueError, match="32 bits"):
        compose(ResourceId(True, 1 << 32))


def test_a_list_of_resources_is_a_resource_list() -> None:
    wire = compose([ResourceId(False, 1), ResourceId(False, 300)])
    assert wire[0] & 0xC7 == 0x43  # ResourceList
    assert parse(wire) == [ResourceId(False, 1), ResourceId(False, 300)]
    mixed = compose([ResourceId(False, 1), 5])
    assert mixed[0] & 0xC7 == 0x42  # an ordinary list
    assert compose([]) == compose([])


def test_a_composer_decides_what_an_object_stands_for() -> None:
    class Thing:
        pass

    thing = Thing()
    wire = compose([thing, thing], resources=lambda v: ResourceId(True, 9) if v is thing else None)
    assert wire[0] & 0xC7 == 0x43 and parse(wire) == [ResourceId(True, 9)] * 2
    with pytest.raises(TypeError):
        compose(thing)


def test_cursors() -> None:
    assert ResourceCursor.empty().is_empty
    cursor = ResourceCursor.from_wire(GENERATION.bytes, 7)
    assert cursor == ResourceCursor(GENERATION, 7) and not cursor.is_empty
    assert cursor.generation_bytes == GENERATION.bytes and str(cursor).endswith(":7")
    for bad in ((b"short", 1), (GENERATION.bytes, "1"), (GENERATION.bytes, True), (None, 1)):
        with pytest.raises(ValueError):
            ResourceCursor.from_wire(*bad)
    with pytest.raises(ValueError):
        ResourceCursor(GENERATION, -1)


def test_members_are_found_by_name_ignoring_case_and_underscores() -> None:
    typedef = TypeDef(INFO)
    assert typedef.find_function("say_hi") is typedef.function_by_index(0)
    assert typedef.find_function("SayHi") is typedef.function_by_index(0)
    assert typedef.find_property("COUNT") is typedef.property_by_index(0)
    assert typedef.find_event("ping") is typedef.event_by_index(0)
    assert typedef.find_property("missing") is None
    assert typedef.is_read_only(typedef.property_by_index(2)) is True  # type: ignore[arg-type]
    twin = TypeDef(
        TypeDefInfo(
            properties=[PropertyDefInfo(index=0, name="a_b"), PropertyDefInfo(index=1, name="aB")]
        )
    )
    assert twin.find_property("aB") is twin.property_by_index(1)  # exact wins
    with pytest.raises(LookupError, match="more than one"):
        twin.find_property("AB")


# ------------------------------------------------------------------------------- attaching --


async def test_attaching_builds_a_proxy_from_the_reply() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    assert isinstance(thing, EpResource) and thing.typedef.name == "Thing"
    assert (thing.type_id, thing.link, thing.hops) == (7, "sys/1", 0)
    assert thing.cursor == ResourceCursor(GENERATION, 5)
    assert thing.count == 0 and thing.get("serial") == "s-1" and thing.age("count") == 1
    assert thing.modified_at("count") == EPOCH
    assert repr(thing) == "<EpResource Thing #1 'sys/1'>"
    # One attach and one type fetch, however many resources share the type.
    await client.attach(2)
    assert len(node.sent(EpPacketRequest.ATTACH_RESOURCE)) == 2
    assert len(node.sent(EpPacketRequest.TYPEDEF_BY_ID)) == 1


async def test_a_definition_sent_as_a_typedef_tdu_is_accepted_too() -> None:
    node = Node()
    node.typedef_as_raw = False
    client = await node.start()
    assert (await client.attach(1)).typedef.name == "Thing"


async def test_a_peer_that_does_not_serve_the_type_by_id_is_asked_through_the_resource() -> None:
    node = Node()
    client = await node.start()
    original = node.answer

    async def answer(conn: EpConnection, action: int, cb: int, value: Any) -> None:
        if action == EpPacketRequest.TYPEDEF_BY_ID:
            conn.send_error(ErrorType.MANAGEMENT, cb, ExceptionCode.TYPEDEF_NOT_FOUND)
        else:
            await original(conn, action, cb, value)

    node.answer = answer  # type: ignore[method-assign]
    assert (await client.attach(1)).typedef.name == "Thing"
    assert node.sent(EpPacketRequest.TYPEDEF_BY_RESOURCE_ID) == [1]


async def test_a_failed_attach_leaves_nothing_behind() -> None:
    node = Node()
    node.fail_attach.add(1)
    client = await node.start()
    with pytest.raises(AsyncException) as denied:
        await client.attach(1)
    assert denied.value.code == ExceptionCode.ATTACH_DENIED
    node.fail_attach.clear()
    assert (await client.attach(1)).instance_id == 1


async def test_concurrent_attaches_share_one_request_and_one_failure() -> None:
    node = Node()
    node.attach_delay[1] = 0.05
    client = await node.start()
    first, second = await asyncio.gather(client.attach(1), client.attach(1))
    assert first is second and len(node.sent(EpPacketRequest.ATTACH_RESOURCE)) == 1

    node.fail_attach.add(2)
    results = await asyncio.gather(client.attach(2), client.attach(2), return_exceptions=True)
    assert all(isinstance(r, AsyncException) for r in results)


async def test_a_malformed_attach_reply_is_a_parse_error() -> None:
    node = Node()
    client = await node.start()

    async def answer(conn: EpConnection, action: int, cb: int, value: Any) -> None:
        conn.send_reply(EpPacketReply.COMPLETED, cb, "not a description")

    node.answer = answer  # type: ignore[method-assign]
    with pytest.raises(AsyncException) as malformed:
        await client.attach(1)
    assert malformed.value.code == ExceptionCode.PARSE_ERROR


async def test_resources_that_refer_to_each_other_attach_without_waiting_on_themselves() -> None:
    node = Node()
    node.attach_values = {
        1: values_blob(friend=ResourceId(False, 2)),
        2: values_blob(friend=ResourceId(False, 1)),
    }
    client = await node.start()
    one, two = await asyncio.wait_for(asyncio.gather(client.attach(1), client.attach(2)), 2)
    assert one.friend is two and two.friend is one
    node.attach_values = {3: values_blob(friend=ResourceId(False, 3))}
    assert (await asyncio.wait_for(client.attach(3), 2)).friend is not None


async def test_references_to_the_receivers_own_resources_are_left_as_ids() -> None:
    node = Node()
    node.attach_values = {1: values_blob(friend=ResourceId(True, 9))}
    client = await node.start()
    assert (await client.attach(1)).friend == ResourceId(True, 9)


# ------------------------------------------------------------------------------- calling ----


async def test_calls_carry_the_instance_the_member_index_and_the_arguments() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    assert await thing.say_hi("a", 2) == [1, 0, ["a", 2]]
    assert node.sent(EpPacketRequest.INVOKE_FUNCTION)[-1] == [1, 0, ["a", 2]]
    assert await thing.say_hi() == [1, 0, []]


async def test_a_static_function_is_called_on_the_type() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    await thing.build(5)
    assert node.sent(EpPacketRequest.STATIC_CALL) == [[7, 2, [5]]]


async def test_streaming_functions_are_not_supported_yet() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    with pytest.raises(NotImplementedError, match="Streaming"):
        thing.stream()


async def test_resource_valued_results_are_attached() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    other = await thing.say_hi()  # the node echoes its arguments: [id, index, args]
    assert other == [1, 0, []]

    async def answer(conn: EpConnection, action: int, cb: int, value: Any) -> None:
        conn.send_reply(EpPacketReply.COMPLETED, cb, [ResourceId(False, 1), {"x": ResourceId(False, 1)}])

    node.answer = answer  # type: ignore[method-assign]
    result = await thing.say_hi()
    assert result[0] is thing and result[1]["x"] is thing


async def test_writing_a_property_updates_the_cache_once_the_peer_accepts() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    await thing.set("count", 41)
    assert thing.count == 41 and node.sent(EpPacketRequest.SET_PROPERTY) == [[1, 0, 41]]
    with pytest.raises(AsyncException) as read_only:
        await thing.set("serial", "x")
    assert read_only.value.code == ExceptionCode.READ_ONLY_PROPERTY
    assert len(node.sent(EpPacketRequest.SET_PROPERTY)) == 1  # nothing was sent
    with pytest.raises(AttributeError):
        await thing.set("nope", 1)


# ---------------------------------------------------------------------------- notifications --


async def test_property_notifications_update_values_and_call_listeners() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    seen: list[int] = []
    thing.on_property("count", seen.append)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 6, 0, 10)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 7, 0, 11)
    await settle()
    assert thing.count == 11 and seen == [10, 11]
    assert thing.age("count") == 7 and thing.cursor.revision == 7
    thing.off_property("count", seen.append)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 8, 0, 12)
    await settle()
    assert seen == [10, 11] and thing.count == 12


async def test_duplicate_and_out_of_order_notifications_are_dropped() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 9, 0, 90)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 9, 0, 91)  # same revision
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 8, 0, 80)  # older
    await settle()
    assert thing.count == 90
    # A new generation restarts the revisions.
    node.notify(
        EpPacketNotification.PROPERTY_MODIFIED, 1, 1, 0, 5, generation=uuid.UUID(int=99)
    )
    await settle()
    assert thing.count == 5 and thing.cursor.generation == uuid.UUID(int=99)


async def test_notifications_for_unknown_resources_and_members_are_ignored() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 99, 9, 0, 1)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 9, 77, 1)  # no such property
    node.notify(EpPacketNotification.EVENT_OCCURRED, 1, 10, 77, 1)  # no such event
    await settle()
    assert client.is_connected and thing.count == 0


async def test_a_malformed_notification_closes_the_connection() -> None:
    node = Node()
    client = await node.start()
    await client.attach(1)
    node.connection.send_notification(EpPacketNotification.PROPERTY_MODIFIED, "garbage")
    await asyncio.wait_for(client.wait_closed(), 1)


async def test_a_notification_waits_for_the_resources_it_refers_to() -> None:
    node = Node()
    node.attach_delay[2] = 0.1
    client = await node.start()
    thing = await client.attach(1)
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 6, 1, ResourceId(False, 2))
    node.notify(EpPacketNotification.PROPERTY_MODIFIED, 1, 7, 0, 5)  # must not overtake it
    await settle()
    assert thing.count == 0  # still waiting for resource 2
    await asyncio.sleep(0.25)
    assert thing.friend is client._attached[2] and thing.count == 5


async def test_event_subscriptions_are_reference_counted() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    one, two = [], []
    await thing.on_event("ping", one.append)
    await thing.on_event("ping", two.append)
    assert len(node.sent(EpPacketRequest.SUBSCRIBE)) == 1
    assert node.sent(EpPacketRequest.SUBSCRIBE)[0][:2] == [1, 0]
    node.notify(EpPacketNotification.EVENT_OCCURRED, 1, 6, 0, "x")
    await settle()
    assert one == two == ["x"]
    await thing.off_event("ping", one.append)
    assert node.sent(EpPacketRequest.UNSUBSCRIBE) == []
    await thing.off_event("ping", two.append)
    assert node.sent(EpPacketRequest.UNSUBSCRIBE) == [[1, 0]]
    await thing.on_event("ping", one.append)
    assert len(node.sent(EpPacketRequest.SUBSCRIBE)) == 2


async def test_auto_delivered_events_are_never_subscribed() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    heard: list[Any] = []
    await thing.on_event("tick", heard.append)
    node.notify(EpPacketNotification.EVENT_OCCURRED, 1, 6, 1, 1)
    await settle()
    assert heard == [1] and node.sent(EpPacketRequest.SUBSCRIBE) == []
    await thing.off_event("tick", heard.append)
    assert node.sent(EpPacketRequest.UNSUBSCRIBE) == []
    await thing.off_event("nope", heard.append)  # an unknown event is not an error here


async def test_a_refused_subscription_forgets_its_listener() -> None:
    node = Node()
    thing = await (await node.start()).attach(1)
    original = node.answer

    async def answer(conn: EpConnection, action: int, cb: int, value: Any) -> None:
        if action == EpPacketRequest.SUBSCRIBE:
            conn.send_error(ErrorType.MANAGEMENT, cb, ExceptionCode.NOT_SUBSCRIBABLE)
        else:
            await original(conn, action, cb, value)

    node.answer = answer  # type: ignore[method-assign]
    heard: list[Any] = []
    with pytest.raises(AsyncException):
        await thing.on_event("ping", heard.append)
    node.notify(EpPacketNotification.EVENT_OCCURRED, 1, 6, 0, "x")
    await settle()
    assert heard == []
    with pytest.raises(AttributeError):
        await thing.on_event("nope", heard.append)


async def test_detaching_forgets_the_proxy() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    await thing.detach()
    assert node.sent(EpPacketRequest.DETACH_RESOURCE) == [1]
    assert (await client.attach(1)) is not thing  # attaching again makes a fresh proxy


async def test_the_proxy_keeps_its_values_after_the_connection_closes() -> None:
    node = Node()
    client = await node.start()
    thing = await client.attach(1)
    client.close()
    await client.wait_closed()
    assert thing.count == 0 and not client._attached
    with pytest.raises(AsyncException) as down:
        await thing.say_hi()
    assert down.value.code == ExceptionCode.HOST_NOT_REACHABLE


async def test_closing_while_a_result_is_being_resolved_fails_the_request() -> None:
    node = Node()
    node.attach_delay[2] = 1
    client = await node.start()
    thing = await client.attach(1)

    async def answer(conn: EpConnection, action: int, cb: int, value: Any) -> None:
        if action == EpPacketRequest.INVOKE_FUNCTION:
            conn.send_reply(EpPacketReply.COMPLETED, cb, ResourceId(False, 2))
        else:
            await Node.answer(node, conn, action, cb, value)

    node.answer = answer  # type: ignore[method-assign]
    pending = thing.say_hi()
    await asyncio.sleep(0.05)
    client.close()
    with pytest.raises(AsyncException) as lost:
        await pending
    assert lost.value.code == ExceptionCode.HOST_NOT_REACHABLE
