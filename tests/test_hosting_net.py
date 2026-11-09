"""A Python client against a Python server: real sockets, both transports."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from hosted_types import Greeter

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.net import EpConnection, EpResource, EpServer
from esiur.net.packets import EpPacketRequest
from esiur.resource import MemoryStore, Warehouse
from esiur.security import ActionType, AllowAll, CallbackPermissions, Ruling


async def eventually(condition: Callable[[], bool], timeout: float = 3.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "the condition never became true"
        await asyncio.sleep(0.01)


async def build_warehouse(*managers: Any) -> tuple[Warehouse, Greeter, Greeter]:
    warehouse = Warehouse()
    for manager in managers:
        warehouse.register_permissions(manager)
    await warehouse.put("sys", MemoryStore())
    greeter = await warehouse.put("sys/greeter", Greeter())
    other = await warehouse.put("sys/other", Greeter())
    await warehouse.open()
    greeter.partner = other
    other.partner = greeter
    return warehouse, greeter, other


@pytest_asyncio.fixture
async def served() -> AsyncIterator[SimpleNamespace]:
    warehouse, greeter, other = await build_warehouse(AllowAll())
    server = await EpServer.listen(warehouse, port=0)
    try:
        yield SimpleNamespace(
            warehouse=warehouse,
            greeter=greeter,
            other=other,
            server=server,
            url=f"ws://127.0.0.1:{server.port}",
        )
    finally:
        await server.close()
        await warehouse.close()


# ---- attaching and calling -------------------------------------------------------------------


async def test_attaching_reads_the_type_and_the_current_values(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        assert isinstance(greeter, EpResource)
        assert greeter.instance_id == served.greeter.instance.id
        assert greeter.link == "sys/greeter"
        assert greeter.typedef.name == "Greeter"
        assert {p.name for p in greeter.typedef.properties} == {
            "visits", "label", "partner", "serial",
        }
        assert {f.name for f in greeter.typedef.functions} >= {"greet", "echo", "add", "range"}
        assert greeter.visits == 0 and greeter.label == "hello" and greeter.serial == "S-1"
        assert greeter.cursor == served.greeter.instance.cursor


async def test_calling_exported_functions(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        assert await greeter.greet("Ahmed") == "Hi Ahmed"
        assert await greeter.add(2, 40) == 42
        assert list(await greeter.range(4)) == [0, 1, 2, 3]
        assert await greeter.slow("quiet") == "QUIET"  # an async function
        assert await greeter.call("add", 1, 1) == 2
        assert served.greeter.visits == 1  # it ran on the server's object


async def test_a_static_function_needs_no_resource(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        assert await greeter.version() == "1.0"
        type_id = served.warehouse.hosted_type(Greeter).id
        assert await connection.static_call(type_id, 8) == "1.0"


async def test_a_failing_function_reports_an_exception(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException) as failed:
            await greeter.fail()
        assert failed.value.type == ErrorType.EXCEPTION
        assert failed.value.code == ExceptionCode.RUNTIME_EXCEPTION
        assert "RuntimeError: boom" in failed.value.message
        assert await greeter.add(1, 2) == 3  # the connection is fine


async def test_wrong_arguments_are_an_error_not_a_crash(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException, match="TypeError"):
            await greeter.add(1)
        with pytest.raises(AsyncException, match="TypeError"):
            await connection.invoke(greeter.instance_id, 0, "a", "b")
        assert await greeter.greet("still alive") == "Hi still alive"


async def test_many_calls_at_once(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        results = await asyncio.gather(*(greeter.add(i, i) for i in range(50)))
        assert results == [2 * i for i in range(50)]


# ---- properties ------------------------------------------------------------------------------


async def test_property_changes_are_pushed_to_the_cached_value(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        changes: list[int] = []
        greeter.on_property("visits", changes.append)
        served.greeter.visits = 5  # changed on the server, not through the peer
        await greeter.greet("a")
        await eventually(lambda: greeter.visits == 6)
        assert changes == [5, 6]
        assert greeter.age("visits") == served.greeter.instance.age_of(0)
        assert greeter.modified_at("visits") is not None
        assert greeter.cursor == served.greeter.instance.cursor


async def test_writing_a_property_is_seen_by_every_attached_peer(served: SimpleNamespace) -> None:
    async with (
        await EpConnection.connect(served.url) as one,
        await EpConnection.connect(served.url) as two,
    ):
        mine = await one.get("sys/other")
        watcher = await two.get("sys/other")
        await mine.set("label", "written by a peer")
        assert served.other.label == "written by a peer"
        assert mine.label == "written by a peer"
        await eventually(lambda: watcher.label == "written by a peer")
        async with await EpConnection.connect(served.url) as three:
            assert (await three.get("sys/other")).label == "written by a peer"


async def test_a_read_only_property_is_refused_by_the_server(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        serial = greeter.typedef.find_property("serial")
        assert serial is not None
        with pytest.raises(AsyncException) as local:
            await greeter.set("serial", "X")  # refused before it is sent
        assert local.value.code == ExceptionCode.READ_ONLY_PROPERTY
        with pytest.raises(AsyncException) as remote:
            await connection.set_property(greeter.instance_id, serial.index, "X")
        assert remote.value.code == ExceptionCode.READ_ONLY_PROPERTY
        assert served.greeter.serial == "S-1"


# ---- events ----------------------------------------------------------------------------------


async def test_events_need_a_subscription_and_stop_after_the_last_listener(
    served: SimpleNamespace,
) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        heard: list[str] = []
        more: list[str] = []
        await greeter.fire_ping("nobody listens")
        await greeter.on_event("ping", heard.append)
        await greeter.on_event("ping", more.append)
        await greeter.fire_ping("one")
        await eventually(lambda: heard == ["one"] and more == ["one"])
        await greeter.off_event("ping", more.append)
        served.greeter.ping.emit("two")  # raised by the server's own code
        await eventually(lambda: heard == ["one", "two"])
        assert more == ["one"]
        await greeter.off_event("ping", heard.append)
        await greeter.fire_ping("three")
        await asyncio.sleep(0.1)
        assert heard == ["one", "two"]
        await greeter.on_event("ping", heard.append)
        await greeter.fire_ping("four")
        await eventually(lambda: heard[-1] == "four")


async def test_auto_delivered_events_need_no_subscription(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        heard: list[str] = []
        await greeter.on_event("tick", heard.append)
        await greeter.fire_tick("hello")
        await eventually(lambda: heard == ["hello"])
        tick = greeter.typedef.find_event("tick")
        assert tick is not None
        with pytest.raises(AsyncException) as refused:  # the server refuses to subscribe it
            await connection.subscribe(greeter.instance_id, tick.index)
        assert refused.value.code == ExceptionCode.NOT_SUBSCRIBABLE


async def test_event_subscriptions_are_checked_by_the_server(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        ping = greeter.typedef.find_event("ping")
        assert ping is not None
        with pytest.raises(AsyncException) as unsubscribed:
            await connection.unsubscribe(greeter.instance_id, ping.index)
        assert unsubscribed.value.code == ExceptionCode.ALREADY_UNSUBSCRIBED
        await connection.subscribe(greeter.instance_id, ping.index)
        with pytest.raises(AsyncException) as twice:
            await connection.subscribe(greeter.instance_id, ping.index)
        assert twice.value.code == ExceptionCode.ALREADY_LISTENED
        with pytest.raises(AsyncException) as unknown:
            await connection.subscribe(greeter.instance_id, 99)
        assert unknown.value.code == ExceptionCode.GENERAL_FAILURE
        # Nothing refers to this one, so this connection never attached it.
        lonely = await served.warehouse.put("sys/lonely", Greeter())
        with pytest.raises(AsyncException) as unattached:
            await connection.subscribe(lonely.instance.id, 0)
        assert unattached.value.code == ExceptionCode.NOT_ATTACHED


# ---- resource references ---------------------------------------------------------------------


async def test_resource_valued_properties_attach_the_referenced_resource(
    served: SimpleNamespace,
) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        other = await connection.get("sys/other")
        assert greeter.partner is other
        assert other.partner is greeter


async def test_resources_that_refer_to_each_other_attach_concurrently(
    served: SimpleNamespace,
) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter, other = await asyncio.wait_for(
            asyncio.gather(
                connection.attach(served.greeter.instance.id),
                connection.attach(served.other.instance.id),
            ),
            5,
        )
        assert greeter.partner is other and other.partner is greeter


async def test_a_resource_can_be_sent_to_the_server_and_back(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        other = await connection.get("sys/other")
        assert await greeter.echo(other) is other
        assert await greeter.echo(greeter) is greeter


async def test_a_property_change_to_another_resource_attaches_it(served: SimpleNamespace) -> None:
    extra = await served.warehouse.put("sys/extra", Greeter())
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        seen: list[Any] = []
        greeter.on_property("partner", seen.append)
        served.greeter.partner = extra  # the peer has not attached it yet
        await eventually(lambda: len(seen) == 1)
        assert seen[0].link == "sys/extra" and greeter.partner is seen[0]
        served.greeter.partner = None
        await eventually(lambda: greeter.partner is None)


# ---- lookups and failures --------------------------------------------------------------------


async def test_unknown_resources_types_and_members_are_errors(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        for attempt, expected in (
            (connection.get("sys/not-there"), ExceptionCode.RESOURCE_NOT_FOUND),
            (connection.attach(987654), ExceptionCode.RESOURCE_NOT_FOUND),
            (connection.fetch_typedef(987654), ExceptionCode.TYPEDEF_NOT_FOUND),
            (connection.fetch_typedef_by_resource_id(987654), ExceptionCode.RESOURCE_NOT_FOUND),
            (connection.invoke(987654, 0), ExceptionCode.RESOURCE_NOT_FOUND),
            (connection.static_call(987654, 0), ExceptionCode.TYPEDEF_NOT_FOUND),
        ):
            with pytest.raises(AsyncException) as failed:
                await attempt
            assert failed.value.code == expected
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException) as method:
            await connection.invoke(greeter.instance_id, 99)
        assert method.value.code == ExceptionCode.METHOD_NOT_FOUND
        with pytest.raises(AsyncException) as property_:
            await connection.set_property(greeter.instance_id, 99, 1)
        assert property_.value.code == ExceptionCode.PROPERTY_NOT_FOUND
        with pytest.raises(AsyncException) as not_static:
            await connection.static_call(served.warehouse.hosted_type(Greeter).id, 0)
        assert not_static.value.code == ExceptionCode.METHOD_NOT_FOUND
        assert (await connection.get("sys/greeter")).typedef.name == "Greeter"


async def test_a_resource_can_be_attached_only_once_per_connection(
    served: SimpleNamespace,
) -> None:
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException) as again:
            await connection.send_request(EpPacketRequest.ATTACH_RESOURCE, greeter.instance_id)
        assert again.value.code == ExceptionCode.ALREADY_ATTACHED


async def test_requests_the_server_does_not_handle_are_answered(served: SimpleNamespace) -> None:
    async with await EpConnection.connect(served.url) as connection:
        with pytest.raises(AsyncException) as unhandled:
            await connection.send_request(EpPacketRequest.QUERY, "sys")
        assert unhandled.value.code == ExceptionCode.NOT_IMPLEMENTED


async def test_a_detached_resource_stops_receiving_changes_and_can_be_attached_again(
    served: SimpleNamespace,
) -> None:
    async with await EpConnection.connect(served.url) as connection:
        watcher = await connection.get("sys/other")
        heard: list[str] = []
        await watcher.on_event("ping", heard.append)
        await watcher.detach()
        before = watcher.visits
        served.other.visits += 1
        served.other.ping.emit("lost")
        await asyncio.sleep(0.2)
        assert watcher.visits == before and heard == []
        fresh = await connection.get("sys/other")  # attaches again, with fresh state
        assert fresh is not watcher and fresh.visits == before + 1
        await fresh.on_event("ping", heard.append)  # and may subscribe again
        served.other.ping.emit("found")
        await eventually(lambda: heard == ["found"])


async def test_the_server_stops_watching_when_the_connection_ends(
    served: SimpleNamespace,
) -> None:
    instance = served.greeter.instance
    connection = await EpConnection.connect(served.url)
    await connection.get("sys/greeter")
    assert len(instance._property_listeners) == 1
    connection.close()
    await connection.wait_closed()
    await eventually(lambda: not instance._property_listeners and not instance._event_listeners)
    await eventually(lambda: not served.server.connections)
    served.greeter.visits = 3  # nobody to tell, and nothing breaks


async def test_closing_the_server_closes_the_peers(served: SimpleNamespace) -> None:
    connection = await EpConnection.connect(served.url)
    greeter = await connection.get("sys/greeter")
    await served.server.close()
    await asyncio.wait_for(connection.wait_closed(), 3)
    with pytest.raises(AsyncException) as down:
        await greeter.greet("late")
    assert down.value.code == ExceptionCode.HOST_NOT_REACHABLE


# ---- permissions -----------------------------------------------------------------------------


async def test_by_default_a_peer_may_read_and_call_but_not_write() -> None:
    warehouse, _, other = await build_warehouse()  # no permissions manager at all
    async with (
        await EpServer.listen(warehouse, port=0) as server,
        await EpConnection.connect(f"ws://127.0.0.1:{server.port}") as connection,
    ):
        greeter = await connection.get("sys/other")
        assert await greeter.greet("x") == "Hi x"
        with pytest.raises(AsyncException) as denied:
            await greeter.set("label", "no")
        assert denied.value.code == ExceptionCode.ACCESS_DENIED
        assert other.label == "hello"
    await warehouse.close()


async def test_a_manager_decides_per_member_and_per_action() -> None:
    def rule(resource: Any, session: Any, action: ActionType, member: Any, inquirer: Any) -> Ruling:
        if action == ActionType.EXECUTE and member is not None and member.name == "fail":
            return Ruling.DENIED
        if action == ActionType.ATTACH and resource.instance.link == "sys/denied":
            return Ruling.DENIED
        if action == ActionType.VIEW_TYPEDEF:
            return Ruling.DENIED
        return Ruling.DONT_CARE

    warehouse, *_ = await build_warehouse(CallbackPermissions(rule))
    async with (
        await EpServer.listen(warehouse, port=0) as server,
        await EpConnection.connect(f"ws://127.0.0.1:{server.port}") as connection,
    ):
        with pytest.raises(AsyncException) as typedef:
            await connection.get("sys/greeter")  # the type may not be viewed
        assert typedef.value.code == ExceptionCode.NOT_ALLOWED
    await warehouse.close()

    def without_typedef_rule(*args: Any) -> Ruling:
        return Ruling.DONT_CARE if args[2] == ActionType.VIEW_TYPEDEF else rule(*args)

    warehouse, *_ = await build_warehouse(CallbackPermissions(without_typedef_rule))
    await warehouse.put("sys/denied", Greeter())
    async with (
        await EpServer.listen(warehouse, port=0) as server,
        await EpConnection.connect(f"ws://127.0.0.1:{server.port}") as connection,
    ):
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException) as execute:
            await greeter.fail()
        assert execute.value.code == ExceptionCode.ACCESS_DENIED
        assert await greeter.add(1, 1) == 2
        with pytest.raises(AsyncException) as attach:
            await connection.get("sys/denied")
        assert attach.value.code == ExceptionCode.ATTACH_DENIED
        assert (await connection.get("sys/other")).typedef.name == "Greeter"
    await warehouse.close()


# ---- transports ------------------------------------------------------------------------------


async def test_the_same_warehouse_is_served_over_raw_tcp() -> None:
    warehouse, _, _ = await build_warehouse(AllowAll())
    async with (
        await EpServer.listen(warehouse, port=0, transport="tcp") as server,
        await EpConnection.connect(f"tcp://127.0.0.1:{server.port}") as connection,
    ):
        greeter = await connection.get("sys/greeter")
        assert await greeter.greet("tcp") == "Hi tcp"
        heard: list[str] = []
        await greeter.on_event("ping", heard.append)
        await greeter.fire_ping("over tcp")
        await eventually(lambda: heard == ["over tcp"])
    await warehouse.close()


async def test_one_server_can_listen_on_both_transports() -> None:
    warehouse, _, _ = await build_warehouse(AllowAll())
    async with EpServer(warehouse) as server:
        ws_port = await server.add_listener("ws", port=0)
        tcp_port = await server.add_listener("tcp", port=0)
        assert server.ports == (ws_port, tcp_port) and ws_port != tcp_port
        async with (
            await EpConnection.connect(f"ws://127.0.0.1:{ws_port}") as by_ws,
            await EpConnection.connect(f"tcp://127.0.0.1:{tcp_port}") as by_tcp,
        ):
            first, second = await by_ws.get("sys/greeter"), await by_tcp.get("sys/greeter")
            await first.set("label", "shared")
            await eventually(lambda: second.label == "shared")
    await warehouse.close()


async def test_a_server_can_refuse_anonymous_peers() -> None:
    warehouse, _, _ = await build_warehouse(AllowAll())
    async with await EpServer.listen(warehouse, port=0, allow_unauthorized=False) as server:
        with pytest.raises(AsyncException):
            await EpConnection.connect(f"ws://127.0.0.1:{server.port}")
    await warehouse.close()


async def test_listener_arguments_are_validated() -> None:
    server = EpServer(Warehouse())
    with pytest.raises(ValueError, match="port"):
        await server.add_listener("ws", port=70000)
    with pytest.raises(ValueError, match="transport"):
        await server.add_listener("udp", port=0)  # type: ignore[arg-type]


async def test_a_resource_of_another_warehouse_cannot_be_sent(served: SimpleNamespace) -> None:
    stranger = Greeter()
    async with await EpConnection.connect(served.url) as connection:
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException, match="warehouse"):
            await greeter.echo(stranger)
