"""Remote resources against a real esiur-ts server (see ``ts_server`` in conftest.py).

The server hosts two ``Greeter`` resources, ``sys/greeter`` and ``sys/other``, that refer to each
other through their ``partner`` property.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.net import EpConnection, EpResource


def url(server: dict[str, Any]) -> str:
    return f"ws://127.0.0.1:{server['port']}"


async def eventually(condition: Callable[[], bool], timeout: float = 3.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "the condition never became true"
        await asyncio.sleep(0.01)


async def test_attaching_reads_the_type_and_the_current_values(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        assert isinstance(greeter, EpResource)
        assert greeter.instance_id == ts_server["greeterId"]
        assert greeter.typedef.name == "Greeter"
        assert {p.name for p in greeter.typedef.properties} >= {"visits", "label", "partner"}
        assert {f.name for f in greeter.typedef.functions} >= {"greet", "echo", "add", "range"}
        assert {e.name for e in greeter.typedef.events} == {"ping", "tick"}
        assert isinstance(greeter.visits, int)
        assert isinstance(greeter.label, str)
        assert not greeter.cursor.is_empty


async def test_attaching_twice_gives_the_same_proxy(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        first, second, third = await asyncio.gather(
            connection.get("sys/greeter"),
            connection.get("sys/greeter"),
            connection.attach(ts_server["greeterId"]),
        )
        assert first is second is third
        assert await connection.get("sys/greeter") is first


async def test_calling_exported_functions(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        assert await greeter.greet("Ahmed") == "Hi Ahmed"
        assert await greeter.add(2, 40) == 42
        assert list(await greeter.range(4)) == [0, 1, 2, 3]
        assert await greeter.call("add", 1, 1) == 2
        with pytest.raises(AttributeError):
            greeter.no_such_member  # noqa: B018


async def test_a_failing_function_reports_an_exception(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        with pytest.raises(AsyncException) as failed:
            await greeter.fail()
        assert failed.value.type == ErrorType.EXCEPTION
        assert "boom" in failed.value.message


async def test_property_changes_are_pushed_to_the_cached_value(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        before = greeter.visits
        changes: list[int] = []
        greeter.on_property("visits", changes.append)
        await greeter.greet("a")
        await greeter.greet("b")
        await eventually(lambda: greeter.visits == before + 2)
        assert changes == [before + 1, before + 2]
        assert greeter.age("visits") >= before + 2 or greeter.age("visits") > 0
        assert greeter.modified_at("visits") is not None


async def test_a_second_connection_sees_changes_made_by_the_first(
    ts_server: dict[str, Any],
) -> None:
    async with (
        await EpConnection.connect(url(ts_server)) as one,
        await EpConnection.connect(url(ts_server)) as two,
    ):
        mine = await one.get("sys/greeter")
        theirs = await two.get("sys/greeter")
        before = theirs.visits
        await mine.greet("x")
        await eventually(lambda: theirs.visits == before + 1)


async def test_writing_a_property(ts_server: dict[str, Any]) -> None:
    async with (
        await EpConnection.connect(url(ts_server)) as one,
        await EpConnection.connect(url(ts_server)) as two,
    ):
        mine = await one.get("sys/other")
        watcher = await two.get("sys/other")
        await mine.set("label", "written from python")
        assert mine.label == "written from python"
        await eventually(lambda: watcher.label == "written from python")
        # A fresh attach reads it from the server.
        async with await EpConnection.connect(url(ts_server)) as three:
            assert (await three.get("sys/other")).label == "written from python"


async def test_events_need_a_subscription_and_stop_after_the_last_listener(
    ts_server: dict[str, Any],
) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        heard: list[str] = []
        more: list[str] = []
        await greeter.fire_ping("nobody listens")  # not subscribed: not delivered
        await greeter.on_event("ping", heard.append)
        await greeter.on_event("ping", more.append)  # the second listener reuses the subscription
        await greeter.fire_ping("one")
        await eventually(lambda: heard == ["one"] and more == ["one"])
        await greeter.off_event("ping", more.append)
        await greeter.fire_ping("two")
        await eventually(lambda: heard == ["one", "two"])
        assert more == ["one"]
        await greeter.off_event("ping", heard.append)  # the last one unsubscribes
        await greeter.fire_ping("three")
        await asyncio.sleep(0.1)
        assert heard == ["one", "two"]
        await greeter.on_event("ping", heard.append)  # and it can subscribe again
        await greeter.fire_ping("four")
        await eventually(lambda: heard[-1] == "four")


async def test_auto_delivered_events_need_no_subscription(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        heard: list[str] = []
        await greeter.on_event("tick", heard.append)
        await greeter.fire_tick("hello")
        await eventually(lambda: heard == ["hello"])


async def test_a_listener_that_raises_does_not_break_the_connection(
    ts_server: dict[str, Any],
) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")

        def broken(value: object) -> None:
            raise RuntimeError("listener bug")

        heard: list[str] = []
        await greeter.on_event("tick", broken)
        await greeter.on_event("tick", heard.append)
        await greeter.fire_tick("still delivered")
        await eventually(lambda: heard == ["still delivered"])
        assert await greeter.add(1, 2) == 3


async def test_resource_valued_properties_attach_the_referenced_resource(
    ts_server: dict[str, Any],
) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter = await connection.get("sys/greeter")
        other = await connection.get("sys/other")
        assert greeter.partner is other
        assert other.partner is greeter  # a cycle resolves to the same proxies


async def test_resources_that_refer_to_each_other_attach_concurrently(
    ts_server: dict[str, Any],
) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        greeter, other = await asyncio.wait_for(
            asyncio.gather(
                connection.attach(ts_server["greeterId"]), connection.attach(ts_server["otherId"])
            ),
            5,
        )
        assert greeter.partner is other and other.partner is greeter


async def test_a_proxy_from_another_connection_cannot_be_sent(ts_server: dict[str, Any]) -> None:
    async with (
        await EpConnection.connect(url(ts_server)) as one,
        await EpConnection.connect(url(ts_server)) as two,
    ):
        foreign = await two.get("sys/other")
        greeter = await one.get("sys/greeter")
        with pytest.raises(AsyncException, match="another connection"):
            await greeter.echo(foreign)


async def test_a_detached_resource_stops_receiving_changes(ts_server: dict[str, Any]) -> None:
    async with (
        await EpConnection.connect(url(ts_server)) as one,
        await EpConnection.connect(url(ts_server)) as two,
    ):
        watcher = await one.get("sys/other")
        driver = await two.get("sys/other")
        await watcher.detach()
        before = watcher.visits
        await driver.greet("x")
        await asyncio.sleep(0.2)
        assert watcher.visits == before


async def test_unknown_resources_and_instances_are_errors(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as connection:
        with pytest.raises(AsyncException) as missing:
            await connection.get("sys/not-there")
        assert missing.value.code == ExceptionCode.RESOURCE_NOT_FOUND
        with pytest.raises(AsyncException) as unknown:
            await connection.attach(987654)
        assert unknown.value.code == ExceptionCode.RESOURCE_NOT_FOUND
        # A failed attach leaves nothing behind that breaks the next one.
        assert (await connection.get("sys/greeter")).typedef.name == "Greeter"


async def test_calls_on_a_closed_connection_fail(ts_server: dict[str, Any]) -> None:
    connection = await EpConnection.connect(url(ts_server))
    greeter = await connection.get("sys/greeter")
    connection.close()
    await connection.wait_closed()
    with pytest.raises(AsyncException) as down:
        await greeter.greet("late")
    assert down.value.code == ExceptionCode.HOST_NOT_REACHABLE
    assert greeter.label  # cached values stay readable
