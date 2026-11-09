"""The resource layer on its own: declared members, the TypeDef built from them, instances and
the warehouse."""

from __future__ import annotations

import pytest
from hosted_types import Greeter

from esiur.data import EventDefFlags, FunctionDefFlags, PropertyDefFlags, t
from esiur.resource import (
    Event,
    MemoryStore,
    Property,
    Resource,
    ResourceOperation,
    Warehouse,
    function,
)
from esiur.security import ActionType, AllowAll, CallbackPermissions, Ruling, default_permissions


async def hosted() -> tuple[Warehouse, Greeter]:
    warehouse = Warehouse()
    await warehouse.put("sys", MemoryStore())
    greeter = await warehouse.put("sys/greeter", Greeter())
    await warehouse.open()
    return warehouse, greeter


# ---- members and the TypeDef built from them -------------------------------------------------


async def test_the_typedef_lists_the_declared_members_in_order() -> None:
    warehouse, _ = await hosted()
    info = warehouse.hosted_type(Greeter).info
    assert info.name == "Greeter"
    assert [p.name for p in info.properties or ()] == ["visits", "label", "partner", "serial"]
    assert [e.name for e in info.events or ()] == ["ping", "tick"]
    assert [f.name for f in info.functions or ()] == [
        "greet", "fire_ping", "fire_tick", "range", "echo", "add", "fail", "slow", "version",
    ]
    assert [m.index for m in info.properties or ()] == [0, 1, 2, 3]
    assert info.signature


async def test_member_flags_and_argument_descriptions() -> None:
    warehouse, _ = await hosted()
    info = warehouse.hosted_type(Greeter).info
    serial = next(p for p in info.properties or () if p.name == "serial")
    assert serial.flags & PropertyDefFlags.READ_ONLY
    tick = next(e for e in info.events or () if e.name == "tick")
    ping = next(e for e in info.events or () if e.name == "ping")
    assert tick.flags & EventDefFlags.AUTO_DELIVERED and not ping.flags & EventDefFlags.AUTO_DELIVERED
    functions = {f.name: f for f in info.functions or ()}
    assert functions["version"].flags & FunctionDefFlags.STATIC
    assert not functions["greet"].flags & FunctionDefFlags.STATIC
    add = functions["add"]
    assert [a.name for a in add.arguments or ()] == ["a", "b"]
    assert [a.value_type for a in add.arguments or ()] == [t.i32, t.i32]
    assert add.return_type == t.i32


async def test_a_type_gets_one_id_and_the_signature_ignores_it() -> None:
    first, second = Warehouse(), Warehouse()
    first.hosted_type(Resource)  # shifts the ids of the first warehouse
    a, b = first.hosted_type(Greeter), second.hosted_type(Greeter)
    assert a.id != b.id
    assert first.hosted_type(Greeter) is a
    assert a.info.signature == b.info.signature
    assert first.type_by_id(a.id) is a
    with pytest.raises(KeyError):
        first.type_by_id(999)


def test_a_subclass_inherits_members_and_keeps_the_place_of_a_redeclared_one() -> None:
    class Base(Resource):
        first = Property(t.i32, default=1)
        second = Property(t.i32, default=2)

    class Derived(Base):
        third = Property(t.i32, default=3)
        first = Property(t.string, default="one")

    members = Warehouse().hosted_type(Derived)
    assert [p.name for p in members.properties] == ["first", "second", "third"]
    assert members.properties[0].type == t.string
    assert Derived().first == "one"
    assert Base().first == 1


def test_function_declarations_are_validated() -> None:
    with pytest.raises(TypeError, match="declares 2 argument types but takes 1"):

        class Mismatch(Resource):
            @function(t.void, [t.i32, t.i32])
            def go(self, only: int) -> None: ...

    with pytest.raises(TypeError, match="positional parameters only"):

        class Variadic(Resource):
            @function(t.void)
            def go(self, *rest: int) -> None: ...

    with pytest.raises(NotImplementedError):
        Property(t.i32, historical=True)
    with pytest.raises(NotImplementedError):
        Event(t.i32, historical=True)
    with pytest.raises(ValueError, match="not both"):
        Property(t.i32, default=1, default_factory=int)


def test_a_bare_function_decorator_and_defaults() -> None:
    class Plain(Resource):
        items = Property(t.list(t.i32), default_factory=list)

        @function
        def twice(self, value, extra=0):  # type: ignore[no-untyped-def]
            return value * 2 + extra

    one, two = Plain(), Plain()
    one.items.append(1)
    assert two.items == []  # each resource gets its own default
    assert one.twice(4, extra=1) == 9  # a call from Python is an ordinary call
    info = Warehouse().hosted_type(Plain).info
    twice = (info.functions or [])[0]
    assert [a.name for a in twice.arguments or ()] == ["value", "extra"]
    assert [a.value_type for a in twice.arguments or ()] == [t.dynamic, t.dynamic]
    assert twice.arguments[1].flags  # the parameter with a default is optional


# ---- instances -------------------------------------------------------------------------------


async def test_every_change_takes_the_next_revision() -> None:
    _, greeter = await hosted()
    instance = greeter.instance
    assert instance is not None
    start = instance.cursor
    assert start.revision == 0 and not start.is_empty
    changes = []
    instance.add_property_listener(changes.append)
    occurrences = []
    instance.add_event_listener(occurrences.append)

    greeter.label = "changed"
    greeter.ping.emit("hello")
    greeter.visits = 7

    assert [c.index for c in changes] == [1, 0]
    assert [c.cursor.revision for c in changes] == [1, 3]
    assert [o.cursor.revision for o in occurrences] == [2]
    assert changes[0].cursor.generation == start.generation
    assert instance.age == 3
    assert instance.age_of(1) == 1 and instance.age_of(0) == 3 and instance.age_of(2) == 0
    assert instance.value_of(0) == 7
    assert instance.modified_at(1) > instance.modified_at(2)  # never changed: the epoch


async def test_event_listeners_in_the_process_run_even_without_peers() -> None:
    _, greeter = await hosted()
    heard: list[str] = []
    greeter.ping.listen(heard.append)
    greeter.ping.emit("a")
    greeter.ping.unlisten(heard.append)
    greeter.ping.emit("b")
    assert heard == ["a"]


async def test_a_failing_listener_does_not_stop_the_others() -> None:
    _, greeter = await hosted()
    assert greeter.instance is not None
    seen: list[int] = []

    def broken(change: object) -> None:
        raise RuntimeError("listener bug")

    greeter.instance.add_property_listener(broken)
    greeter.instance.add_property_listener(lambda change: seen.append(change.index))
    greeter.visits = 1
    assert seen == [0]


def test_a_resource_outside_a_warehouse_is_an_ordinary_object() -> None:
    greeter = Greeter()
    greeter.visits += 2
    greeter.ping.emit("nobody")
    assert greeter.visits == 2 and greeter.instance is None
    assert greeter.add(1, 2) == 3
    assert Greeter.version() == "1.0"


# ---- the warehouse ---------------------------------------------------------------------------


async def test_put_query_and_remove() -> None:
    warehouse, greeter = await hosted()
    assert greeter.instance is not None and greeter.instance.link == "sys/greeter"
    assert await warehouse.query("sys/greeter") is greeter
    assert await warehouse.query("/sys/greeter/") is greeter
    assert await warehouse.query("sys/missing") is None
    assert await warehouse.query("elsewhere/greeter") is None
    assert warehouse.get_by_id(greeter.instance.id) is greeter
    store = await warehouse.query("sys")
    assert isinstance(store, MemoryStore) and await store.get(f"${greeter.instance.id}") is greeter

    destroyed: list[Resource] = []
    greeter.add_destroy_handler(destroyed.append)
    assert await warehouse.remove(greeter)
    assert destroyed == [greeter]
    assert greeter.instance is None
    assert await warehouse.query("sys/greeter") is None
    assert not await warehouse.remove(greeter)


async def test_put_validates_its_arguments() -> None:
    warehouse = Warehouse()
    with pytest.raises(ValueError, match="not a store"):
        await warehouse.put("alone", Greeter())
    with pytest.raises(ValueError, match="Invalid path"):
        await warehouse.put("", MemoryStore())
    with pytest.raises(LookupError, match="parent"):
        await warehouse.put("missing/greeter", Greeter())
    await warehouse.put("sys", MemoryStore())
    greeter = await warehouse.put("sys/greeter", Greeter())
    with pytest.raises(ValueError, match="already hosted"):
        await warehouse.put("sys/again", greeter)


async def test_lifecycle_operations_reach_resources() -> None:
    seen: list[ResourceOperation] = []

    class Recording(Resource):
        async def handle(self, operation: ResourceOperation, context: object = None) -> bool:
            seen.append(operation)
            return await super().handle(operation, context)

        def create(self) -> bool:
            seen.append(ResourceOperation.CONFIGURE)  # marks that create() ran
            return True

    warehouse = Warehouse()
    await warehouse.put("sys", MemoryStore())
    await warehouse.put("sys/early", Recording())
    assert seen == []  # not opened yet
    await warehouse.open()
    assert seen == [ResourceOperation.INITIALIZE, ResourceOperation.CONFIGURE]
    seen.clear()
    await warehouse.put("sys/late", Recording())  # initialized as it arrives
    assert seen == [ResourceOperation.INITIALIZE, ResourceOperation.CONFIGURE]
    seen.clear()
    await warehouse.close()
    assert seen.count(ResourceOperation.TERMINATE) == 2
    assert not warehouse.is_open


async def test_closing_reports_every_failure() -> None:
    class Breaks(Resource):
        async def handle(self, operation: ResourceOperation, context: object = None) -> bool:
            if operation == ResourceOperation.TERMINATE:
                raise RuntimeError("cannot terminate")
            return True

    warehouse = Warehouse()
    await warehouse.put("sys", MemoryStore())
    await warehouse.put("sys/a", Breaks())
    await warehouse.put("sys/b", Breaks())
    with pytest.raises(RuntimeError, match="2 resources failed"):
        await warehouse.close()


# ---- permissions -----------------------------------------------------------------------------


async def test_default_permissions_allow_reading_and_deny_changing() -> None:
    warehouse, greeter = await hosted()
    assert warehouse.evaluate(greeter, None, ActionType.ATTACH).allowed
    assert warehouse.evaluate(greeter, None, ActionType.EXECUTE).allowed
    assert not warehouse.evaluate(greeter, None, ActionType.SET_PROPERTY).allowed
    assert default_permissions(ActionType.DELETE) == Ruling.DENIED


async def test_a_denial_beats_an_allowance_and_a_failing_manager_denies() -> None:
    warehouse, greeter = await hosted()
    warehouse.register_permissions(AllowAll())
    assert warehouse.evaluate(greeter, None, ActionType.SET_PROPERTY).allowed
    warehouse.register_permissions(
        CallbackPermissions(lambda *_: Ruling.DENIED if _[2] == ActionType.EXECUTE else Ruling.DONT_CARE)
    )
    verdict = warehouse.evaluate(greeter, None, ActionType.EXECUTE)
    assert not verdict.allowed and "denied" in (verdict.reason or "")
    assert warehouse.evaluate(greeter, None, ActionType.SET_PROPERTY).allowed

    def explode(*_: object) -> Ruling:
        raise RuntimeError("manager bug")

    warehouse.register_permissions(CallbackPermissions(explode))
    assert not warehouse.evaluate(greeter, None, ActionType.ATTACH).allowed
    with pytest.raises(ValueError, match="already registered"):
        manager = AllowAll()
        warehouse.register_permissions(manager)
        warehouse.register_permissions(manager)
