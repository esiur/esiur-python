"""Resource classes the hosting tests serve: the same surface as the esiur-ts test server's
``Greeter``, so a client written for either side reads the same."""

from __future__ import annotations

import asyncio

from esiur.data import t
from esiur.resource import Event, Property, Resource, function


class Greeter(Resource):
    """A resource with every kind of member."""

    visits = Property(t.i32, default=0)
    label = Property(t.string, default="hello")
    partner = Property(t.resource.to_nullable(), default=None)
    serial = Property(t.string, default="S-1", read_only=True)
    ping = Event(t.string)
    tick = Event(t.string, auto_delivered=True)

    @function(t.string, [t.string])
    def greet(self, name: str) -> str:
        self.visits += 1
        return "Hi " + name

    @function(t.void, [t.string])
    def fire_ping(self, message: str) -> None:
        self.ping.emit(message)

    @function(t.void, [t.string])
    def fire_tick(self, message: str) -> None:
        self.tick.emit(message)

    @function(t.list(t.i32), [t.i32])
    def range(self, count: int) -> list[int]:
        return list(range(count))

    @function(t.resource, [t.resource])
    def echo(self, resource: Resource) -> Resource:
        return resource

    @function(t.i32, [t.i32, t.i32])
    def add(self, a: int, b: int) -> int:
        return a + b

    @function(t.void)
    def fail(self) -> None:
        raise RuntimeError("boom")

    @function(t.string, [t.string])
    async def slow(self, text: str) -> str:
        await asyncio.sleep(0.01)
        return text.upper()

    @function(t.string, static=True)
    def version() -> str:  # type: ignore[misc]
        return "1.0"
