"""A resource that lives on the other side of a connection (port of esiur-ts ``EpResource``).

The proxy keeps the last value of every property (refreshed by the peer's notifications), turns
calls to exported functions into requests, and delivers the peer's events to listeners::

    greeter = await connection.get("sys/greeter")
    print(greeter.visits)                 # a cached property value
    print(await greeter.greet("Ahmed"))   # a remote call
    await greeter.set("visits", 0)        # a remote write
    await greeter.on_event("ping", print) # subscribes on first listener

Members are found by name, ignoring case and underscores, so ``greeter.say_hi`` reaches a
member the peer calls ``sayHi``. Attributes of the proxy itself (``connection``, ``link`` ...)
come first; reach a member they shadow with :meth:`get`, :meth:`call` or :meth:`set`.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.data import PropertyDefInfo, StreamMode
from esiur.resource import ResourceCursor, TypeDef

if TYPE_CHECKING:
    from .connection import EpConnection

Listener = Callable[[Any], Any]


class EpResource:
    """The local stand-in for a resource hosted by a peer."""

    def __init__(
        self,
        connection: EpConnection,
        instance_id: int,
        typedef: TypeDef,
        *,
        type_id: int = 0,
        cursor: ResourceCursor | None = None,
        link: str = "",
        hops: int = 0,
    ) -> None:
        self.connection = connection
        self.instance_id = instance_id
        self.typedef = typedef
        #: The id the peer reported for the resource's type (0 when it relays the resource).
        self.type_id = type_id
        self.cursor = cursor or ResourceCursor.empty()
        self.link = link
        self.hops = hops

        self._values: dict[int, Any] = {}
        self._ages: dict[int, int] = {}
        self._dates: dict[int, dt.datetime | None] = {}
        self._property_cursors: dict[int, ResourceCursor] = {}
        self._event_cursors: dict[int, ResourceCursor] = {}
        self._property_listeners: dict[int, list[Listener]] = {}
        self._event_listeners: dict[int, list[Listener]] = {}
        self._subscribed: set[int] = set()
        self._subscription_locks: dict[int, asyncio.Lock] = {}

    def __repr__(self) -> str:
        return f"<EpResource {self.typedef.name} #{self.instance_id} {self.link!r}>"

    # ---- members by name ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        property_ = self.typedef.find_property(name)
        if property_ is not None:
            return self._values.get(property_.index)
        function = self.typedef.find_function(name)
        if function is not None:
            return lambda *args: self._invoke(function.index, args)
        raise AttributeError(f"{self.typedef.name} has no member '{name}'.")

    def get(self, name: str) -> Any:
        """The last known value of a property."""
        return self._values.get(self._property(name).index)

    def age(self, name: str) -> int:
        """The revision at which a property last changed."""
        return self._ages.get(self._property(name).index, 0)

    def modified_at(self, name: str) -> dt.datetime | None:
        """When a property last changed, as the peer reported it."""
        return self._dates.get(self._property(name).index)

    def call(self, name: str, *args: Any) -> asyncio.Future[Any]:
        """Call an exported function; the same as ``resource.<name>(*args)``."""
        function = self.typedef.find_function(name)
        if function is None:
            raise AttributeError(f"{self.typedef.name} has no function '{name}'.")
        return self._invoke(function.index, args)

    async def set(self, name: str, value: Any) -> None:
        """Write a property on the peer; the cached value follows once it accepts."""
        property_ = self._property(name)
        if self.typedef.is_read_only(property_):
            raise AsyncException(
                ErrorType.MANAGEMENT,
                ExceptionCode.READ_ONLY_PROPERTY,
                f"'{property_.name}' is read-only.",
            )
        await self.connection.set_property(self.instance_id, property_.index, value)
        self._values[property_.index] = value

    async def detach(self) -> None:
        """Stop receiving this resource's notifications."""
        await self.connection.detach(self.instance_id)

    def _property(self, name: str) -> PropertyDefInfo:
        property_ = self.typedef.find_property(name)
        if property_ is None:
            raise AttributeError(f"{self.typedef.name} has no property '{name}'.")
        return property_

    def _invoke(self, index: int, args: tuple[Any, ...]) -> asyncio.Future[Any]:
        function = self.typedef.function_by_index(index)
        assert function is not None
        if function.stream_mode != StreamMode.NONE:
            raise NotImplementedError("Streaming functions are not supported yet.")
        if self.typedef.is_static(function):
            return self.connection.static_call(self.type_id or self.typedef.id, index, *args)
        return self.connection.invoke(self.instance_id, index, *args)

    # ---- listeners ------------------------------------------------------------------------

    def on_property(self, name: str, callback: Listener) -> None:
        """Call ``callback(value)`` whenever the peer changes a property."""
        self._property_listeners.setdefault(self._property(name).index, []).append(callback)

    def off_property(self, name: str, callback: Listener) -> None:
        listeners = self._property_listeners.get(self._property(name).index, [])
        if callback in listeners:
            listeners.remove(callback)

    async def on_event(self, name: str, callback: Listener) -> None:
        """Call ``callback(value)`` whenever the peer raises an event. The first listener of an
        event that needs it subscribes on the peer; this returns once that has happened."""
        event = self.typedef.find_event(name)
        if event is None:
            raise AttributeError(f"{self.typedef.name} has no event '{name}'.")
        listeners = self._event_listeners.setdefault(event.index, [])
        listeners.append(callback)
        try:
            await self._reconcile(event.index)
        except BaseException:
            if callback in listeners:
                listeners.remove(callback)
            raise

    async def off_event(self, name: str, callback: Listener) -> None:
        """Remove a listener; the last one unsubscribes on the peer."""
        event = self.typedef.find_event(name)
        if event is None:
            return
        listeners = self._event_listeners.get(event.index, [])
        if callback in listeners:
            listeners.remove(callback)
        await self._reconcile(event.index)

    async def _reconcile(self, index: int) -> None:
        """Bring the peer's subscription for event ``index`` in line with the listeners. The
        peer rejects a redundant subscribe or unsubscribe, so the state is tracked here."""
        event = self.typedef.event_by_index(index)
        if event is None or not (
            self.typedef.is_subscribable(event) or self.typedef.is_historical(event)
        ):
            return
        async with self._subscription_locks.setdefault(index, asyncio.Lock()):
            wanted = bool(self._event_listeners.get(index))
            if wanted and index not in self._subscribed:
                after = self._event_cursors.get(index, self.cursor)
                await self.connection.subscribe(self.instance_id, index, after)
                self._subscribed.add(index)
            elif not wanted and index in self._subscribed:
                await self.connection.unsubscribe(self.instance_id, index)
                self._subscribed.discard(index)

    # ---- fed by the connection ------------------------------------------------------------

    def _set_snapshot(
        self, index: int, age: int, date: dt.datetime | None, value: Any
    ) -> None:
        """Seed a value from an attach reply: it is state, not a change, so nothing is raised."""
        self._values[index] = value
        self._ages[index] = age
        self._dates[index] = date
        if not self.cursor.is_empty:
            self._property_cursors[index] = ResourceCursor(self.cursor.generation, age)
        if age > self.cursor.revision:
            self.cursor = ResourceCursor(self.cursor.generation, age)

    def _update_property(
        self, index: int, value: Any, cursor: ResourceCursor, date: dt.datetime | None
    ) -> None:
        if self._is_stale(self._property_cursors.get(index), cursor):
            return
        self._property_cursors[index] = cursor
        self._observe(cursor)
        self._values[index] = value
        self._ages[index] = cursor.revision
        self._dates[index] = date or dt.datetime.now(dt.timezone.utc)
        for listener in list(self._property_listeners.get(index, ())):
            self.connection._notify_listener(listener, value)

    def _apply_event(self, index: int, value: Any, cursor: ResourceCursor) -> None:
        if self._is_stale(self._event_cursors.get(index), cursor):
            return
        self._event_cursors[index] = cursor
        self._observe(cursor)
        for listener in list(self._event_listeners.get(index, ())):
            self.connection._notify_listener(listener, value)

    @staticmethod
    def _is_stale(previous: ResourceCursor | None, cursor: ResourceCursor) -> bool:
        """A notification at or before one already applied (same generation) is a duplicate."""
        return (
            previous is not None
            and previous.generation == cursor.generation
            and previous.revision >= cursor.revision
        )

    def _observe(self, cursor: ResourceCursor) -> None:
        if (
            self.cursor.is_empty
            or self.cursor.generation != cursor.generation
            or cursor.revision > self.cursor.revision
        ):
            self.cursor = cursor
