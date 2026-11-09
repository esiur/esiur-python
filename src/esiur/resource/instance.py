"""A hosted resource's identity and change stream (port of esiur-ts ``Instance``)."""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .cursor import ResourceCursor
from .hosted import HostedType
from .members import Event, Property
from .resource import Resource

if TYPE_CHECKING:
    from .stores import Store
    from .warehouse import Warehouse

logger = logging.getLogger("esiur.resource")

_NEVER = dt.datetime.fromtimestamp(0, dt.timezone.utc)


@dataclass(frozen=True, slots=True)
class PropertyModified:
    resource: Resource
    index: int
    value: Any
    age: int
    cursor: ResourceCursor
    recorded_at: dt.datetime


@dataclass(frozen=True, slots=True)
class EventOccurred:
    resource: Resource
    index: int
    value: Any
    cursor: ResourceCursor
    recorded_at: dt.datetime


PropertyListener = Callable[[PropertyModified], None]
EventListener = Callable[[EventOccurred], None]


class Instance:
    """What a warehouse knows about one resource: its id, name and store, its type, and the
    ordered stream of changes it has made. Every property change and every raised event takes
    the next revision of the stream; a peer compares revisions to drop what it has seen."""

    def __init__(
        self,
        warehouse: Warehouse,
        instance_id: int,
        name: str,
        resource: Resource,
        store: Store,
        hosted: HostedType,
    ) -> None:
        self.warehouse = warehouse
        self.id = instance_id
        self.name = name
        self.resource = resource
        self.store = store
        self.type = hosted
        #: Free-form state stores and managers keep per resource (the memory store keeps the
        #: resource's link here).
        self.variables: dict[str, Any] = {}
        self.is_destroyed = False

        self._cursor = ResourceCursor(uuid.uuid4(), 0)
        self._ages = [0] * len(hosted.properties)
        self._dates: list[dt.datetime | None] = [None] * len(hosted.properties)
        self._property_listeners: list[PropertyListener] = []
        self._event_listeners: list[EventListener] = []
        self._destroy_listeners: list[Callable[[Resource], None]] = []
        resource.add_destroy_handler(self._on_destroy)

    def __repr__(self) -> str:
        return f"<Instance #{self.id} {self.link!r} {self.type.name}>"

    # ---- identity -------------------------------------------------------------------------

    @property
    def link(self) -> str | None:
        """The path a peer resolves to reach this resource, such as ``sys/greeter``."""
        if self.resource is self.store:
            return self.name  # a store's link is its own name
        store_name = self.store.instance.name if self.store.instance is not None else ""
        return f"{store_name}/{self.store.link(self.resource)}"

    @property
    def cursor(self) -> ResourceCursor:
        """The position of the latest change."""
        return self._cursor

    @property
    def generation(self) -> uuid.UUID:
        return self._cursor.generation

    @property
    def age(self) -> int:
        return self._cursor.revision

    # ---- per-property state ---------------------------------------------------------------

    def age_of(self, index: int) -> int:
        """The revision at which property ``index`` last changed (0 if it never has)."""
        return self._ages[index] if 0 <= index < len(self._ages) else 0

    def modified_at(self, index: int) -> dt.datetime:
        """When property ``index`` last changed; the epoch if it never has."""
        date = self._dates[index] if 0 <= index < len(self._dates) else None
        return date or _NEVER

    def value_of(self, index: int) -> Any:
        """The current value of property ``index``."""
        return getattr(self.resource, self.type.properties[index].attribute)

    # ---- changes --------------------------------------------------------------------------

    def modified(self, property_: Property[Any], value: Any) -> None:
        """A property changed (the descriptor calls this from its setter)."""
        index = self._index_of_property(property_)
        if index < 0:
            return
        cursor = self._next_cursor()
        now = dt.datetime.now(dt.timezone.utc)
        self._ages[index] = cursor.revision
        self._dates[index] = now
        self.store.modify(self.resource, index, value, cursor.revision, now)
        change = PropertyModified(self.resource, index, value, cursor.revision, cursor, now)
        for listener in list(self._property_listeners):
            self._call(listener, change)

    def event_occurred(self, event: Event, value: Any) -> None:
        """An exported event was raised."""
        try:
            index = self.type.events.index(event)
        except ValueError:
            return
        cursor = self._next_cursor()
        occurrence = EventOccurred(
            self.resource, index, value, cursor, dt.datetime.now(dt.timezone.utc)
        )
        for listener in list(self._event_listeners):
            self._call(listener, occurrence)

    def _index_of_property(self, property_: Property[Any]) -> int:
        properties = self.type.properties
        for index, candidate in enumerate(properties):
            if candidate is property_:
                return index
        return -1

    def _next_cursor(self) -> ResourceCursor:
        self._cursor = ResourceCursor(self._cursor.generation, self._cursor.revision + 1)
        return self._cursor

    @staticmethod
    def _call(listener: Callable[[Any], None], argument: Any) -> None:
        try:
            listener(argument)
        except Exception:
            logger.exception("A resource change listener failed")

    # ---- listeners ------------------------------------------------------------------------

    def add_property_listener(self, listener: PropertyListener) -> None:
        self._property_listeners.append(listener)

    def remove_property_listener(self, listener: PropertyListener) -> None:
        if listener in self._property_listeners:
            self._property_listeners.remove(listener)

    def add_event_listener(self, listener: EventListener) -> None:
        self._event_listeners.append(listener)

    def remove_event_listener(self, listener: EventListener) -> None:
        if listener in self._event_listeners:
            self._event_listeners.remove(listener)

    def add_destroy_listener(self, listener: Callable[[Resource], None]) -> None:
        self._destroy_listeners.append(listener)

    def remove_destroy_listener(self, listener: Callable[[Resource], None]) -> None:
        if listener in self._destroy_listeners:
            self._destroy_listeners.remove(listener)

    def _on_destroy(self, resource: Resource) -> None:
        self.is_destroyed = True
        for listener in list(self._destroy_listeners):
            self._call(listener, resource)
