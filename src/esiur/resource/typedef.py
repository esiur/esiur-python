"""A resource type's exported surface, as members addressable by index and by name.

This is the view of a :class:`~esiur.data.TypeDefInfo` that clients and servers work with: the
wire structure stays the single source of truth, and the lookups are built once.
"""

from __future__ import annotations

from typing import TypeVar

from esiur.data import (
    EventDefFlags,
    EventDefInfo,
    FunctionDefFlags,
    FunctionDefInfo,
    PropertyDefFlags,
    PropertyDefInfo,
    TypeDefInfo,
)

_M = TypeVar("_M", PropertyDefInfo, FunctionDefInfo, EventDefInfo)


class TypeDef:
    """The members of one type. Names are matched exactly first, then ignoring case and
    underscores, so ``say_hi`` finds a member a camelCase or PascalCase peer calls ``sayHi``
    or ``SayHi``."""

    def __init__(self, info: TypeDefInfo) -> None:
        self.info = info
        self.properties = tuple(info.properties or ())
        self.functions = tuple(info.functions or ())
        self.events = tuple(info.events or ())
        self.constants = tuple(info.constants or ())
        self._properties_by_index = {m.index: m for m in self.properties}
        self._functions_by_index = {m.index: m for m in self.functions}
        self._events_by_index = {m.index: m for m in self.events}

    @property
    def id(self) -> int:
        return self.info.id

    @property
    def name(self) -> str:
        return self.info.name

    def property_by_index(self, index: int) -> PropertyDefInfo | None:
        return self._properties_by_index.get(index)

    def function_by_index(self, index: int) -> FunctionDefInfo | None:
        return self._functions_by_index.get(index)

    def event_by_index(self, index: int) -> EventDefInfo | None:
        return self._events_by_index.get(index)

    def find_property(self, name: str) -> PropertyDefInfo | None:
        return _find(self.properties, name)

    def find_function(self, name: str) -> FunctionDefInfo | None:
        return _find(self.functions, name)

    def find_event(self, name: str) -> EventDefInfo | None:
        return _find(self.events, name)

    @staticmethod
    def is_read_only(property: PropertyDefInfo) -> bool:
        return bool(property.flags & PropertyDefFlags.READ_ONLY)

    @staticmethod
    def is_static(function: FunctionDefInfo) -> bool:
        return bool(function.flags & FunctionDefFlags.STATIC)

    @staticmethod
    def is_subscribable(event: EventDefInfo) -> bool:
        """Whether the peer pushes this event only to subscribers (the default); an
        auto-delivered event reaches every attached connection."""
        return not event.flags & EventDefFlags.AUTO_DELIVERED

    @staticmethod
    def is_historical(event: EventDefInfo) -> bool:
        return bool(event.flags & EventDefFlags.HISTORICAL)

    def __repr__(self) -> str:
        return f"TypeDef({self.name!r}, id={self.id})"


def _normalize(name: str) -> str:
    return name.replace("_", "").lower()


def _find(members: tuple[_M, ...], name: str) -> _M | None:
    for member in members:
        if member.name == name:
            return member
    wanted = _normalize(name)
    matches = [member for member in members if _normalize(member.name) == wanted]
    if len(matches) > 1:
        raise LookupError(f"'{name}' matches more than one member: {[m.name for m in matches]}.")
    return matches[0] if matches else None
