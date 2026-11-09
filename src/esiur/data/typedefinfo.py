"""Wire shapes of type definitions (port of esiur-ts ``data/types/*`` / C# ``TypeDefInfo``).

A ``TypeDefInfo`` is the payload of a ``TypeDef`` TDU (0x81): an indexed structure describing a
resource, record or enum, with one nested structure per property, function, event and constant.
Numeric fields hold plain ``int`` values (the enums below are ``IntEnum``/``IntFlag``, so a value
a newer peer sends that this port does not know is kept rather than rejected).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

from .guard import ParserError
from .structure import IndexedStructure, from_indexed_map, member
from .tru import Tru
from .typed import t


class TypeDefKind(enum.IntEnum):
    RESOURCE = 0
    RECORD = 1
    ENUM = 2
    FUNCTION = 3


class OrderingControl(enum.IntEnum):
    STRICT = 0
    RELAXED = 1
    LATEST_ONLY = 2


class StreamMode(enum.IntEnum):
    NONE = 0
    PUSH = 1
    PULL = 2


class OperationEffects(enum.IntFlag):
    NONE = 0x00
    MODIFIES_STATE = 0x01
    CREATES_RESOURCE = 0x02
    DELETES_RESOURCE = 0x04
    EXTERNAL = 0x08
    EMITS_EVENTS = 0x10
    UNKNOWN = 0x80


class PropertyDefFlags(enum.IntFlag):
    NONE = 0x00
    INHERITED = 0x01
    DEPRECATED = 0x02
    READ_ONLY = 0x04
    CONSTANT = 0x08
    VOLATILE = 0x10
    HISTORICAL = 0x20


class FunctionDefFlags(enum.IntFlag):
    NONE = 0x00
    INHERITED = 0x01
    DEPRECATED = 0x02
    STATIC = 0x04
    READ_ONLY = 0x08
    IDEMPOTENT = 0x10
    CANCELLABLE = 0x20
    PAUSABLE = 0x40


class EventDefFlags(enum.IntFlag):
    NONE = 0x00
    INHERITED = 0x01
    DEPRECATED = 0x02
    AUTO_DELIVERED = 0x04
    HISTORICAL = 0x08


class ConstantDefFlags(enum.IntFlag):
    NONE = 0x00
    INHERITED = 0x01
    DEPRECATED = 0x02


class ArgumentDefFlags(enum.IntFlag):
    NONE = 0x00
    OPTIONAL = 0x01
    VARIADIC = 0x02


@dataclass(kw_only=True)
class MemberDefInfo(IndexedStructure):
    """What every member kind (property, function, event, constant, argument) shares."""

    index: int = member(0x00, 0, expect=int)
    name: str = member(0x01, "", expect=str)
    #: Raw flags byte; interpret it with the subclass's own ``*DefFlags``.
    flags: int = member(0x02, 0, expect=int)

    description: str | None = member(0x20, expect=str)
    usage: str | None = member(0x21, expect=str)
    examples: list[Any] | None = member(0x22, expect=list)
    tags: list[str] | None = member(0x23, expect=list)
    unit: str | None = member(0x24, expect=str)
    minimum: Any = member(0x25)
    maximum: Any = member(0x26)
    allowed_values: list[Any] | None = member(0x27, expect=list)
    pattern: str | None = member(0x28, expect=str)
    format: str | None = member(0x29, expect=str)
    preconditions: list[str] | None = member(0x2A, expect=list)
    postconditions: list[str] | None = member(0x2B, expect=list)
    #: :class:`OperationEffects` bitmask.
    effects: int = member(0x2C, 0, expect=int)
    warnings: list[str] | None = member(0x2D, expect=list)
    related_members: list[int] | None = member(0x2E, expect=list)
    deprecation_message: str | None = member(0x2F, expect=str)
    annotations: dict[str, str] | None = member(0x30, expect=dict)


@dataclass(kw_only=True)
class PropertyDefInfo(MemberDefInfo):
    value_type: Tru | None = member(0x03, expect=Tru)
    ordering_control: int = member(0x04, OrderingControl.STRICT, expect=int)
    history_control: int = member(0x05, 0, expect=int)
    default_value: Any = member(0x06)


@dataclass(kw_only=True)
class ArgumentDefInfo(MemberDefInfo):
    """A function argument; its name comes from the inherited ``name``."""

    value_type: Tru | None = member(0x03, expect=Tru)
    default_value: Any = member(0x04)


@dataclass(kw_only=True)
class FunctionDefInfo(MemberDefInfo):
    arguments: list[ArgumentDefInfo] | None = member(0x03, expect=list)
    return_type: Tru | None = member(0x04, expect=Tru)
    stream_mode: int = member(0x05, StreamMode.NONE, expect=int)


@dataclass(kw_only=True)
class EventDefInfo(MemberDefInfo):
    argument_type: Tru | None = member(0x03, expect=Tru)
    argument_name: str | None = member(0x04, expect=str)
    ordering_control: int = member(0x05, OrderingControl.STRICT, expect=int)
    history_control: int = member(0x06, 0, expect=int)


@dataclass(kw_only=True)
class ConstantDefInfo(MemberDefInfo):
    value_type: Tru | None = member(0x03, expect=Tru)
    value: Any = member(0x04)


_UINT64_MAX = (1 << 64) - 1


@dataclass(kw_only=True)
class TypeDefInfo(IndexedStructure):
    """A type definition as it travels in a ``TypeDef`` TDU (0x81)."""

    version: int = member(0x00, 0, wire=t.i32, expect=int)
    id: int = member(0x01, 0, wire=t.u64, expect=int)
    name: str = member(0x02, "", expect=str)
    namespace: str | None = member(0x03, expect=str)
    kind: int = member(0x04, TypeDefKind.RESOURCE, wire=t.u8, expect=int)
    parent: int | None = member(0x05, wire=t.u64, expect=int)
    properties: list[PropertyDefInfo] | None = member(0x06, expect=list)
    functions: list[FunctionDefInfo] | None = member(0x07, expect=list)
    events: list[EventDefInfo] | None = member(0x08, expect=list)
    constants: list[ConstantDefInfo] | None = member(0x09, expect=list)
    #: Id-independent hash of the definition, used to validate cached definitions.
    signature: int | None = member(0x0A, wire=t.u64, expect=int)

    usage: str | None = member(0x20, expect=str)
    description: str | None = member(0x21, expect=str)
    example: Any = member(0x22)
    category: str | None = member(0x23, expect=str)
    since: str | None = member(0x24, expect=str)
    annotations: dict[str, str] | None = member(0x25, wire=t.map(t.string, t.string), expect=dict)

    @classmethod
    def from_map(cls, value: Any) -> TypeDefInfo:
        """Build a ``TypeDefInfo`` (and its nested member infos) from a decoded payload."""
        info = from_indexed_map(cls, value)
        for field_name in ("id", "parent", "signature"):
            number = getattr(info, field_name)
            if number is not None and not 0 <= number <= _UINT64_MAX:
                raise ParserError(f"TypeDefInfo.{field_name} must fit in 64 bits.")
        info.properties = _hydrate_list(info.properties, PropertyDefInfo)
        info.events = _hydrate_list(info.events, EventDefInfo)
        info.constants = _hydrate_list(info.constants, ConstantDefInfo)
        functions = _hydrate_list(info.functions, FunctionDefInfo)
        if functions is not None:
            for function in functions:
                function.arguments = _hydrate_list(function.arguments, ArgumentDefInfo)
        info.functions = functions
        return info


def _hydrate_list(items: list[Any] | None, cls: type[Any]) -> list[Any] | None:
    if items is None:
        return None
    return [from_indexed_map(cls, item) for item in items]


__all__ = [
    "ArgumentDefFlags", "ArgumentDefInfo", "ConstantDefFlags", "ConstantDefInfo",
    "EventDefFlags", "EventDefInfo", "FunctionDefFlags", "FunctionDefInfo", "MemberDefInfo",
    "OperationEffects", "OrderingControl", "PropertyDefFlags", "PropertyDefInfo", "StreamMode",
    "TypeDefInfo", "TypeDefKind",
]
