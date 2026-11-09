"""Indexed structures: schema-less types whose members travel by byte index.

Port of esiur-ts ``IndexedStructure`` / ``IndexedStructureCodec`` (C# ``IndexedStructure``). A
structure composes as a sparse ``TypedMap<UInt8, dynamic>``: members that are ``None`` are
omitted, and indices the receiver does not know are ignored, so either side can add members
without breaking the other.

Declare one as a keyword-only dataclass whose fields come from :func:`member`::

    @dataclass(kw_only=True)
    class Point(IndexedStructure):
        x: int = member(0, wire=t.i32)
        label: str | None = member(1, None, expect=str)

``wire`` pins the width a number travels in (otherwise it narrows like any dynamic value);
``expect`` is the Python type a received value must have, enforced on decode.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from .guard import ParserError
from .tru import Tru, TruComposite, TruIdentifier
from .typed import TypedList, TypedMap, t
from .widths import Char16, Float32, Int8, Int16, Int32, Int64, UInt8, UInt16, UInt32, UInt64

_KEY = "esiur.index"


@dataclass(frozen=True, slots=True)
class IndexedMember:
    index: int
    name: str
    wire: Tru | None
    expect: tuple[type, ...] | None


def member(
    index: int,
    default: Any = None,
    *,
    wire: Tru | None = None,
    expect: type | tuple[type, ...] | None = None,
) -> Any:
    """A dataclass field that travels at ``index`` (0-255). ``default`` must be immutable."""
    if not 0 <= index <= 255:
        raise ValueError("A structure index must be between 0 and 255.")
    if expect is not None and not isinstance(expect, tuple):
        expect = (expect,)
    info = IndexedMember(index, "", wire, expect)
    return dataclasses.field(default=default, metadata={_KEY: info})


class IndexedStructure:
    """Marker base of indexed structures (subclasses must be dataclasses)."""


T = TypeVar("T", bound=IndexedStructure)


_MEMBERS: dict[type, tuple[IndexedMember, ...]] = {}


def indexed_members(cls: type) -> tuple[IndexedMember, ...]:
    """The members of ``cls`` (inherited ones included), ordered by wire index."""
    cached = _MEMBERS.get(cls)
    if cached is not None:
        return cached
    if not dataclasses.is_dataclass(cls):
        raise TypeError(f"{cls.__name__} must be a dataclass to be an IndexedStructure.")
    found: dict[int, IndexedMember] = {}
    for f in dataclasses.fields(cls):
        info = f.metadata.get(_KEY)
        if info is None:
            continue
        if info.index in found:
            raise ValueError(f"Structure index {info.index} is already used on {cls.__name__}.")
        found[info.index] = IndexedMember(info.index, f.name, info.wire, info.expect)
    ordered = tuple(found[i] for i in sorted(found))
    _MEMBERS[cls] = ordered
    return ordered


def to_indexed_map(value: IndexedStructure) -> TypedMap:
    """The sparse ``TypedMap<UInt8, dynamic>`` a structure composes as."""
    entries: list[tuple[int, Any]] = []
    for m in indexed_members(type(value)):
        raw = getattr(value, m.name)
        if raw is None:
            continue
        entries.append((m.index, _prepare(raw, m.wire)))
    return TypedMap(t.u8, t.dynamic, entries)


_INTEGER_WIDTHS: dict[int, Any] = {
    TruIdentifier.UINT8: UInt8,
    TruIdentifier.INT8: Int8,
    TruIdentifier.CHAR: Char16,
    TruIdentifier.UINT16: UInt16,
    TruIdentifier.INT16: Int16,
    TruIdentifier.UINT32: UInt32,
    TruIdentifier.INT32: Int32,
    TruIdentifier.UINT64: UInt64,
    TruIdentifier.INT64: Int64,
}


def _prepare(value: Any, wire: Tru | None = None) -> Any:
    if wire is not None:
        ident = wire.identifier
        wrapper = _INTEGER_WIDTHS.get(ident)
        if wrapper is not None:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"Indexed {TruIdentifier(ident).name} value must be an integer.")
            return wrapper(value)
        if ident == TruIdentifier.FLOAT32:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError("Indexed FLOAT32 value must be a number.")
            return Float32(float(value))
        if isinstance(wire, TruComposite):
            if ident == TruIdentifier.TYPED_LIST:
                if not isinstance(value, (list, tuple)):
                    raise TypeError("Indexed TYPED_LIST value must be a list.")
                return TypedList(wire.sub_types[0], [_prepare(item) for item in value])
            if ident == TruIdentifier.TYPED_MAP:
                if not isinstance(value, Mapping):
                    raise TypeError("Indexed TYPED_MAP value must be a mapping.")
                return TypedMap(
                    wire.sub_types[0],
                    wire.sub_types[1],
                    [(_prepare(k), _prepare(v)) for k, v in value.items()],
                )
    if isinstance(value, IndexedStructure):
        return to_indexed_map(value)
    if isinstance(value, (list, tuple)):
        return [_prepare(item) for item in value]
    return value


def check_member(m: IndexedMember, value: Any, owner: str) -> None:
    """Reject a received value of the wrong Python type (``None`` is always accepted)."""
    if value is None or m.expect is None:
        return
    if isinstance(value, bool) and bool not in m.expect:
        ok = False  # a bool is an int in Python but never an integer on the wire
    else:
        ok = isinstance(value, m.expect)
    if not ok:
        names = "/".join(x.__name__ for x in m.expect)
        raise ParserError(
            f"{owner}.{m.name} must be {names}, received {type(value).__name__}."
        )


def from_indexed_map(cls: type[T], value: Any) -> T:
    """Build a ``cls`` from a decoded indexed-map payload.

    Version tolerant: members missing from the map keep their default, and entries with no
    matching member are ignored.
    """
    if not isinstance(value, Mapping):
        raise ParserError(f"{cls.__name__} must decode from a map, received {type(value).__name__}.")
    values: dict[str, Any] = {}
    for m in indexed_members(cls):
        if m.index not in value:
            continue
        item = value[m.index]
        if item is None:
            continue
        check_member(m, item, cls.__name__)
        values[m.name] = item
    return cls(**values)
