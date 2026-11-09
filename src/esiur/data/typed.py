"""Explicitly typed collections and the ``t`` type descriptors.

Python values carry no wire width, so where the wire needs a type (a typed list, map or
tuple) you say it with a descriptor::

    compose(TypedList(t.i32, [1, 2, 3]))
    compose(TypedMap(t.string, t.f64, {"pi": 3.14}))
    compose(TypedTuple([t.i32, t.string], (1, "a")))

Decoding returns plain ``list``, ``dict`` and ``tuple`` values.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .tru import Tru, TruComposite, TruIdentifier, TruPrimitive, tuple_identifier


class _Types:
    """Namespace of ready-made Trus: ``t.i32``, ``t.list(t.string)``, ..."""

    void = TruPrimitive(TruIdentifier.VOID)
    dynamic = TruPrimitive(TruIdentifier.DYNAMIC)
    bool = TruPrimitive(TruIdentifier.BOOL)
    char = TruPrimitive(TruIdentifier.CHAR)
    u8 = TruPrimitive(TruIdentifier.UINT8)
    i8 = TruPrimitive(TruIdentifier.INT8)
    u16 = TruPrimitive(TruIdentifier.UINT16)
    i16 = TruPrimitive(TruIdentifier.INT16)
    u32 = TruPrimitive(TruIdentifier.UINT32)
    i32 = TruPrimitive(TruIdentifier.INT32)
    u64 = TruPrimitive(TruIdentifier.UINT64)
    i64 = TruPrimitive(TruIdentifier.INT64)
    u128 = TruPrimitive(TruIdentifier.UINT128)
    i128 = TruPrimitive(TruIdentifier.INT128)
    f32 = TruPrimitive(TruIdentifier.FLOAT32)
    f64 = TruPrimitive(TruIdentifier.FLOAT64)
    decimal = TruPrimitive(TruIdentifier.DECIMAL)
    string = TruPrimitive(TruIdentifier.STRING)
    raw_data = TruPrimitive(TruIdentifier.RAW_DATA)
    datetime = TruPrimitive(TruIdentifier.DATETIME)
    resource = TruPrimitive(TruIdentifier.RESOURCE)
    record = TruPrimitive(TruIdentifier.RECORD)

    @staticmethod
    def list(element: Tru) -> TruComposite:
        return TruComposite(TruIdentifier.TYPED_LIST, (element,))

    @staticmethod
    def map(key: Tru, value: Tru) -> TruComposite:
        return TruComposite(TruIdentifier.TYPED_MAP, (key, value))

    @staticmethod
    def tuple(*sub_types: Tru) -> TruComposite:
        return TruComposite(tuple_identifier(len(sub_types)), tuple(sub_types))

    @staticmethod
    def nullable(type_: Tru) -> Tru:
        return type_.to_nullable()


t = _Types()


@dataclass(frozen=True, slots=True)
class TypedList:
    """A list whose element type is declared. Integer element types use the compact
    group-varint encoding."""

    element: Tru
    values: Sequence[Any]


@dataclass(frozen=True, slots=True)
class TypedMap:
    """A map with declared key and value types."""

    key_type: Tru
    value_type: Tru
    entries: tuple[tuple[Any, Any], ...] = field(default=())

    def __init__(
        self,
        key_type: Tru,
        value_type: Tru,
        entries: Mapping[Any, Any] | Sequence[tuple[Any, Any]] = (),
    ) -> None:
        pairs = entries.items() if isinstance(entries, Mapping) else entries
        object.__setattr__(self, "key_type", key_type)
        object.__setattr__(self, "value_type", value_type)
        object.__setattr__(self, "entries", tuple((k, v) for k, v in pairs))


@dataclass(frozen=True, slots=True)
class TypedTuple:
    """A tuple of two to seven elements with declared types."""

    elements: Sequence[Tru]
    values: Sequence[Any]

    def __post_init__(self) -> None:
        tuple_identifier(len(self.elements))
        if len(self.elements) != len(self.values):
            raise ValueError("Tuple element-type count must match value count.")
