"""Compose Python values into TDUs and parse TDUs back into Python values.

Python <-> wire mapping for self-describing (dynamic) values::

    None                         Null
    bool                         True / False
    int                          narrowest of Int8/16/32/64 (UInt64 above 2**63; wrap in
                                 Int128/UInt128 or the width classes to pin a width)
    float                        Infinity token for NaN/inf, else the narrowest of
                                 Int8/Int16/Int32/Float32/Float64 that holds it exactly
    str                          String (UTF-8)
    bytes / bytearray            RawData
    datetime                     DateTime (naive values are taken as UTC)
    uuid.UUID                    UUID
    decimal.Decimal              Decimal128 (scale 0..28, 96-bit mantissa)
    list / tuple                 List
    dict                         Map
    ResourceLink                 ResourceLink
    TypedList / TypedMap /       Typed (0x80) with TypedList / TypedMap / TupleN metadata;
    TypedTuple                   decode to list / dict / tuple
    Tru                          TRU (0x82)

    IndexedStructure             Typed (0x80) ``TypedMap<UInt8, dynamic>``, sparse
    TypeDefInfo                  TypeDef (0x81) wrapping its structure
    registered record / enum     Typed (0x80) with a ``TruTypeDef``; needs ``types=`` (a
                                 :class:`~esiur.data.registry.TypeRegistry`) on both sides

Resources and resource references that need a connection are not decoded here.
"""

from __future__ import annotations

import contextvars
import datetime as _dt
import decimal
import math
import struct
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from .guard import (
    DEFAULT_MAXIMUM_ALLOCATION_SIZE,
    DEFAULT_MAXIMUM_COLLECTION_ITEMS,
    DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
    DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
    DEFAULT_MAXIMUM_VALUE_DEPTH,
    ParserError,
    ParserLimitError,
    ensure_allocation,
    ensure_collection_count,
)
from .gvwie import (
    GROUP_INT16,
    GROUP_INT32,
    GROUP_INT64,
    GROUP_UINT16,
    GROUP_UINT32,
    GROUP_UINT64,
    GroupCodec,
)
from .registry import TypeDefinition, TypeRegistry
from .structure import IndexedStructure, to_indexed_map
from .tdu import ParsedTdu, TduClass, compose_tdu, framed_header
from .tdu import TduIdentifier as Id
from .tru import TUPLE_IDENTIFIERS, Tru, TruComposite, TruIdentifier, TruTypeDef, tuple_identifier
from .typed import TypedList, TypedMap, TypedTuple
from .typedefinfo import TypeDefInfo, TypeDefKind
from .values import NotModified, ResourceId, ResourceLink
from .widths import (
    Char16,
    Float32,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    UInt128,
)

_EPOCH = _dt.datetime(1, 1, 1, tzinfo=_dt.timezone.utc)
_TICKS_PER_SECOND = 10_000_000
_INT64_MIN, _INT64_MAX = -(1 << 63), (1 << 63) - 1
_UINT64_MAX = (1 << 64) - 1
_TWO_96 = 1 << 96


# ---------------------------------------------------------------- compose --


def _signed(value: int, *widths: int) -> bytes | None:
    for width in widths:
        low, high = -(1 << (8 * width - 1)), (1 << (8 * width - 1)) - 1
        if low <= value <= high:
            ident = {1: Id.INT8, 2: Id.INT16, 4: Id.INT32, 8: Id.INT64}[width]
            return compose_tdu(ident, value.to_bytes(width, "little", signed=True))
    return None


def _unsigned(value: int, *widths: int) -> bytes | None:
    for width in widths:
        if value < (1 << (8 * width)):
            ident = {1: Id.UINT8, 2: Id.UINT16, 4: Id.UINT32, 8: Id.UINT64}[width]
            return compose_tdu(ident, value.to_bytes(width, "little"))
    return None


def _compose_signed(value: int, max_width: int) -> bytes:
    widths = tuple(w for w in (1, 2, 4, 8) if w <= max_width)
    out = _signed(value, *widths)
    if out is None:
        raise OverflowError(f"value {value} does not fit in Int{max_width * 8}")
    return out


def _compose_unsigned(value: int, max_width: int) -> bytes:
    if value < 0:
        raise OverflowError(f"value {value} is negative; unsigned expected")
    widths = tuple(w for w in (1, 2, 4, 8) if w <= max_width)
    out = _unsigned(value, *widths)
    if out is None:
        raise OverflowError(f"value {value} does not fit in UInt{max_width * 8}")
    return out


def _compose_int(value: int) -> bytes:
    if _INT64_MIN <= value <= _INT64_MAX:
        return _compose_signed(value, 8)
    if 0 <= value <= _UINT64_MAX:
        return _compose_unsigned(value, 8)
    raise OverflowError("integer exceeds the 64-bit range; wrap it in Int128 or UInt128")


def _compose_float(value: float, allow_float32_exact: bool = True) -> bytes:
    if math.isnan(value) or math.isinf(value):
        return compose_tdu(Id.INFINITY)
    if value == math.trunc(value):
        out = _signed(int(value), 1, 2, 4)
        if out is not None:
            return out
    if allow_float32_exact:
        try:
            packed = struct.pack("<f", value)
        except OverflowError:
            packed = None
        if packed is not None and struct.unpack("<f", packed)[0] == value:
            return compose_tdu(Id.FLOAT32, packed)
    return compose_tdu(Id.FLOAT64, struct.pack("<d", value))


def _compose_float32(value: float) -> bytes:
    if math.isnan(value) or math.isinf(value):
        return compose_tdu(Id.INFINITY)
    if value == math.trunc(value):
        out = _signed(int(value), 1, 2)
        if out is not None:
            return out
    return compose_tdu(Id.FLOAT32, struct.pack("<f", value))


def _to_ticks(value: _dt.datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * _TICKS_PER_SECOND + delta.microseconds * 10


def _compose_decimal(value: decimal.Decimal) -> bytes:
    if not value.is_finite():
        raise ValueError("Decimal128 cannot represent NaN or infinity")
    sign, digits, exponent = value.as_tuple()
    assert isinstance(exponent, int)
    mantissa = int("".join(map(str, digits)) or "0")
    scale = 0
    if exponent > 0:
        mantissa *= 10**exponent
    else:
        scale = -exponent
    if scale > 28 or mantissa >= _TWO_96:
        raise OverflowError("value does not fit in Decimal128 (96-bit mantissa, scale <= 28)")
    negative = bool(sign) and mantissa != 0
    if scale == 0:
        out = _signed(-mantissa if negative else mantissa, 1, 2, 4, 8)
        if out is not None:
            return out
    flags = (scale << 16) | (0x80000000 if negative else 0)
    lo, mid, hi = mantissa & 0xFFFFFFFF, (mantissa >> 32) & 0xFFFFFFFF, mantissa >> 64
    return compose_tdu(Id.DECIMAL128, struct.pack("<4I", flags, hi, lo, mid))


_TYPES: contextvars.ContextVar[TypeRegistry | None] = contextvars.ContextVar(
    "esiur_compose_types", default=None
)


#: Maps an object that stands for a resource to the reference to write, or ``None`` for any
#: other object. The connection supplies one, since which side owns a resource is its business.
ResourceComposer = Callable[[Any], ResourceId | None]

_RESOURCES: contextvars.ContextVar[ResourceComposer | None] = contextvars.ContextVar(
    "esiur_compose_resources", default=None
)


def compose(
    value: Any,
    *,
    types: TypeRegistry | None = None,
    resources: ResourceComposer | None = None,
) -> bytes:
    """Encode ``value`` as one self-describing TDU. Registered records and enums need the
    ``types`` registry that registered them; ``resources`` recognises resource objects (a
    :class:`ResourceId` is always written as the reference it is)."""
    types_token = _TYPES.set(types)
    resources_token = _RESOURCES.set(resources)
    try:
        return _compose_tdu(value, 0).composed
    finally:
        _RESOURCES.reset(resources_token)
        _TYPES.reset(types_token)


_RESOURCE_IDENTIFIERS = (
    (0xFF, Id.LOCAL_RESOURCE8, Id.REMOTE_RESOURCE8, "<B"),
    (0xFFFF, Id.LOCAL_RESOURCE16, Id.REMOTE_RESOURCE16, "<H"),
    (0xFFFF_FFFF, Id.LOCAL_RESOURCE32, Id.REMOTE_RESOURCE32, "<I"),
)


def _as_resource(value: Any) -> ResourceId | None:
    if isinstance(value, ResourceId):
        return value
    composer = _RESOURCES.get()
    return composer(value) if composer is not None else None


def _compose_resource(reference: ResourceId) -> _Tdu:
    """A resource reference in the narrowest of the 8, 16 and 32-bit forms."""
    for limit, local, remote, fmt in _RESOURCE_IDENTIFIERS:
        if 0 <= reference.id <= limit:
            return _make(local if reference.local else remote, struct.pack(fmt, reference.id))
    raise ValueError("A resource id must fit in 32 bits.")


def _resource_list(items: Sequence[Any]) -> _Tdu | None:
    """A non-empty list made only of resources is written as a ``ResourceList``."""
    if not items or _as_resource(items[0]) is None:
        return None
    references = [_as_resource(item) for item in items]
    if any(reference is None for reference in references):
        return None
    return _make(
        Id.RESOURCE_LIST,
        b"".join(_compose_resource(r).composed for r in references if r is not None),
    )


@dataclass(slots=True)
class _Tdu:
    """A composed TDU plus what a parent needs to know about it: its identifier, its type
    metadata (plain ``Typed`` only) and where the value payload starts."""

    composed: bytes
    identifier: int
    metadata: Tru | None = None
    content_offset: int = 0

    def match_type(self, other: _Tdu) -> bool:
        """Port of ``Tdu.matchType``: whether ``other`` allows this one to be written as a
        ``TypeContinuation`` (same identifier, and for plain Typed the same metadata)."""
        if self.identifier != other.identifier or self.identifier >> 6 != TduClass.TYPED:
            return False
        if self.identifier != Id.TYPED:
            return True  # TypeDef / TRU carry no metadata: the identifier says it all
        return (
            self.metadata is not None
            and other.metadata is not None
            and self.metadata.match(other.metadata)
        )


def _make(identifier: int, payload: bytes, metadata: Tru | None = None) -> _Tdu:
    if identifier >> 6 == TduClass.FIXED:
        return _Tdu(bytes([identifier]) + payload, identifier, None, 1)
    if identifier != Id.TYPED:
        header = framed_header(identifier, len(payload))
        return _Tdu(header + payload, identifier, None, len(header))
    if metadata is None:
        raise ValueError("Metadata must be provided for typed TDUs.")
    meta = metadata.compose()
    header = framed_header(identifier, len(meta) + len(payload))
    return _Tdu(header + meta + payload, identifier, metadata, len(header) + len(meta))


def _wrap(composed: bytes) -> _Tdu:
    first = composed[0]
    return _Tdu(composed, first if first >> 6 == TduClass.FIXED else first & 0xC7)


def _compose_tdu(value: Any, depth: int) -> _Tdu:
    if depth > DEFAULT_MAXIMUM_VALUE_DEPTH:
        raise ParserLimitError("Value nesting is too deep.")
    if isinstance(value, TypedList):
        payload = _compose_typed_array(value.values, value.element, depth)
        return _make(Id.TYPED, payload, TruComposite(TruIdentifier.TYPED_LIST, (value.element,)))
    if isinstance(value, TypedMap):
        return _compose_typed_map(value, depth)
    if isinstance(value, TypedTuple):
        return _compose_typed_tuple(value, depth)
    if isinstance(value, Tru):
        return _make(Id.TRU, value.compose())
    if isinstance(value, TypeDefInfo):
        # The TypeDef slot wraps the structure's complete Typed TDU.
        return _make(Id.TYPEDEF, _compose_tdu(to_indexed_map(value), depth + 1).composed)
    if isinstance(value, IndexedStructure):
        return _compose_tdu(to_indexed_map(value), depth + 1)
    types = _TYPES.get()
    if types is not None:
        definition = types.definition_of(value)
        if definition is not None:
            return _compose_defined(value, definition, depth)
    if isinstance(value, dict):
        return _compose_array([x for pair in value.items() for x in pair], Id.MAP, depth)
    if isinstance(value, (list, tuple)):
        return _resource_list(value) or _compose_array(value, Id.LIST, depth)
    reference = _as_resource(value)
    if reference is not None:
        return _compose_resource(reference)
    return _wrap(_compose_plain(value))


def _compose_defined(value: Any, definition: TypeDefinition, depth: int) -> _Tdu:
    """A registered record (each property in definition order) or enum (its constant index)."""
    metadata = TruTypeDef(definition.id)
    if definition.kind == TypeDefKind.ENUM:
        index = definition.constant_index(value)
        if index is None:
            return _wrap(compose_tdu(Id.NULL))  # not a constant of the enum: like esiur-ts
        return _make(Id.TYPED, bytes([index]), metadata)
    parts: list[bytes] = []
    for prop in definition.properties:
        tdu = _compose_tdu(getattr(value, prop.name), depth + 1)
        if (
            tdu.identifier == Id.TYPED
            and prop.value_type is not None
            and tdu.metadata is not None
            and prop.value_type.match(tdu.metadata)
        ):
            parts.append(compose_tdu(Id.TYPE_OF_TARGET, tdu.composed[tdu.content_offset :]))
        else:
            parts.append(tdu.composed)
    return _make(Id.TYPED, b"".join(parts), metadata)


def _compose_array(items: Iterable[Any], identifier: int, depth: int) -> _Tdu:
    """A self-describing array. Consecutive Typed elements of one shape collapse their
    metadata into a ``TypeContinuation``, as esiur-ts and esiur-dotnet do."""
    parts: list[bytes] = []
    previous: _Tdu | None = None
    for item in items:
        tdu = _compose_tdu(item, depth + 1)
        if previous is not None and tdu.match_type(previous):
            parts.append(compose_tdu(Id.TYPE_CONTINUATION, tdu.composed[tdu.content_offset :]))
        else:
            parts.append(tdu.composed)
        previous = tdu
    return _make(identifier, b"".join(parts))


_GVWIE: dict[int, tuple[GroupCodec, int]] = {
    TruIdentifier.INT16: (GROUP_INT16, 2),
    TruIdentifier.INT32: (GROUP_INT32, 4),
    TruIdentifier.INT64: (GROUP_INT64, 8),
    TruIdentifier.UINT16: (GROUP_UINT16, 2),
    TruIdentifier.UINT32: (GROUP_UINT32, 4),
    TruIdentifier.UINT64: (GROUP_UINT64, 8),
}


def _typed_int(value: Any, kind: str, low: int, high: int) -> int:
    candidate = getattr(value, "value", value)
    if kind == "Char" and isinstance(candidate, str) and len(candidate) == 1:
        candidate = ord(candidate)
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        raise TypeError(f"Typed {kind} values must be integers; received {type(value).__name__}.")
    if not low <= candidate <= high:
        raise OverflowError(f"value {candidate} does not fit in {kind}")
    return candidate


def _compose_typed_element(value: Any, element: Tru, depth: int) -> _Tdu:
    """Primitive elements keep the collection's declared width instead of narrowing."""
    ident = element.identifier
    if ident == TruIdentifier.UINT8:
        return _make(Id.UINT8, bytes([_typed_int(value, "UInt8", 0, 0xFF)]))
    if ident == TruIdentifier.INT8:
        v = _typed_int(value, "Int8", -0x80, 0x7F)
        return _make(Id.INT8, v.to_bytes(1, "little", signed=True))
    if ident == TruIdentifier.CHAR:
        v = _typed_int(value, "Char", 0, 0xFFFF)
        return _make(Id.CHAR16, v.to_bytes(2, "little"))
    return _compose_tdu(value, depth + 1)


def _compose_typed_array(values: Sequence[Any], element: Tru, depth: int) -> bytes:
    spec = _GVWIE.get(element.identifier)
    if spec is not None:
        return spec[0].encode(getattr(v, "value", v) for v in values)

    parts: list[bytes] = []
    previous: _Tdu | None = None
    for value in values:
        tdu = _compose_typed_element(value, element, depth)
        if tdu.identifier == Id.TYPED and tdu.metadata is not None and element.match(tdu.metadata):
            # The element has exactly the declared type: its metadata is implied.
            parts.append(compose_tdu(Id.TYPE_OF_TARGET, tdu.composed[tdu.content_offset :]))
        elif previous is not None and tdu.match_type(previous):
            parts.append(compose_tdu(Id.TYPE_CONTINUATION, tdu.composed[tdu.content_offset :]))
        else:
            parts.append(tdu.composed)
        previous = tdu
    return b"".join(parts)


def _compose_typed_map(value: TypedMap, depth: int) -> _Tdu:
    keys = _compose_typed_array([k for k, _ in value.entries], value.key_type, depth)
    values = _compose_typed_array([v for _, v in value.entries], value.value_type, depth)
    payload = compose_tdu(Id.TYPE_OF_TARGET, keys) + compose_tdu(Id.TYPE_OF_TARGET, values)
    metadata = TruComposite(TruIdentifier.TYPED_MAP, (value.key_type, value.value_type))
    return _make(Id.TYPED, payload, metadata)


def _compose_typed_tuple(value: TypedTuple, depth: int) -> _Tdu:
    parts: list[bytes] = []
    for target, item in zip(value.elements, value.values, strict=True):
        tdu = _compose_tdu(item, depth + 1)
        if tdu.identifier == Id.TYPED and tdu.metadata is not None and target.match(tdu.metadata):
            parts.append(compose_tdu(Id.TYPE_OF_TARGET, tdu.composed[tdu.content_offset :]))
        else:
            parts.append(tdu.composed)
    metadata = TruComposite(tuple_identifier(len(value.elements)), tuple(value.elements))
    return _make(Id.TYPED, b"".join(parts), metadata)


def _compose_plain(value: Any) -> bytes:
    if value is None:
        return compose_tdu(Id.NULL)
    if value is NotModified:
        return compose_tdu(Id.NOT_MODIFIED)

    # Width wrappers first: they are not ints, but Int128/UInt128 are.
    if isinstance(value, Int128):
        return compose_tdu(Id.INT128, int(value).to_bytes(16, "little", signed=True))
    if isinstance(value, UInt128):
        return compose_tdu(Id.UINT128, int(value).to_bytes(16, "little"))
    if isinstance(value, bool):
        return compose_tdu(Id.TRUE if value else Id.FALSE)
    if isinstance(value, int):
        return _compose_int(value)
    if isinstance(value, float):
        return _compose_float(value)
    if isinstance(value, UInt8):
        return _compose_unsigned(value.value, 1)
    if isinstance(value, Int8):
        return compose_tdu(Id.INT8, (value.value & 0xFF).to_bytes(1, "little"))
    if isinstance(value, UInt16):
        return _compose_unsigned(value.value, 2)
    if isinstance(value, Int16):
        return _compose_signed(value.value, 2)
    if isinstance(value, UInt32):
        return _compose_unsigned(value.value, 4)
    if isinstance(value, Int32):
        return _compose_signed(value.value, 4)
    if isinstance(value, UInt64):
        return _compose_unsigned(value.value, 8)
    if isinstance(value, Int64):
        return _compose_signed(value.value, 8)
    if isinstance(value, Float32):
        return _compose_float32(value.value)
    if isinstance(value, Char16):
        return compose_tdu(Id.CHAR16, (value.value & 0xFFFF).to_bytes(2, "little"))

    if isinstance(value, ResourceLink):  # before str: it is a str subclass
        return compose_tdu(Id.RESOURCE_LINK, value.encode("utf-8"))
    if isinstance(value, str):
        return compose_tdu(Id.STRING, value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return compose_tdu(Id.RAW_DATA, bytes(value))
    if isinstance(value, _dt.datetime):
        return compose_tdu(Id.DATETIME, _to_ticks(value).to_bytes(8, "little", signed=True))
    if isinstance(value, uuid.UUID):
        return compose_tdu(Id.UUID, value.bytes)
    if isinstance(value, decimal.Decimal):
        return _compose_decimal(value)

    raise TypeError(f"Cannot compose a value of type {type(value).__name__}.")


# ------------------------------------------------------------------ parse --


def _fixed(fmt: str) -> Callable[[ParsedTdu], Any]:
    size = struct.calcsize(fmt)

    def parser(t: ParsedTdu) -> Any:
        return struct.unpack_from(fmt, t.data, t.payload_offset)[0] if size else None

    return parser


def _int_le(signed: bool) -> Callable[[ParsedTdu], int]:
    return lambda t: int.from_bytes(t.payload, "little", signed=signed)


def _datetime(t: ParsedTdu) -> _dt.datetime:
    ticks = struct.unpack_from("<q", t.data, t.payload_offset)[0]
    try:
        return _EPOCH + _dt.timedelta(microseconds=ticks // 10)
    except OverflowError as error:
        raise ParserError("DateTime is out of range.") from error


def _decimal(t: ParsedTdu) -> decimal.Decimal:
    flags, hi, lo, mid = struct.unpack_from("<4I", t.data, t.payload_offset)
    scale = (flags >> 16) & 0xFF
    if scale > 28:
        raise ParserError("Decimal128 scale is out of range.")
    mantissa = (hi << 64) | (mid << 32) | lo
    digits = tuple(int(c) for c in str(mantissa))
    return decimal.Decimal((1 if flags & 0x80000000 and mantissa else 0, digits, -scale))


def _resource(local: bool, fmt: str) -> Callable[[ParsedTdu], ResourceId]:
    return lambda t: ResourceId(local, struct.unpack_from(fmt, t.data, t.payload_offset)[0])


def _utf8(t: ParsedTdu) -> str:
    try:
        return bytes(t.data[t.payload_offset : t.payload_offset + t.payload_length]).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ParserError("String is not valid UTF-8.") from error


_FIXED: dict[int, Callable[[ParsedTdu], Any]] = {
    Id.NULL: lambda t: None,
    Id.FALSE: lambda t: False,
    Id.TRUE: lambda t: True,
    Id.NOT_MODIFIED: lambda t: NotModified,
    Id.INFINITY: lambda t: math.inf,
    Id.UINT8: _fixed("<B"),
    Id.INT8: _fixed("<b"),
    Id.CHAR8: _fixed("<B"),
    Id.LOCAL_RESOURCE8: _resource(True, "<B"),
    Id.REMOTE_RESOURCE8: _resource(False, "<B"),
    Id.UINT16: _fixed("<H"),
    Id.INT16: _fixed("<h"),
    Id.CHAR16: _fixed("<H"),
    Id.LOCAL_RESOURCE16: _resource(True, "<H"),
    Id.REMOTE_RESOURCE16: _resource(False, "<H"),
    Id.UINT32: _fixed("<I"),
    Id.INT32: _fixed("<i"),
    Id.FLOAT32: _fixed("<f"),
    Id.LOCAL_RESOURCE32: _resource(True, "<I"),
    Id.REMOTE_RESOURCE32: _resource(False, "<I"),
    Id.UINT64: _fixed("<Q"),
    Id.INT64: _fixed("<q"),
    Id.FLOAT64: _fixed("<d"),
    Id.DATETIME: _datetime,
    Id.UINT128: lambda t: UInt128(_int_le(False)(t)),
    Id.INT128: lambda t: Int128(_int_le(True)(t)),
    Id.DECIMAL128: _decimal,
    Id.UUID: lambda t: uuid.UUID(bytes=t.payload),
}


@dataclass(frozen=True, slots=True)
class _Limits:
    payload: int
    items: int
    allocation: int
    metadata_depth: int
    types: TypeRegistry | None = None


def _parse_child(data: bytes | memoryview, offset: int, ends: int, lim: _Limits) -> ParsedTdu:
    tdu = ParsedTdu.parse(data, offset, ends, lim.payload, lim.metadata_depth)
    if not tdu.valid:
        raise ParserError("Truncated value inside a collection.")
    return tdu


def _inherit(current: ParsedTdu, previous: ParsedTdu) -> None:
    """A TypeContinuation takes the type of the element before it."""
    current.tdu_class = previous.tdu_class
    current.identifier = previous.identifier
    current.index = previous.index
    current.exponent = previous.exponent
    current.metadata = previous.metadata


def _implied_typed(current: ParsedTdu, metadata: Tru) -> None:
    """A TypeOfTarget element is a Typed value whose metadata is the declared type."""
    current.tdu_class = TduClass.TYPED
    current.identifier = Id.TYPED
    current.index = 0
    current.metadata = metadata


def _parse_array(tdu: ParsedTdu, depth: int, lim: _Limits) -> list[Any]:
    items: list[Any] = []
    offset = tdu.payload_offset
    ends = offset + tdu.payload_length
    previous: ParsedTdu | None = None
    while offset < ends:
        current = _parse_child(tdu.data, offset, ends, lim)
        if current.identifier == Id.TYPE_CONTINUATION and previous is not None:
            _inherit(current, previous)
        items.append(_parse_tdu(current, depth + 1, lim))
        ensure_collection_count(len(items), lim.items)
        offset += current.total_length
        previous = current
    return items


def _parse_typed_array(tdu: ParsedTdu, element: Tru, depth: int, lim: _Limits) -> list[Any]:
    spec = _GVWIE.get(element.identifier)
    if spec is not None:
        codec, size = spec
        ensure_allocation(tdu.payload_length * size, lim.allocation, "typed array")

        def guard(count: int) -> None:
            ensure_collection_count(count, lim.items)
            ensure_allocation(count * size, lim.allocation, "typed array")

        end = tdu.payload_offset + tdu.payload_length
        return codec.decode(tdu.data, tdu.payload_offset, end, guard)

    items: list[Any] = []
    offset = tdu.payload_offset
    ends = offset + tdu.payload_length
    previous: ParsedTdu | None = None
    while offset < ends:
        current = _parse_child(tdu.data, offset, ends, lim)
        if current.identifier == Id.TYPE_CONTINUATION and previous is not None:
            _inherit(current, previous)
        elif current.identifier == Id.TYPE_OF_TARGET:
            _implied_typed(current, element)
        items.append(_parse_tdu(current, depth + 1, lim))
        ensure_collection_count(len(items), lim.items)
        offset += current.total_length
        previous = current
    return items


def _parse_typed_map(
    tdu: ParsedTdu, key_type: Tru, value_type: Tru, depth: int, lim: _Limits
) -> dict[Any, Any]:
    ends = tdu.payload_offset + tdu.payload_length
    keys_tdu = _parse_child(tdu.data, tdu.payload_offset, ends, lim)
    values_tdu = _parse_child(tdu.data, keys_tdu.payload_offset + keys_tdu.payload_length, ends, lim)
    if keys_tdu.identifier != Id.TYPE_OF_TARGET or values_tdu.identifier != Id.TYPE_OF_TARGET:
        raise ParserError("A typed map holds a keys array followed by a values array.")
    keys = _parse_typed_array(keys_tdu, key_type, depth + 1, lim)
    values = _parse_typed_array(values_tdu, value_type, depth + 1, lim)
    if len(keys) != len(values):
        raise ParserError("A typed map has a different number of keys and values.")
    try:
        return dict(zip(keys, values, strict=True))
    except TypeError as error:
        raise ParserError("A map key is not hashable.") from error


def _parse_typed_tuple(
    tdu: ParsedTdu, sub_types: Sequence[Tru], depth: int, lim: _Limits
) -> tuple[Any, ...]:
    results: list[Any] = []
    offset = tdu.payload_offset
    ends = offset + tdu.payload_length
    for sub_type in sub_types:
        current = _parse_child(tdu.data, offset, ends, lim)
        if current.identifier == Id.TYPE_OF_TARGET:
            _implied_typed(current, sub_type)
        results.append(_parse_tdu(current, depth + 1, lim))
        offset += current.total_length
    return tuple(results)


def _parse_typed(tdu: ParsedTdu, depth: int, lim: _Limits) -> Any:
    tru = tdu.metadata
    if isinstance(tru, TruComposite):
        ident = tru.identifier
        if ident == TruIdentifier.TYPED_LIST:
            return _parse_typed_array(tdu, tru.sub_types[0], depth, lim)
        if ident == TruIdentifier.TYPED_MAP:
            return _parse_typed_map(tdu, tru.sub_types[0], tru.sub_types[1], depth, lim)
        if ident in TUPLE_IDENTIFIERS.values():
            return _parse_typed_tuple(tdu, tru.sub_types, depth, lim)
        raise ParserError(f"Unsupported typed value with TRU identifier 0x{ident:02x}.")
    if isinstance(tru, TruTypeDef):
        return _parse_defined(tdu, tru, depth, lim)
    raise ParserError("Unknown TRU.")


def _parse_defined(tdu: ParsedTdu, tru: TruTypeDef, depth: int, lim: _Limits) -> Any:
    if tru.remote:
        raise ParserError("Remote type definitions require a connection.")
    if lim.types is None:
        raise ParserError(
            f"TypeDef {tru.type_id} cannot be decoded without a TypeRegistry (types=...)."
        )
    definition = lim.types.by_id(tru.type_id)
    if definition.kind == TypeDefKind.ENUM:
        if tdu.payload_length != 1:
            raise ParserError("An enum value is a single constant index.")
        return definition.constant_value(tdu.data[tdu.payload_offset])
    if definition.kind != TypeDefKind.RECORD:
        raise NotImplementedError("Typed resource values need the resource layer.")
    return _parse_record(tdu, definition, depth, lim)


def _parse_record(tdu: ParsedTdu, definition: TypeDefinition, depth: int, lim: _Limits) -> Any:
    ensure_collection_count(len(definition.properties), lim.items)
    offset = tdu.payload_offset
    ends = offset + tdu.payload_length
    values: list[Any] = []
    previous: ParsedTdu | None = None
    for prop in definition.properties:
        current = _parse_child(tdu.data, offset, ends, lim)
        if current.identifier == Id.TYPE_CONTINUATION and previous is not None:
            _inherit(current, previous)
        elif current.identifier == Id.TYPE_OF_TARGET:
            if prop.value_type is None:
                raise ParserError(
                    f"Property '{prop.name}' has no declared type for an implied value."
                )
            _implied_typed(current, prop.value_type)
        values.append(_parse_tdu(current, depth + 1, lim))
        offset += current.total_length
        previous = current
    if offset != ends:
        raise ParserError(f"Record '{definition.name}' has data after its last property.")
    instance = definition.create()
    for prop, value in zip(definition.properties, values, strict=True):
        definition.set_property(instance, prop.name, value)
    return instance


def _parse_typedef(tdu: ParsedTdu, depth: int, lim: _Limits) -> TypeDefInfo:
    end = tdu.payload_offset + tdu.payload_length
    inner = ParsedTdu.parse(tdu.data, tdu.payload_offset, end, lim.payload, lim.metadata_depth)
    if not inner.valid or inner.total_length != tdu.payload_length:
        raise ParserError("The TypeDef payload contains trailing or incomplete data.")
    return TypeDefInfo.from_map(_parse_tdu(inner, depth + 1, lim))


def _parse_tru(tdu: ParsedTdu, lim: _Limits) -> Tru:
    end = tdu.payload_offset + tdu.payload_length
    tru, size = Tru.parse(tdu.data, tdu.payload_offset, end, maximum_depth=lim.metadata_depth)
    if size != tdu.payload_length:
        raise ParserError("The TRU payload contains trailing or incomplete data.")
    return tru


def _parse_tdu(tdu: ParsedTdu, depth: int, lim: _Limits) -> Any:
    if depth > DEFAULT_MAXIMUM_VALUE_DEPTH:
        raise ParserLimitError("Value nesting is too deep.")
    cls = tdu.tdu_class
    if cls == TduClass.FIXED:
        parser = _FIXED.get(tdu.identifier)
        if parser is None:
            raise ParserError(f"Unsupported fixed TDU 0x{tdu.identifier:02x}.")
        return parser(tdu)
    if cls == TduClass.DYNAMIC:
        ident = tdu.identifier
        if ident == Id.RAW_DATA:
            return tdu.payload
        if ident == Id.STRING:
            return _utf8(tdu)
        if ident == Id.RESOURCE_LINK:
            return ResourceLink(_utf8(tdu))
        if ident in (Id.LIST, Id.RESOURCE_LIST, Id.RECORD_LIST, Id.MAP_LIST):
            return _parse_array(tdu, depth, lim)
        if ident == Id.MAP:
            flat = _parse_array(tdu, depth, lim)
            if len(flat) % 2:
                raise ParserError("Map has a key without a value.")
            try:
                return {flat[i]: flat[i + 1] for i in range(0, len(flat), 2)}
            except TypeError as error:
                raise ParserError("A map key is not hashable.") from error
        raise ParserError(f"Unsupported dynamic TDU 0x{ident:02x}.")
    if cls == TduClass.TYPED:
        if tdu.index == 0:
            return _parse_typed(tdu, depth, lim)
        if tdu.index == 1:
            return _parse_typedef(tdu, depth, lim)
        if tdu.index == 2:
            return _parse_tru(tdu, lim)
        raise ParserError(f"Unsupported typed TDU 0x{tdu.identifier:02x}.")
    raise ParserError("Unsupported TDU class.")


def parse_with_length(
    data: bytes | memoryview,
    offset: int = 0,
    *,
    maximum_payload_length: int = DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
    maximum_collection_items: int = DEFAULT_MAXIMUM_COLLECTION_ITEMS,
    maximum_allocation_size: int = DEFAULT_MAXIMUM_ALLOCATION_SIZE,
    maximum_type_metadata_depth: int = DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
    types: TypeRegistry | None = None,
) -> tuple[Any, int]:
    """Decode one value at ``offset``; returns ``(value, bytes_consumed)``. Registered records
    and enums need the ``types`` registry that registered them."""
    lim = _Limits(
        maximum_payload_length,
        maximum_collection_items,
        maximum_allocation_size,
        maximum_type_metadata_depth,
        types,
    )
    tdu = ParsedTdu.parse(data, offset, len(data), lim.payload, lim.metadata_depth)
    if not tdu.valid:
        raise ParserError("Incomplete value.")
    return _parse_tdu(tdu, 0, lim), tdu.total_length


def parse(
    data: bytes | memoryview,
    offset: int = 0,
    *,
    types: TypeRegistry | None = None,
    **limits: int,
) -> Any:
    """Decode one value at ``offset``."""
    return parse_with_length(data, offset, types=types, **limits)[0]
