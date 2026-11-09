"""Type-Representation Units (port of esiur-ts ``Tru`` / C# ``Tru``).

A Tru says how a value's type maps onto the wire. It is one header byte,
``(0x80 if nullable) | identifier``. Identifiers below 0x40 are primitives. Identifiers
from 0x40 set bit 6, and bits 3-5 then give the number of sub-types that follow inline
(``TypedList`` = 1, ``TypedMap``/``Tuple2`` = 2, ... ``Tuple7`` = 7). A count of zero
means a TypeDef reference whose id follows, little-endian, in the width the identifier
names (``LocalType8`` ... ``RemoteType64``).

:class:`TruTypeDef` carries only the id; resolving it to a definition is the job of a
:class:`~esiur.data.typedef.TypeRegistry`.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass

from .guard import (
    DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
    ParserError,
    ensure_type_metadata_depth,
)
from .signature import name64, name_hash_source


class TruIdentifier(enum.IntEnum):
    VOID = 0x0
    DYNAMIC = 0x1
    BOOL = 0x2
    UINT8 = 0x3
    INT8 = 0x4
    CHAR = 0x5
    UINT16 = 0x6
    INT16 = 0x7
    UINT32 = 0x8
    INT32 = 0x9
    FLOAT32 = 0xA
    UINT64 = 0xB
    INT64 = 0xC
    FLOAT64 = 0xD
    DATETIME = 0xE
    UINT128 = 0xF
    INT128 = 0x10
    DECIMAL = 0x11
    STRING = 0x12
    RAW_DATA = 0x13
    RESOURCE = 0x14
    RECORD = 0x15
    LIST = 0x16
    MAP = 0x17

    LOCAL_TYPE8 = 0x40
    REMOTE_TYPE8 = 0x41
    LOCAL_TYPE16 = 0x42
    REMOTE_TYPE16 = 0x43
    LOCAL_TYPE32 = 0x44
    REMOTE_TYPE32 = 0x45
    LOCAL_TYPE64 = 0x46
    REMOTE_TYPE64 = 0x47

    TYPED_LIST = 0x48

    TUPLE2 = 0x50
    TYPED_MAP = 0x51
    TUPLE3 = 0x58
    TUPLE4 = 0x60
    TUPLE5 = 0x68
    TUPLE6 = 0x70
    TUPLE7 = 0x78


TUPLE_IDENTIFIERS = {
    2: TruIdentifier.TUPLE2,
    3: TruIdentifier.TUPLE3,
    4: TruIdentifier.TUPLE4,
    5: TruIdentifier.TUPLE5,
    6: TruIdentifier.TUPLE6,
    7: TruIdentifier.TUPLE7,
}

_TYPE_ID_WIDTH = {
    TruIdentifier.LOCAL_TYPE8: (1, False),
    TruIdentifier.REMOTE_TYPE8: (1, True),
    TruIdentifier.LOCAL_TYPE16: (2, False),
    TruIdentifier.REMOTE_TYPE16: (2, True),
    TruIdentifier.LOCAL_TYPE32: (4, False),
    TruIdentifier.REMOTE_TYPE32: (4, True),
    TruIdentifier.LOCAL_TYPE64: (8, False),
    TruIdentifier.REMOTE_TYPE64: (8, True),
}
_LOCAL_BY_WIDTH = {1: TruIdentifier.LOCAL_TYPE8, 2: TruIdentifier.LOCAL_TYPE16,
                   4: TruIdentifier.LOCAL_TYPE32, 8: TruIdentifier.LOCAL_TYPE64}
_REMOTE_BY_WIDTH = {1: TruIdentifier.REMOTE_TYPE8, 2: TruIdentifier.REMOTE_TYPE16,
                    4: TruIdentifier.REMOTE_TYPE32, 8: TruIdentifier.REMOTE_TYPE64}


def tuple_identifier(count: int) -> TruIdentifier:
    try:
        return TUPLE_IDENTIFIERS[count]
    except KeyError:
        raise ValueError("Tuples must have between 2 and 7 elements.") from None


class Tru:
    """Base of the three Tru shapes. Instances are immutable and hashable."""

    __slots__ = ()

    identifier: int
    nullable: bool

    def compose(self) -> bytes:
        raise NotImplementedError

    def match(self, other: Tru) -> bool:
        """Same type, ignoring nullability."""
        raise NotImplementedError

    def to_nullable(self) -> Tru:
        return dataclasses.replace(self, nullable=True)  # type: ignore[type-var]

    @property
    def _header(self) -> int:
        return (0x80 if self.nullable else 0) | int(self.identifier)

    @classmethod
    def parse(
        cls,
        data: bytes | memoryview,
        offset: int = 0,
        ends: int | None = None,
        *,
        maximum_depth: int = DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
    ) -> tuple[Tru, int]:
        """Parse a Tru at ``offset``; returns it and the number of bytes consumed."""
        limit = len(data) if ends is None else ends
        return _parse(data, offset, limit, 1, maximum_depth)


@dataclass(frozen=True, slots=True)
class TruPrimitive(Tru):
    identifier: int
    nullable: bool = False

    def compose(self) -> bytes:
        return bytes([self._header])

    def match(self, other: Tru) -> bool:
        return isinstance(other, TruPrimitive) and other.identifier == self.identifier

    def __str__(self) -> str:
        return _name(self.identifier) + ("?" if self.nullable else "")


@dataclass(frozen=True, slots=True)
class TruComposite(Tru):
    """A typed list, map or tuple, carrying its element types inline."""

    identifier: int
    sub_types: tuple[Tru, ...]
    nullable: bool = False

    def compose(self) -> bytes:
        return bytes([self._header]) + b"".join(sub.compose() for sub in self.sub_types)

    def match(self, other: Tru) -> bool:
        return (
            isinstance(other, TruComposite)
            and other.identifier == self.identifier
            and len(other.sub_types) == len(self.sub_types)
            and all(a.match(b) for a, b in zip(self.sub_types, other.sub_types, strict=True))
        )

    def __str__(self) -> str:
        inner = ",".join(str(sub) for sub in self.sub_types)
        return f"{_name(self.identifier)}<{inner}>" + ("?" if self.nullable else "")


@dataclass(frozen=True, slots=True)
class TruTypeDef(Tru):
    """A reference to a registered record, enum or resource type, by id."""

    type_id: int
    nullable: bool = False
    remote: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.type_id < (1 << 64):
            raise OverflowError("TypeDef id must fit in 64 bits.")

    @property
    def identifier(self) -> int:  # type: ignore[override]
        width = next(w for w in (1, 2, 4, 8) if self.type_id < (1 << (8 * w)))
        return (_REMOTE_BY_WIDTH if self.remote else _LOCAL_BY_WIDTH)[width]

    def compose(self) -> bytes:
        name_of = name_hash_source()
        if name_of is not None:
            # Signature mode: the hash of the referenced name, written with the widest
            # identifier, so the result never depends on a TypeDef id or its width.
            header = (0x80 if self.nullable else 0) | TruIdentifier.LOCAL_TYPE64
            return bytes([header]) + name64(name_of(self.type_id)).to_bytes(8, "little")
        ident = self.identifier
        width = _TYPE_ID_WIDTH[TruIdentifier(ident)][0]
        return bytes([self._header]) + self.type_id.to_bytes(width, "little")

    def match(self, other: Tru) -> bool:
        return isinstance(other, TruTypeDef) and other.type_id == self.type_id

    def __str__(self) -> str:
        return f"{'remote:' if self.remote else ''}type#{self.type_id}" + (
            "?" if self.nullable else ""
        )


def _name(identifier: int) -> str:
    try:
        return TruIdentifier(identifier).name.title().replace("_", "")
    except ValueError:
        return f"0x{identifier:02x}"


def _parse(
    data: bytes | memoryview, offset: int, ends: int, depth: int, maximum_depth: int
) -> tuple[Tru, int]:
    ensure_type_metadata_depth(depth, maximum_depth)
    if offset >= ends:
        raise ParserError("Truncated TRU.")
    start = offset
    header = data[offset]
    offset += 1
    nullable = bool(header & 0x80)
    identifier = header & 0x7F

    if not header & 0x40:
        return TruPrimitive(identifier, nullable), 1

    sub_count = (header >> 3) & 0x7
    if sub_count == 0:
        try:
            width, remote = _TYPE_ID_WIDTH[TruIdentifier(identifier)]
        except (ValueError, KeyError):
            raise ParserError(f"Invalid TRU TypeDef identifier 0x{identifier:02x}.") from None
        if ends - offset < width:
            raise ParserError("Truncated TRU TypeDef id.")
        type_id = int.from_bytes(data[offset : offset + width], "little")
        return TruTypeDef(type_id, nullable, remote), 1 + width

    subs: list[Tru] = []
    for _ in range(sub_count):
        sub, size = _parse(data, offset, ends, depth + 1, maximum_depth)
        subs.append(sub)
        offset += size
    return TruComposite(identifier, tuple(subs), nullable), offset - start
