"""Typed layer: Tru, Gvwie arrays, typed lists / maps / tuples."""

from __future__ import annotations

import random
from typing import Any

import pytest

from esiur.data import (
    GROUP_INT16,
    GROUP_INT32,
    GROUP_INT64,
    GROUP_UINT16,
    GROUP_UINT32,
    GROUP_UINT64,
    ParsedTdu,
    ParserError,
    ParserLimitError,
    Tru,
    TruComposite,
    TruIdentifier,
    TruPrimitive,
    TruTypeDef,
    TypedList,
    TypedMap,
    TypedTuple,
    compose,
    parse,
    t,
)

# ----------------------------------------------------------------- Tru --


def test_tru_wire_forms() -> None:
    assert t.i32.compose() == bytes([0x09])
    assert t.nullable(t.i32).compose() == bytes([0x89])
    assert t.list(t.string).compose() == bytes([0x48, 0x12])
    assert t.map(t.string, t.i32).compose() == bytes([0x51, 0x12, 0x09])
    assert t.tuple(t.u8, t.bool, t.f64).compose() == bytes([0x58, 0x03, 0x02, 0x0D])


@pytest.mark.parametrize(
    "tru",
    [
        t.dynamic,
        t.nullable(t.u128),
        t.list(t.list(t.i64)),
        t.map(t.string, t.nullable(t.list(t.f32))),
        t.tuple(t.u8, t.string),
        t.tuple(*[t.i8] * 7),
        TruTypeDef(7),
        TruTypeDef(300, nullable=True),
        TruTypeDef(70_000),
        TruTypeDef(2**40),
        TruTypeDef(5, remote=True),
        t.list(TruTypeDef(9)),
    ],
    ids=str,
)
def test_tru_round_trips(tru: Tru) -> None:
    data = tru.compose()
    parsed, size = Tru.parse(data)
    assert size == len(data)
    assert parsed == tru
    assert parsed.compose() == data


def test_tru_type_def_picks_the_narrowest_id_width() -> None:
    assert TruTypeDef(0xFF).compose() == bytes([0x40, 0xFF])
    assert TruTypeDef(0x100).compose() == bytes([0x42, 0x00, 0x01])
    assert TruTypeDef(0x1_0000).compose() == bytes([0x44, 0x00, 0x00, 0x01, 0x00])
    assert TruTypeDef(1 << 32).identifier == TruIdentifier.LOCAL_TYPE64
    assert TruTypeDef(1, remote=True).identifier == TruIdentifier.REMOTE_TYPE8


def test_tru_match_ignores_nullability_but_not_shape() -> None:
    assert t.i32.match(t.nullable(t.i32))
    assert not t.i32.match(t.u32)
    assert t.list(t.i32).match(t.nullable(t.list(t.i32)))
    assert not t.list(t.i32).match(t.list(t.i64))
    assert not t.list(t.i32).match(t.i32)
    assert TruTypeDef(3).match(TruTypeDef(3, nullable=True))
    assert not TruTypeDef(3).match(TruTypeDef(4))


def test_tru_str_is_readable() -> None:
    assert str(t.nullable(t.map(t.string, t.i32))) == "TypedMap<String,Int32>?"


def test_tuple_arity_is_limited() -> None:
    with pytest.raises(ValueError):
        t.tuple(t.i32)
    with pytest.raises(ValueError):
        t.tuple(*[t.i32] * 8)


@pytest.mark.parametrize(
    "data",
    [
        b"",  # nothing
        bytes([0x48]),  # TypedList without its element
        bytes([0x51, 0x12]),  # TypedMap missing the value type
        bytes([0x42, 0x01]),  # 16-bit TypeDef id cut short
        bytes([0x4A]),  # bit 6 with sub-count 1 but nothing after
        bytes([0x40 | 0x20]),  # sub-count 4 with no sub-types
    ],
)
def test_truncated_tru_is_rejected(data: bytes) -> None:
    with pytest.raises(ParserError):
        Tru.parse(data)


def test_unknown_primitive_identifiers_survive_a_round_trip() -> None:
    parsed, _ = Tru.parse(bytes([0x3F]))
    assert isinstance(parsed, TruPrimitive)
    assert parsed.identifier == 0x3F
    assert parsed.compose() == bytes([0x3F])


def test_tru_depth_is_limited() -> None:
    deep: Tru = t.i32
    for _ in range(80):
        deep = t.list(deep)
    data = deep.compose()
    with pytest.raises(ParserLimitError):
        Tru.parse(data)
    parsed, _ = Tru.parse(data, maximum_depth=0)  # a non-positive budget disables the check
    assert parsed == deep


def test_tru_value_is_its_own_tdu() -> None:
    wire = compose(t.list(t.i32))
    assert wire == bytes([0x8A, 2, 0x48, 0x09])
    assert parse(wire) == t.list(t.i32)


def test_tru_value_with_trailing_bytes_is_rejected() -> None:
    wire = bytes([0x82 | (1 << 3), 2, 0x09, 0x09])
    with pytest.raises(ParserError):
        parse(wire)


# --------------------------------------------------------------- Gvwie --

CODECS = {
    "i16": (GROUP_INT16, -(2**15), 2**15 - 1),
    "i32": (GROUP_INT32, -(2**31), 2**31 - 1),
    "i64": (GROUP_INT64, -(2**63), 2**63 - 1),
    "u16": (GROUP_UINT16, 0, 2**16 - 1),
    "u32": (GROUP_UINT32, 0, 2**32 - 1),
    "u64": (GROUP_UINT64, 0, 2**64 - 1),
}


@pytest.mark.parametrize("name", CODECS)
def test_gvwie_round_trips_random_arrays(name: str) -> None:
    codec, low, high = CODECS[name]
    rng = random.Random(name)
    for length in (0, 1, 2, 3, 15, 16, 17, 33, 34, 40, 64, 65, 300, 5000):
        values = []
        for _ in range(length):
            magnitude = rng.choice([7, 8, 15, 16, 31, 32, 63, 64])
            values.append(max(low, min(high, rng.randint(low, high) >> (64 - magnitude))))
        assert codec.decode(codec.encode(values)) == values


@pytest.mark.parametrize("name", CODECS)
def test_gvwie_extremes(name: str) -> None:
    codec, low, high = CODECS[name]
    values = [low, high, 0, low, high] * 3
    assert codec.decode(codec.encode(values)) == values


def test_gvwie_known_bytes() -> None:
    assert GROUP_INT16.encode([]) == b""
    assert GROUP_INT16.encode([0, -1, 63]) == bytes([0, 1, 126])  # zig-zag literals
    assert GROUP_UINT32.encode([5]) == bytes([5])  # <= 7 bits is a literal byte
    # One value (count field 0) of width 2 -> header 1|000|01.
    assert GROUP_UINT32.encode([300]) == bytes([0x81, 0x2C, 0x01])
    # One value of width 6 -> header 1|0000|101.
    assert GROUP_UINT64.encode([1 << 40]) == bytes([0x85]) + (1 << 40).to_bytes(6, "little")


def test_gvwie_extended_count_boundary() -> None:
    codec = GROUP_UINT16
    short_max = codec._short_max_count  # boundary under test
    for count in (short_max - 1, short_max, short_max + 1, short_max + 2, 1000):
        values = [1000] * count
        assert codec.decode(codec.encode(values)) == values


def test_gvwie_rejects_values_outside_the_width() -> None:
    with pytest.raises(OverflowError):
        GROUP_INT16.encode([32768])
    with pytest.raises(OverflowError):
        GROUP_UINT32.encode([-1])


def test_gvwie_truncated_run_is_rejected() -> None:
    wire = GROUP_UINT32.encode([70_000, 70_001, 70_002])
    with pytest.raises(ParserError):
        GROUP_UINT32.decode(wire[:-1])


def test_gvwie_guard_sees_the_count_before_values_are_read() -> None:
    seen: list[int] = []

    def guard(count: int) -> None:
        seen.append(count)
        if count > 4:
            raise ParserLimitError("too many")

    wire = GROUP_UINT16.encode([1000] * 10)
    with pytest.raises(ParserLimitError):
        GROUP_UINT16.decode(wire, validate_count=guard)
    assert seen == [10]


# --------------------------------------------------- typed list / map ----


def test_typed_list_decodes_to_a_list() -> None:
    assert parse(compose(TypedList(t.i32, [1, -2, 70_000]))) == [1, -2, 70_000]
    assert parse(compose(TypedList(t.string, ["a", "b"]))) == ["a", "b"]
    assert parse(compose(TypedList(t.i32, []))) == []


def test_typed_list_of_lists() -> None:
    value = TypedList(t.list(t.i32), [TypedList(t.i32, [1, 2]), TypedList(t.i32, [3])])
    assert parse(compose(value)) == [[1, 2], [3]]


def test_typed_map_decodes_to_a_dict() -> None:
    assert parse(compose(TypedMap(t.string, t.i32, {"a": 1, "b": 300}))) == {"a": 1, "b": 300}
    assert parse(compose(TypedMap(t.string, t.i32, [("a", 1)]))) == {"a": 1}
    assert parse(compose(TypedMap(t.string, t.string, {}))) == {}


def test_typed_map_with_typed_values_uses_type_of_target() -> None:
    value = TypedMap(t.string, t.list(t.i32), {"x": TypedList(t.i32, [1, 2])})
    assert parse(compose(value)) == {"x": [1, 2]}


def test_typed_tuple_decodes_to_a_tuple() -> None:
    value = TypedTuple([t.i32, t.string, t.bool], (7, "z", True))
    assert parse(compose(value)) == (7, "z", True)


def test_typed_tuple_validates_arity() -> None:
    with pytest.raises(ValueError):
        TypedTuple([t.i32, t.string], (1,))
    with pytest.raises(ValueError):
        TypedTuple([t.i32], (1,))


def test_dynamic_list_of_typed_lists_uses_type_continuation() -> None:
    first = compose(TypedList(t.i32, [1]))
    both = compose([TypedList(t.i32, [1]), TypedList(t.i32, [2, 3])])
    # TypeContinuation (0xC0 | 1 length byte) carrying only the second list's gvwie payload.
    assert bytes([0xC8, 2, 4, 6]) in both
    assert parse(both) == [[1], [2, 3]]
    assert both[0] & 0xC7 == 0x42  # still a List
    assert first in both  # the first element is written in full


def test_typed_primitive_elements_keep_their_declared_width() -> None:
    # A bare int would narrow to Int8; a declared UInt8 / Int8 / Char element keeps its tag.
    assert compose(TypedList(t.u8, [1])).endswith(bytes([0x08, 1]))  # UInt8 fixed TDU
    assert compose(TypedList(t.i8, [1])).endswith(bytes([0x09, 1]))  # Int8 fixed TDU
    assert parse(compose(TypedList(t.char, [97, "b"]))) == [97, 98]


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (TypedList(t.u8, [256]), OverflowError),
        (TypedList(t.u8, [-1]), OverflowError),
        (TypedList(t.i8, [128]), OverflowError),
        (TypedList(t.u8, ["x"]), TypeError),
        (TypedList(t.u8, [True]), TypeError),
        (TypedList(t.i16, [40_000]), OverflowError),
        (TypedList(t.u64, [-1]), OverflowError),
    ],
)
def test_typed_elements_are_range_checked(value: Any, error: type[Exception]) -> None:
    with pytest.raises(error):
        compose(value)


# --------------------------------------------------------- hostile input --


def test_typed_list_allocation_budget() -> None:
    wire = compose(TypedList(t.i16, list(range(200))))
    with pytest.raises(ParserLimitError):
        parse(wire, maximum_allocation_size=100)
    assert parse(wire) == list(range(200))


def test_typed_list_collection_budget() -> None:
    wire = compose(TypedList(t.u16, [1000] * 50))
    with pytest.raises(ParserLimitError):
        parse(wire, maximum_collection_items=10)


def test_generic_typed_list_collection_budget() -> None:
    wire = compose(TypedList(t.string, ["a"] * 50))
    with pytest.raises(ParserLimitError):
        parse(wire, maximum_collection_items=10)


def test_gvwie_count_bomb_is_rejected_without_materialising() -> None:
    # TypedList<UInt16> whose single run claims a huge extended count with no payload.
    # Count field 62 means "extended count in 3 bytes"; width bit 1 means 2-byte values.
    body = bytes([0x80 | (62 << 1) | 1]) + (0xFFFFFF).to_bytes(3, "little")
    meta = bytes([0x48, 0x06])
    content = meta + body
    wire = bytes([0x80 | (1 << 3), len(content)]) + content
    with pytest.raises(ParserError):
        parse(wire)


def test_typed_tdu_metadata_depth_budget() -> None:
    deep: Tru = t.i32
    for _ in range(10):
        deep = t.list(deep)
    meta = deep.compose()
    wire = bytes([0x80 | (1 << 3), len(meta)]) + meta
    with pytest.raises(ParserLimitError):
        parse(wire, maximum_type_metadata_depth=5)


def test_typed_tdu_with_truncated_metadata_is_rejected() -> None:
    wire = bytes([0x80 | (1 << 3), 1, 0x48])  # TypedList with no element Tru
    with pytest.raises(ParserError):
        parse(wire)


def test_typed_map_needs_matching_key_and_value_counts() -> None:
    keys = compose(TypedList(t.string, ["a", "b"]))
    values = compose(TypedList(t.string, ["x"]))
    # Rebuild the payload by hand: TypeOfTarget(keys) TypeOfTarget(values), mismatched.
    from esiur.data import compose_tdu

    def payload(value: bytes) -> bytes:
        parsed = ParsedTdu.parse(value)
        return compose_tdu(0xC1, parsed.payload)

    inner = payload(keys) + payload(values)
    meta = t.map(t.string, t.string).compose()
    content = meta + inner
    wire = bytes([0x80 | (1 << 3), len(content)]) + content
    with pytest.raises(ParserError):
        parse(wire)


def test_typed_map_with_unhashable_key_is_rejected() -> None:
    value = TypedMap(t.list(t.i32), t.i32, [(TypedList(t.i32, [1]), 1)])
    with pytest.raises(ParserError):
        parse(compose(value))


def test_typedef_referencing_values_need_a_registry() -> None:
    meta = TruTypeDef(1).compose()
    wire = bytes([0x80 | (1 << 3), len(meta)]) + meta
    with pytest.raises(ParserError):
        parse(wire)


def test_primitive_tru_as_metadata_is_not_a_value_type() -> None:
    wire = bytes([0x80 | (1 << 3), 1, 0x09])
    with pytest.raises(ParserError):
        parse(wire)


def test_truncated_typed_payload_is_incomplete() -> None:
    wire = compose(TypedList(t.i32, [1, 2, 3]))
    with pytest.raises(ParserError):
        parse(wire[:-1])


def test_composite_identifier_helpers() -> None:
    assert isinstance(t.list(t.i32), TruComposite)
    assert t.list(t.i32).identifier == TruIdentifier.TYPED_LIST
