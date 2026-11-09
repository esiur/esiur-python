import datetime as dt
import decimal
import uuid

import pytest

from esiur.data import (
    Int8,
    Int128,
    NotModified,
    ParsedTdu,
    ParserError,
    ParserLimitError,
    ResourceId,
    ResourceLink,
    TduClass,
    UInt128,
    compose,
    parse,
    parse_with_length,
)


@pytest.mark.parametrize(
    "value",
    [
        None, True, False, 0, 1, -1, 127, -128, 128, 40000, 70_000, -(2**31), 2**31,
        5_000_000_000, -(2**63), 2**63 - 1, 2**63, 2**64 - 1,
        1.5, 0.1, -2.25, 1e300, "", "Hi", "héllo ✓", b"", b"\x00\x01\xff",
        [], [1, "a", None], {"a": 1, 2: [True]}, [[1, 2], [3, [4]]],
        Int128(-(2**100)), UInt128(2**127), uuid.UUID(int=0x1234),
        decimal.Decimal("1.2345678901234567890123456789"), decimal.Decimal("-12.50"),
        decimal.Decimal(12345678901234567890123456789),
        dt.datetime(2026, 6, 2, 13, 45, 30, 123456, tzinfo=dt.timezone.utc),
        ResourceLink("ep://host/path"),
    ],
)
def test_roundtrip(value: object) -> None:
    decoded = parse(compose(value))
    assert decoded == value
    assert type(decoded) is type(value) or isinstance(value, bool | int)


def test_not_modified_and_infinity() -> None:
    assert parse(compose(NotModified)) is NotModified
    assert parse(compose(float("inf"))) == float("inf")


def test_narrowing_preserves_value_but_not_python_type_for_integral_floats() -> None:
    # Like esiur-ts: 3.0 travels as Int8 and comes back as 3.
    assert compose(3.0) == compose(3)
    assert parse(compose(3.0)) == 3


def test_naive_datetime_is_utc() -> None:
    naive = dt.datetime(2026, 1, 1, 12)
    assert parse(compose(naive)) == naive.replace(tzinfo=dt.timezone.utc)


def test_scale_zero_decimal_narrows_to_an_integer() -> None:
    # Like esiur-ts and esiur-dotnet: a whole decimal travels as the smallest integer.
    assert compose(decimal.Decimal(7)) == compose(7)
    assert parse(compose(decimal.Decimal(0))) == 0


def test_decimal_keeps_trailing_zero_scale() -> None:
    decoded = parse(compose(decimal.Decimal("1.50")))
    assert isinstance(decoded, decimal.Decimal)
    assert str(decoded) == "1.50"


def test_decimal_out_of_range_is_rejected() -> None:
    with pytest.raises(OverflowError):
        compose(decimal.Decimal(2**96))
    with pytest.raises(OverflowError):
        compose(decimal.Decimal("1e-29"))


def test_integer_beyond_64_bits_needs_a_wrapper() -> None:
    with pytest.raises(OverflowError):
        compose(2**64)
    assert parse(compose(Int128(2**64))) == 2**64


def test_explicit_int8_is_always_one_byte() -> None:
    assert compose(Int8(-3)).hex() == "09fd"


def test_unsupported_type() -> None:
    with pytest.raises(TypeError):
        compose(object())


def test_length_prefix_grows_with_payload() -> None:
    small = compose(b"x" * 255)
    medium = compose(b"x" * 256)
    assert small[0] == 0x40 | (1 << 3) and small[1] == 255
    assert medium[0] == 0x40 | (2 << 3) and medium[1:3] == b"\x01\x00"
    assert parse(medium) == b"x" * 256


def test_parse_reports_consumed_length_and_ignores_trailing_bytes() -> None:
    value, length = parse_with_length(compose("ab") + b"\xff\xff")
    assert (value, length) == ("ab", 4)


def test_incomplete_tdu_reports_bytes_needed() -> None:
    wire = compose(b"hello")
    tdu = ParsedTdu.parse(wire[:-2])
    assert tdu.tdu_class == TduClass.INVALID and tdu.total_length == 2
    with pytest.raises(ParserError):
        parse(wire[:-2])


def test_type_continuation_repeats_previous_identifier() -> None:
    # List [Int8 1, <continuation: 2>, <continuation: 3>]: identifier written once.
    payload = bytes([0x09, 1]) + bytes([0xC0 | (1 << 3), 1, 2]) + bytes([0xC0 | (1 << 3), 1, 3])
    wire = bytes([0x42 | (1 << 3), len(payload)]) + payload
    assert parse(wire) == [1, 2, 3]


def test_resource_references_decode_to_placeholders() -> None:
    assert parse(bytes([0x0C, 7])) == ResourceId(False, 7)
    assert parse(bytes([0x13, 0x01, 0x02])) == ResourceId(True, 0x0201)


def test_oversized_declaration_is_rejected_before_waiting_for_data() -> None:
    wire = bytes([0x40 | (4 << 3)]) + (9 * 1024 * 1024).to_bytes(4, "big")
    with pytest.raises(ParserLimitError):
        ParsedTdu.parse(wire)


def test_collection_item_limit() -> None:
    wire = compose([0] * 10)
    with pytest.raises(ParserLimitError):
        parse(wire, maximum_collection_items=5)


def test_nesting_depth_is_bounded() -> None:
    value: object = []
    for _ in range(200):
        value = [value]
    with pytest.raises(ParserLimitError):
        compose(value)
    wire = b"\x42\x09\x00"  # innermost ok; build a hostile deep wire instead
    for _ in range(200):
        wire = bytes([0x42 | (2 << 3)]) + len(wire).to_bytes(2, "big") + wire
    with pytest.raises(ParserLimitError):
        parse(wire)


def test_typedef_payload_must_be_a_structure() -> None:
    # A TypeDef TDU wraps one complete Typed TDU; a bare Null is not a map.
    with pytest.raises(ParserError):
        parse(bytes([0x81 | (1 << 3), 1, 0]))


def test_invalid_utf8_and_odd_map() -> None:
    with pytest.raises(ParserError):
        parse(bytes([0x41 | (1 << 3), 1, 0xFF]))
    one = compose(1)
    with pytest.raises(ParserError):
        parse(bytes([0x46 | (1 << 3), len(one)]) + one)
