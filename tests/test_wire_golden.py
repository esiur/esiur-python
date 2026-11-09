"""Byte-for-byte vectors shared with esiur-dotnet and esiur-ts (``wire-golden``)."""

import datetime as dt
import decimal
import math
import uuid

import pytest

from esiur.data import Char16, UInt32, UInt64, compose

I64 = 5_000_000_000


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("null", None, "00"),
        ("bool_false", False, "01"),
        ("bool_true", True, "02"),
        ("int_0", 0, "0900"),
        ("int_1", 1, "0901"),
        ("int_minus1", -1, "09ff"),
        ("int_127", 127, "097f"),
        ("int_128", 128, "118000"),
        ("int_200", 200, "11c800"),
        ("int_40000", 40000, "19409c0000"),
        ("int_70000", 70000, "1970110100"),
        ("long_5e9", I64, "2100f2052a01000000"),
        ("uint_255", UInt32(255), "08ff"),
        ("uint_256", UInt32(256), "100001"),
        ("ulong_max", UInt64(0xFFFFFFFFFFFFFFFF), "20ffffffffffffffff"),
        ("float_1p5", 1.5, "1a0000c03f"),
        ("double_0p1", 0.1, "229a9999999999b93f"),
        ("char_A", Char16.of("A"), "124100"),
        ("string_Hi", "Hi", "49024869"),
        ("string_empty", "", "41"),
    ],
)
def test_composes_primitives(name: str, value: object, expected: str) -> None:
    assert compose(value).hex() == expected, name


def test_composes_high_precision_decimal() -> None:
    value = decimal.Decimal("1.2345678901234567890123456789")
    assert compose(value).hex() == "2a00001c00321be4271581396eb1c9be46"


def test_composes_datetime() -> None:
    value = dt.datetime(2026, 6, 2, 13, 45, 30, tzinfo=dt.timezone.utc)
    assert compose(value).hex() == "230039f035adc0de08"


def test_composes_uuid() -> None:
    raw = bytes.fromhex("78563412ab90efcd1234567890abcdef")
    assert compose(uuid.UUID(bytes=raw)).hex() == "2b" + raw.hex()


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_floats_are_one_token(value: float) -> None:
    assert compose(value).hex() == "04"
