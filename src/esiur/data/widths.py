"""Explicit numeric-width wrappers.

A bare Python ``int`` is composed like a C# ``long`` and a bare ``float`` like a
``double``; wrap a value in one of these to pin the wire width (unsigned types, a
32-bit float, ...). Like the other Esiur composers they still narrow to the
smallest representation that fits: ``UInt32(255)`` encodes as ``UInt8``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Int8:
    value: int


@dataclass(frozen=True, slots=True)
class UInt8:
    value: int


@dataclass(frozen=True, slots=True)
class Int16:
    value: int


@dataclass(frozen=True, slots=True)
class UInt16:
    value: int


@dataclass(frozen=True, slots=True)
class Int32:
    value: int


@dataclass(frozen=True, slots=True)
class UInt32:
    value: int


@dataclass(frozen=True, slots=True)
class Int64:
    value: int


@dataclass(frozen=True, slots=True)
class UInt64:
    value: int


@dataclass(frozen=True, slots=True)
class Float32:
    value: float


@dataclass(frozen=True, slots=True)
class Char16:
    """A UTF-16 code unit, encoded as the ``Char16`` TDU."""

    value: int

    @classmethod
    def of(cls, value: int | str) -> Char16:
        return cls(ord(value) if isinstance(value, str) else value)


class Int128(int):
    """Signed 128-bit integer. Also the marker that selects the 128-bit wire width."""

    def __new__(cls, value: int = 0) -> Int128:
        if not -(1 << 127) <= value < (1 << 127):
            raise OverflowError("value does not fit in Int128")
        return super().__new__(cls, value)


class UInt128(int):
    """Unsigned 128-bit integer. Also the marker that selects the 128-bit wire width."""

    def __new__(cls, value: int = 0) -> UInt128:
        if not 0 <= value < (1 << 128):
            raise OverflowError("value does not fit in UInt128")
        return super().__new__(cls, value)
