"""Group-varint integer arrays (port of esiur-ts ``gvwie`` / C# ``Gvwie.GroupIntNNCodec``).

One header byte frames a run: ``1 | count-field[count_bits] | (width-1)[width_bits]`` where
``count_bits + width_bits == 7``. A value that fits in 7 bits (after zig-zag for signed
widths) is a single literal byte instead. Count-field values above ``max_short_field``
announce an extended count stored in 1-4 little-endian bytes after the header.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .guard import ParserError


@dataclass(frozen=True)
class GroupCodec:
    """Group-varint codec for one integer width and signedness."""

    count_bits: int
    bits: int
    signed: bool

    @property
    def max_width(self) -> int:
        return self.bits // 8

    @property
    def _width_bits(self) -> int:
        return 7 - self.count_bits

    @property
    def _count_field_max(self) -> int:
        return (1 << self.count_bits) - 1

    @property
    def _max_short_field(self) -> int:
        return self._count_field_max - 4  # the top four field values mean "extended count"

    @property
    def _short_max_count(self) -> int:
        return self._max_short_field + 1

    def _range_check(self, value: int) -> None:
        if self.signed:
            low, high = -(1 << (self.bits - 1)), (1 << (self.bits - 1)) - 1
        else:
            low, high = 0, (1 << self.bits) - 1
        if not low <= value <= high:
            kind = "Int" if self.signed else "UInt"
            raise OverflowError(f"value {value} does not fit in {kind}{self.bits}")

    def _to_z(self, value: int) -> int:
        mask = (1 << self.bits) - 1
        if self.signed:
            return ((value << 1) ^ (value >> (self.bits - 1))) & mask
        return value & mask

    def _from_z(self, z: int) -> int:
        return (z >> 1) ^ -(z & 1) if self.signed else z

    def _width_of(self, z: int) -> int:
        return min(max((z.bit_length() + 7) // 8, 1), self.max_width)

    def encode(self, values: Iterable[int]) -> bytes:
        items = [int(v) for v in values]
        for item in items:
            self._range_check(item)
        out = bytearray()
        width_mask = (1 << self._width_bits) - 1
        i = 0
        while i < len(items):
            z = self._to_z(items[i])
            if z <= 0x7F:
                out.append(z)
                i += 1
                continue

            start, width, count = i, self._width_of(z), 1
            while i + count < len(items):
                z2 = self._to_z(items[i + count])
                if z2 <= 0x7F or self._width_of(z2) != width:
                    break
                count += 1

            if count <= self._short_max_count:
                out.append(0x80 | ((count - 1) << self._width_bits) | ((width - 1) & width_mask))
            else:
                extra = count - (self._short_max_count + 1)
                lol = 1 if extra <= 0xFF else 2 if extra <= 0xFFFF else 3 if extra <= 0xFFFFFF else 4
                group_bits = self._max_short_field + lol
                out.append(0x80 | (group_bits << self._width_bits) | ((width - 1) & width_mask))
                out += extra.to_bytes(lol, "little")

            for k in range(count):
                out += self._to_z(items[start + k]).to_bytes(width, "little")
            i += count
        return bytes(out)

    def decode(
        self,
        data: bytes | memoryview,
        start: int = 0,
        end: int | None = None,
        validate_count: Callable[[int], None] | None = None,
    ) -> list[int]:
        """Decode ``data[start:end]``. ``validate_count`` sees the running total before
        any run is read, so a hostile count is rejected without being materialised."""
        limit = len(data) if end is None else end
        result: list[int] = []
        pos = start
        width_mask = (1 << self._width_bits) - 1

        def take(width: int) -> int:
            nonlocal pos
            if pos + width > limit:
                raise ParserError("Buffer underflow while reading a group payload.")
            value = int.from_bytes(data[pos : pos + width], "little")
            pos += width
            return value

        while pos < limit:
            header = data[pos]
            pos += 1
            if not header & 0x80:
                if validate_count is not None:
                    validate_count(len(result) + 1)
                result.append(self._from_z(header & 0x7F))
                continue

            count_field = (header >> self._width_bits) & self._count_field_max
            width = (header & width_mask) + 1
            if count_field <= self._max_short_field:
                count = count_field + 1
            else:
                count = self._short_max_count + 1 + take(count_field - self._max_short_field)

            if validate_count is not None:
                validate_count(len(result) + count)
            for _ in range(count):
                result.append(self._from_z(take(width)))
        return result


GROUP_INT16 = GroupCodec(count_bits=6, bits=16, signed=True)
GROUP_INT32 = GroupCodec(count_bits=5, bits=32, signed=True)
GROUP_INT64 = GroupCodec(count_bits=4, bits=64, signed=True)
GROUP_UINT16 = GroupCodec(count_bits=6, bits=16, signed=False)
GROUP_UINT32 = GroupCodec(count_bits=5, bits=32, signed=False)
GROUP_UINT64 = GroupCodec(count_bits=4, bits=64, signed=False)

__all__ = [
    "GROUP_INT16",
    "GROUP_INT32",
    "GROUP_INT64",
    "GROUP_UINT16",
    "GROUP_UINT32",
    "GROUP_UINT64",
    "GroupCodec",
]
