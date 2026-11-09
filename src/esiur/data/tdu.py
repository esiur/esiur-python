"""Transmission Data Units: the self-describing framing of every Esiur value."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .guard import (
    DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
    DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
    ensure_packet_size,
)
from .tru import Tru


class TduClass(enum.IntEnum):
    """Top two bits of the identifier; selects how the payload length is framed."""

    FIXED = 0x0  # length implied by the identifier's exponent
    DYNAMIC = 0x1  # length-prefixed payload
    TYPED = 0x2  # length-prefixed, may carry type metadata
    EXTENSION = 0x3
    INVALID = 0x4  # not enough bytes / not a TDU


class TduIdentifier(enum.IntEnum):
    """Leading type byte: ``[class:2][size-or-exponent:3][index:3]``."""

    # Fixed, zero payload
    NULL = 0x0
    FALSE = 0x1
    TRUE = 0x2
    NOT_MODIFIED = 0x3
    INFINITY = 0x4
    # Fixed, 1 byte
    UINT8 = 0x8
    INT8 = 0x9
    CHAR8 = 0xA
    LOCAL_RESOURCE8 = 0xB
    REMOTE_RESOURCE8 = 0xC
    LOCAL_PROCEDURE8 = 0xD
    REMOTE_PROCEDURE8 = 0xE
    # Fixed, 2 bytes
    UINT16 = 0x10
    INT16 = 0x11
    CHAR16 = 0x12
    LOCAL_RESOURCE16 = 0x13
    REMOTE_RESOURCE16 = 0x14
    LOCAL_PROCEDURE16 = 0x15
    REMOTE_PROCEDURE16 = 0x16
    # Fixed, 4 bytes
    UINT32 = 0x18
    INT32 = 0x19
    FLOAT32 = 0x1A
    LOCAL_RESOURCE32 = 0x1B
    REMOTE_RESOURCE32 = 0x1C
    LOCAL_PROCEDURE32 = 0x1D
    REMOTE_PROCEDURE32 = 0x1E
    # Fixed, 8 bytes
    UINT64 = 0x20
    INT64 = 0x21
    FLOAT64 = 0x22
    DATETIME = 0x23
    # Fixed, 16 bytes
    UINT128 = 0x28
    INT128 = 0x29
    DECIMAL128 = 0x2A
    UUID = 0x2B
    # Dynamic
    RAW_DATA = 0x40
    STRING = 0x41
    LIST = 0x42
    RESOURCE_LIST = 0x43
    RECORD_LIST = 0x44
    RESOURCE_LINK = 0x45
    MAP = 0x46
    MAP_LIST = 0x47
    # Typed
    TYPED = 0x80
    TYPEDEF = 0x81
    TRU = 0x82
    # Extension
    TYPE_CONTINUATION = 0xC0
    TYPE_OF_TARGET = 0xC1


def framed_header(id_byte: int, content_length: int) -> bytes:
    """Header of a length-prefixed TDU: the identifier with the length-of-length in
    bits 3-5, then the content length big-endian. Empty payloads omit both."""
    if content_length == 0:
        return bytes([id_byte])
    n = max(1, (content_length.bit_length() + 7) // 8)
    if n > 7:
        raise OverflowError("TDU payload too large")
    return bytes([(id_byte | (n << 3)) & 0xFF]) + content_length.to_bytes(n, "big")


def compose_tdu(identifier: int, payload: bytes = b"") -> bytes:
    """Encode a Fixed, Dynamic or Extension TDU (and TypeDef/TRU, which carry no metadata)."""
    cls = identifier >> 6
    if cls == TduClass.FIXED:
        return bytes([identifier]) + payload
    return framed_header(identifier, len(payload)) + payload


@dataclass(slots=True)
class ParsedTdu:
    """A measured TDU pointing back into its source buffer."""

    identifier: int = TduIdentifier.NULL
    index: int = 0
    tdu_class: TduClass = TduClass.INVALID
    payload_offset: int = 0
    payload_length: int = 0
    data: bytes | memoryview = field(default=b"", repr=False)
    exponent: int = 0
    total_length: int = 0
    ends: int = 0
    #: Type metadata of a plain ``Typed`` TDU (0x80); ``None`` for every other TDU.
    metadata: Tru | None = None
    #: Offset of the TDU's identifier byte in ``data``.
    tdu_offset: int = 0

    @property
    def valid(self) -> bool:
        return self.tdu_class != TduClass.INVALID

    @property
    def payload(self) -> bytes:
        return bytes(self.data[self.payload_offset : self.payload_offset + self.payload_length])

    @property
    def tdu_bytes(self) -> bytes:
        """The whole TDU (identifier, length and payload), ready to hand to ``parse``."""
        return bytes(self.data[self.tdu_offset : self.tdu_offset + self.total_length])

    @classmethod
    def invalid(cls, bytes_needed: int) -> ParsedTdu:
        """Not enough data yet; ``total_length`` is how many more bytes are required."""
        return cls(tdu_class=TduClass.INVALID, total_length=bytes_needed)

    @classmethod
    def parse(
        cls,
        data: bytes | memoryview,
        offset: int = 0,
        ends: int | None = None,
        maximum_payload_length: int = DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
        maximum_type_metadata_depth: int = DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
        *,
        parse_metadata: bool = True,
    ) -> ParsedTdu:
        """Measure the TDU at ``offset``. A plain ``Typed`` TDU (0x80) has its leading Tru
        metadata parsed into ``metadata``, and its payload then starts after it; ``TypeDef``
        (0x81) and ``TRU`` (0x82) are framed payloads without a metadata prefix.

        With ``parse_metadata=False`` the Tru metadata is left alone and ``payload`` covers the
        whole content (see :meth:`measure`)."""
        if ends is None:
            ends = len(data)
        if offset >= ends:
            return cls.invalid(1)
        start = offset
        header = data[offset]
        offset += 1
        tdu_class = TduClass(header >> 6)

        if tdu_class == TduClass.FIXED:
            exponent = (header & 0x38) >> 3
            tdu = cls(
                identifier=header,
                index=header & 0x7,
                tdu_class=tdu_class,
                data=data,
                exponent=exponent,
                ends=ends,
                tdu_offset=start,
            )
            if exponent == 0:
                tdu.payload_offset = offset
                tdu.total_length = 1
                return tdu
            length = 1 << (exponent - 1)
            if ends - offset < length:
                return cls.invalid(length - (ends - offset))
            tdu.payload_offset = offset
            tdu.payload_length = length
            tdu.total_length = 1 + length
            return tdu

        length_size = (header >> 3) & 0x7
        if ends - offset < length_size:
            return cls.invalid(length_size - (ends - offset))
        length = int.from_bytes(data[offset : offset + length_size], "big")
        offset += length_size
        # Reject an oversized declaration before it can justify waiting for more bytes.
        ensure_packet_size(length, maximum_payload_length)
        if ends - offset < length:
            return cls.invalid(length - (ends - offset))

        if parse_metadata and tdu_class == TduClass.TYPED and (header & 0xC7) == 0x80:
            payload_end = offset + length
            tru, size = Tru.parse(
                data, offset, payload_end, maximum_depth=maximum_type_metadata_depth
            )
            return cls(
                identifier=0x80,
                index=0,
                tdu_class=tdu_class,
                data=data,
                payload_offset=offset + size,
                payload_length=length - size,
                total_length=1 + length_size + length,
                ends=ends,
                metadata=tru,
                tdu_offset=start,
            )

        return cls(
            identifier=header & 0xC7,
            index=header & 0x7,
            tdu_class=tdu_class,
            data=data,
            payload_offset=offset,
            payload_length=length,
            total_length=1 + length_size + length,
            ends=ends,
            tdu_offset=start,
        )

    @classmethod
    def measure(
        cls,
        data: bytes | memoryview,
        offset: int = 0,
        ends: int | None = None,
        maximum_payload_length: int = DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
    ) -> ParsedTdu:
        """Delimit the TDU at ``offset`` without decoding anything (esiur-ts ``PlainTdu``).

        The packet layer uses this to find where a value ends; decoding is deferred because it
        may need the connection to resolve remote resources and TypeDefs. Unlike :meth:`parse`,
        a ``Typed`` TDU's metadata is not read, so ``payload`` covers metadata and value."""
        return cls.parse(data, offset, ends, maximum_payload_length, parse_metadata=False)
