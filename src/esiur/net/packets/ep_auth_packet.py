"""The authentication-phase packet (port of esiur-ts ``EpAuthPacket``).

Header byte ``[command:2][has-value:1][…]``. For ``INITIALIZE`` the low bits carry
``auth_mode << 2 | encryption_mode``; for every other command they carry the
:class:`EpAuthPacketMethod` (whose own top bits repeat the command). An optional TDU follows,
typically a ``TypedMap<UInt8, dynamic>`` keyed by :class:`EpAuthPacketHeader`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from esiur.data.guard import DEFAULT_MAXIMUM_PAYLOAD_LENGTH
from esiur.data.tdu import ParsedTdu
from esiur.security.modes import AuthenticationMode, EncryptionMode

from ._common import checked_tdu, parse_bounds
from .enums import EpAuthPacketCommand, EpAuthPacketMethod

_HAS_TDU = 0x20


@dataclass(slots=True)
class EpAuthPacket:
    command: int = EpAuthPacketCommand.INITIALIZE
    #: The method of a non-``INITIALIZE`` packet; ``INITIALIZE`` for an initialize packet.
    method: int = EpAuthPacketMethod.INITIALIZE
    #: Only meaningful for ``INITIALIZE`` (``NONE`` otherwise). A value from a peer that this
    #: version does not know stays a plain ``int`` for the caller to refuse.
    auth_mode: int = AuthenticationMode.NONE
    #: Only meaningful for ``INITIALIZE`` (``NONE`` otherwise); may be an unknown ``int`` (3).
    encryption_mode: int = EncryptionMode.NONE
    #: The headers, measured but not decoded (see ``EpPacket.tdu``).
    tdu: ParsedTdu | None = None

    @property
    def has_tdu(self) -> bool:
        return self.tdu is not None

    def parse(
        self,
        data: bytes | memoryview,
        offset: int = 0,
        ends: int | None = None,
        *,
        maximum_payload_length: int = DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
    ) -> int:
        """Read a packet from ``data[offset:ends]``; returns the bytes consumed, or ``-n`` when
        ``n`` more bytes are needed (the packet is left untouched)."""
        ends = parse_bounds(data, offset, ends)
        start = offset
        if offset >= ends:
            return -1

        header = data[offset]
        offset += 1
        command = header >> 6
        method: int = EpAuthPacketMethod.INITIALIZE
        auth_mode: int = AuthenticationMode.NONE
        encryption_mode: int = EncryptionMode.NONE
        if command == EpAuthPacketCommand.INITIALIZE:
            auth_mode = _known(AuthenticationMode, (header >> 2) & 0x3)
            encryption_mode = _known(EncryptionMode, header & 0x3)
        else:
            method = _known(EpAuthPacketMethod, header & 0xDF)

        tdu: ParsedTdu | None = None
        if header & _HAS_TDU:
            if offset >= ends:
                return -1
            tdu = ParsedTdu.measure(data, offset, ends, maximum_payload_length)
            if not tdu.valid:
                return -tdu.total_length
            offset += tdu.total_length

        self.command = EpAuthPacketCommand(command)
        self.method = method
        self.auth_mode = auth_mode
        self.encryption_mode = encryption_mode
        self.tdu = tdu
        return offset - start

    # ---- compose --------------------------------------------------------------------------

    @staticmethod
    def compose_initialize(
        auth_mode: AuthenticationMode | int,
        encryption_mode: EncryptionMode | int,
        headers_tdu: bytes | None = None,
    ) -> bytes:
        """An ``INITIALIZE`` packet; the two modes share the low four bits of the header."""
        if not 0 <= auth_mode <= 0x3 or not 0 <= encryption_mode <= 0x3:
            raise ValueError("The authentication and encryption modes must each fit in two bits.")
        value = checked_tdu(headers_tdu)
        header = (
            (EpAuthPacketCommand.INITIALIZE << 6)
            | (_HAS_TDU if headers_tdu is not None else 0)
            | (auth_mode << 2)
            | encryption_mode
        )
        return bytes([header]) + value

    @staticmethod
    def compose_method(method: EpAuthPacketMethod | int, headers_tdu: bytes | None = None) -> bytes:
        """A packet for any method; its top two bits already carry the command."""
        if not 0 <= method <= 0xFF or method & _HAS_TDU:
            raise ValueError("An authentication method must be a byte without the 0x20 bit.")
        value = checked_tdu(headers_tdu)
        header = method | (_HAS_TDU if headers_tdu is not None else 0)
        return bytes([header]) + value


def _known(enum_type: type[enum.IntEnum], value: int) -> int:
    """The enum member for ``value``, or ``value`` itself when this version has no such member."""
    try:
        return enum_type(value)
    except ValueError:
        return value
