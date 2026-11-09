"""The EP packet (port of esiur-ts ``EpPacket``).

Layout: a header byte ``[method:2][has-value:1][action:5]``, a four-byte little-endian callback
id for requests and replies, then an optional value as one self-describing TDU. The value is only
delimited here; decoding it may need the connection (remote resources, TypeDefs), so it is left
to the caller, who holds the registry and the budgets.
"""

from __future__ import annotations

from dataclasses import dataclass

from esiur.data.guard import DEFAULT_MAXIMUM_PAYLOAD_LENGTH
from esiur.data.tdu import ParsedTdu

from ._common import checked_tdu, parse_bounds
from .enums import EpPacketMethod, EpPacketNotification, EpPacketReply, EpPacketRequest

_HAS_TDU = 0x20


@dataclass(slots=True)
class EpPacket:
    method: int = EpPacketMethod.NOTIFICATION
    #: The low five bits of the header: an :class:`EpPacketRequest`, :class:`EpPacketReply` or
    #: :class:`EpPacketNotification` depending on ``method`` (or an extension action). The enums
    #: are ``IntEnum``\ s, so ``packet.action == EpPacketRequest.KEEP_ALIVE`` works directly.
    action: int = 0
    callback_id: int = 0
    #: The value, measured but not decoded; it points into the buffer passed to :meth:`parse`,
    #: so decode it (``parse(packet.tdu.tdu_bytes, ...)``) before that buffer is reused.
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
        """Read a packet from ``data[offset:ends]``.

        Returns the number of bytes consumed, or ``-n`` when the buffer is short and ``n`` more
        bytes are needed (the packet is left untouched; call again once they have arrived).
        Raises :class:`~esiur.data.ParserLimitError` for a value that declares more than
        ``maximum_payload_length`` bytes.
        """
        ends = parse_bounds(data, offset, ends)
        start = offset
        if offset >= ends:
            return -1

        header = data[offset]
        offset += 1
        method = header >> 6
        action = header & 0x1F
        callback_id = 0

        if method in (EpPacketMethod.REQUEST, EpPacketMethod.REPLY):
            if ends - offset < 4:
                return -(4 - (ends - offset))
            callback_id = int.from_bytes(data[offset : offset + 4], "little")
            offset += 4

        tdu: ParsedTdu | None = None
        if header & _HAS_TDU:
            if offset >= ends:
                return -1
            tdu = ParsedTdu.measure(data, offset, ends, maximum_payload_length)
            if not tdu.valid:
                return -tdu.total_length
            offset += tdu.total_length

        self.method = EpPacketMethod(method)
        self.action = action
        self.callback_id = callback_id
        self.tdu = tdu
        return offset - start

    # ---- compose --------------------------------------------------------------------------

    @staticmethod
    def _compose(
        method: EpPacketMethod, action: int, callback_id: int | None, tdu: bytes | None
    ) -> bytes:
        if not 0 <= action <= 0x1F:
            raise ValueError("A packet action must fit in five bits.")
        value = checked_tdu(tdu)
        header = (method << 6) | (_HAS_TDU if tdu is not None else 0) | action
        if callback_id is None:
            return bytes([header]) + value
        if not 0 <= callback_id <= 0xFFFF_FFFF:
            raise ValueError("A callback id must fit in 32 bits.")
        return bytes([header]) + callback_id.to_bytes(4, "little") + value

    @staticmethod
    def compose_request(
        action: EpPacketRequest | int, callback_id: int, tdu: bytes | None = None
    ) -> bytes:
        """A request packet. ``tdu`` is the argument, already composed as one TDU."""
        return EpPacket._compose(EpPacketMethod.REQUEST, action, callback_id, tdu)

    @staticmethod
    def compose_reply(
        action: EpPacketReply | int, callback_id: int, tdu: bytes | None = None
    ) -> bytes:
        """A reply packet. ``tdu`` is the result, already composed as one TDU."""
        return EpPacket._compose(EpPacketMethod.REPLY, action, callback_id, tdu)

    @staticmethod
    def compose_notification(action: EpPacketNotification | int, tdu: bytes | None = None) -> bytes:
        """A notification packet (no callback id)."""
        return EpPacket._compose(EpPacketMethod.NOTIFICATION, action, None, tdu)
