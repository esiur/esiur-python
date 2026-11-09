"""Helpers shared by the two packet classes."""

from __future__ import annotations

from esiur.data.tdu import ParsedTdu


def parse_bounds(data: bytes | memoryview, offset: int, ends: int | None) -> int:
    """Validate the ``[offset, ends)`` window of a parse call and return ``ends``."""
    if ends is None:
        ends = len(data)
    if not 0 <= offset <= ends <= len(data):
        raise ValueError(f"Invalid window [{offset}, {ends}) for a buffer of {len(data)} bytes.")
    return ends


def checked_tdu(tdu: bytes | None) -> bytes:
    """The optional value of a packet being composed, which must be exactly one complete TDU:
    anything else would shift every later packet on the stream out of frame."""
    if tdu is None:
        return b""
    # The size budget is the receiver's business; only the framing is checked here.
    measured = ParsedTdu.measure(tdu, 0, len(tdu), 0)
    if not measured.valid or measured.total_length != len(tdu):
        raise ValueError("A packet's value must be exactly one complete TDU.")
    return tdu
