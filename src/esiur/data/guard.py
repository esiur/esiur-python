"""Parser budgets (port of esiur-ts ``ParserGuard``; defaults match esiur-dotnet)."""

from __future__ import annotations

DEFAULT_MAXIMUM_PAYLOAD_LENGTH = 8 * 1024 * 1024
DEFAULT_MAXIMUM_ALLOCATION_SIZE = 4 * 1024 * 1024
DEFAULT_MAXIMUM_COLLECTION_ITEMS = 65_536
DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH = 64
DEFAULT_MAXIMUM_VALUE_DEPTH = 64


class ParserError(ValueError):
    """The bytes are not a valid Esiur value."""


class ParserLimitError(ParserError):
    """A declared size exceeded a configured parser budget."""


def ensure_packet_size(declared_length: int, maximum_payload_length: int) -> None:
    """Reject an oversized length declaration before anything is allocated or awaited.

    A non-positive maximum disables the limit.
    """
    if maximum_payload_length > 0 and declared_length > maximum_payload_length:
        raise ParserLimitError(
            f"Declared packet payload of {declared_length} bytes exceeds "
            f"the {maximum_payload_length}-byte limit."
        )


def ensure_collection_count(count: int, maximum_items: int) -> None:
    if maximum_items > 0 and count > maximum_items:
        raise ParserLimitError(
            f"Collection of {count} items exceeds the {maximum_items}-item limit."
        )


def ensure_allocation(size: int, maximum_allocation_size: int, kind: str) -> None:
    """Reject a decoded value that would allocate more than the configured budget."""
    if maximum_allocation_size > 0 and size > maximum_allocation_size:
        raise ParserLimitError(
            f"Decoded {kind} allocation of {size} bytes exceeds "
            f"the {maximum_allocation_size}-byte limit."
        )


def ensure_type_metadata_depth(depth: int, maximum_depth: int) -> None:
    """Reject recursively nested TRU metadata before it can exhaust the stack."""
    if maximum_depth > 0 and depth > maximum_depth:
        raise ParserLimitError(
            f"TRU type metadata depth of {depth} exceeds the configured limit of {maximum_depth}."
        )
