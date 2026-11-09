"""Limits a node applies to what it receives, and advertises to its peers."""

from __future__ import annotations

from dataclasses import dataclass

from esiur.data.guard import (
    DEFAULT_MAXIMUM_ALLOCATION_SIZE,
    DEFAULT_MAXIMUM_COLLECTION_ITEMS,
    DEFAULT_MAXIMUM_PAYLOAD_LENGTH,
    DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH,
)


@dataclass(slots=True)
class ParserConfiguration:
    """Parser budgets (esiur-ts ``ParserConfiguration`` plus the encrypted-record cap). A
    value of ``0`` disables that limit. Each is sent to the peer during the handshake, so the
    peer refuses to compose anything this node would reject."""

    #: Largest TDU payload accepted, in bytes.
    maximum_packet_size: int = DEFAULT_MAXIMUM_PAYLOAD_LENGTH
    #: Largest allocation one decoded value may cause.
    maximum_allocation_size: int = DEFAULT_MAXIMUM_ALLOCATION_SIZE
    #: Most values decoded into one collection.
    maximum_collection_items: int = DEFAULT_MAXIMUM_COLLECTION_ITEMS
    #: Deepest recursion of TRU metadata.
    maximum_type_metadata_depth: int = DEFAULT_MAXIMUM_TYPE_METADATA_DEPTH
    #: Largest protected record accepted once encryption is on.
    maximum_encrypted_record_size: int = DEFAULT_MAXIMUM_PAYLOAD_LENGTH + 1024

    def parse_limits(self) -> dict[str, int]:
        """The keyword arguments ``esiur.data.parse`` takes."""
        return {
            "maximum_payload_length": self.maximum_packet_size,
            "maximum_allocation_size": self.maximum_allocation_size,
            "maximum_collection_items": self.maximum_collection_items,
            "maximum_type_metadata_depth": self.maximum_type_metadata_depth,
        }
