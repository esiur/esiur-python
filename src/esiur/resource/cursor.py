"""A position in a resource's ordered stream of property and event changes (port of esiur-ts
``ResourceCursor``): the id of the stream (its *generation*) and a revision within it."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

_EMPTY_GENERATION = uuid.UUID(int=0)
_MAXIMUM_REVISION = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class ResourceCursor:
    generation: uuid.UUID
    revision: int

    def __post_init__(self) -> None:
        if not 0 <= self.revision <= _MAXIMUM_REVISION:
            raise ValueError("A resource cursor revision must fit in 64 bits.")

    @classmethod
    def empty(cls) -> ResourceCursor:
        return cls(_EMPTY_GENERATION, 0)

    @classmethod
    def from_wire(cls, generation: object, revision: object) -> ResourceCursor:
        """Build a cursor from the two values it travels as: 16 raw bytes and an integer."""
        if (
            not isinstance(generation, bytes | bytearray)
            or len(generation) != 16
            or not isinstance(revision, int)
            or isinstance(revision, bool)
        ):
            raise ValueError("A resource cursor is a 16-byte generation and an integer revision.")
        return cls(uuid.UUID(bytes=bytes(generation)), revision)

    @property
    def generation_bytes(self) -> bytes:
        return self.generation.bytes

    @property
    def is_empty(self) -> bool:
        return self.revision == 0 and self.generation == _EMPTY_GENERATION

    def __str__(self) -> str:
        return f"{self.generation.hex}:{self.revision}"
