"""Small value types that have no native Python counterpart."""

from __future__ import annotations

from dataclasses import dataclass


class _NotModifiedType:
    """Sentinel meaning "value unchanged" (port of C# ``NotModified``)."""

    _instance: _NotModifiedType | None = None

    def __new__(cls) -> _NotModifiedType:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "NotModified"

    def __bool__(self) -> bool:
        return False


NotModified = _NotModifiedType()


@dataclass(frozen=True, slots=True)
class ResourceId:
    """A resource reference decoded without a connection to resolve it."""

    local: bool
    id: int


class ResourceLink(str):
    """A textual link to a resource, e.g. ``ep://host/path``."""

    __slots__ = ()
