"""Id-independent type definition signatures (port of esiur-ts ``typeDefSignature``).

``signature = LE64(first 8 bytes of SHA-256(canonical))`` where *canonical* is the normal wire
encoding of a definition's ``TypeDefInfo`` with every TypeDef id replaced by a hash of the name it
stands for. A node computes the signature of its own definitions; a client stores what it was sent.

While a signature is being composed, a :class:`~esiur.data.tru.TruTypeDef` writes ``LocalType64``
followed by ``name64(name)`` instead of its id. Python's ``TruTypeDef`` carries only an id, so the
active composition holds the ``name_of`` callable that maps an id back to the type's name.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
from collections.abc import Callable, Iterator

_NameOf = Callable[[int], str]
_ACTIVE: contextvars.ContextVar[_NameOf | None] = contextvars.ContextVar(
    "esiur_typedef_signature", default=None
)


def name_hash_source() -> _NameOf | None:
    """The id-to-name lookup of the signature being composed, or ``None`` outside one."""
    return _ACTIVE.get()


@contextlib.contextmanager
def signature_mode(name_of: _NameOf) -> Iterator[None]:
    """Compose with TypeDef references written by name hash. Nests and is task-local."""
    token = _ACTIVE.set(name_of)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def _first_u64(digest: bytes) -> int:
    return int.from_bytes(digest[:8], "little")


def name64(name: str) -> int:
    """First 8 bytes of SHA-256(UTF-8(name)), little endian."""
    return _first_u64(hashlib.sha256(name.encode("utf-8")).digest())


def signature_of(canonical: bytes) -> int:
    """The signature of already composed canonical bytes; zero is reserved for "unknown"."""
    return _first_u64(hashlib.sha256(canonical).digest()) or 1
