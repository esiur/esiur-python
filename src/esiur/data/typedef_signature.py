"""The signature of a type definition this node serves (port of esiur-ts
``protocol/typeDefSigning.computeTypeDefSignature``; see ``docs/typedef-sync.md`` there).

It is a hash of the definition's normal wire encoding with its own id zeroed and every type
reference written as the hash of the referenced type's name, so two nodes that assigned different
ids to the same contract still agree on it.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from .codec import compose
from .signature import name64, signature_mode, signature_of
from .typedefinfo import TypeDefInfo


def typedef_signature(info: TypeDefInfo, name_of: Callable[[int], str]) -> int:
    """The id-independent signature of ``info``. ``name_of`` maps a TypeDef id (a reference, or
    the parent) to the name of the type it stands for; it may raise ``KeyError``/``LookupError``
    for an id it cannot name, which drops an unnameable parent from the hash instead of its id."""
    canonical = dataclasses.replace(info, id=0, signature=None)
    if canonical.parent is not None:
        try:
            canonical.parent = name64(name_of(canonical.parent))
        except LookupError:
            canonical.parent = None
    with signature_mode(name_of):
        return signature_of(compose(canonical))
