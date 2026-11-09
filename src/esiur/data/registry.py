"""Local type definitions for records and enums, and the registry that resolves them.

A record or enum value travels as a ``Typed`` TDU whose metadata is a ``TruTypeDef`` (the id of
its definition); the definition itself is agreed out of band (a ``TypeDef`` TDU, or both sides
registering the same type). :class:`TypeRegistry` is that agreement for this process: pass it as
``types=`` to :func:`~esiur.data.compose` and :func:`~esiur.data.parse`.

Ids are handed out from 1 in registration order, like esiur-ts's ``Warehouse``, unless a type is
registered with an explicit ``id``.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .guard import ParserError
from .tru import Tru
from .typedefinfo import TypeDefKind


@dataclass(frozen=True, slots=True)
class TypeDefProperty:
    name: str
    value_type: Tru | None = None


@dataclass(frozen=True, slots=True)
class TypeDefConstant:
    name: str
    value: Any
    index: int


@dataclass(eq=False)
class TypeDefinition:
    """A registered record or enum: what the serializer needs to read and write its values."""

    id: int
    kind: TypeDefKind
    name: str
    properties: tuple[TypeDefProperty, ...] = ()
    constants: tuple[TypeDefConstant, ...] = ()
    python_type: type | None = None
    #: Builds an empty record before its properties are assigned.
    factory: Callable[[], Any] | None = None

    def create(self) -> Any:
        if self.factory is not None:
            return self.factory()
        if self.python_type is None:
            raise TypeError(f"TypeDef '{self.name}' has no Python type to instantiate.")
        # Skip __init__: every property is assigned from the wire, and a record's constructor
        # may require arguments.
        return object.__new__(self.python_type)

    def set_property(self, instance: Any, name: str, value: Any) -> None:
        object.__setattr__(instance, name, value)  # also works on frozen dataclasses

    def constant_index(self, value: Any) -> int | None:
        raw = value.value if isinstance(value, enum.Enum) else value
        for constant in self.constants:
            if constant.value == raw:
                return constant.index
        return None

    def constant_value(self, index: int) -> Any:
        try:
            raw = self.constants[index].value
        except IndexError:
            raise ParserError(f"Enum '{self.name}' has no constant at index {index}.") from None
        if self.python_type is not None and issubclass(self.python_type, enum.Enum):
            return self.python_type(raw)
        return raw


class TypeRegistry:
    """The record and enum definitions known to this process."""

    def __init__(self) -> None:
        self._by_id: dict[int, TypeDefinition] = {}
        self._by_type: dict[type, TypeDefinition] = {}
        self._counter = 0

    def _allocate(self, requested: int | None) -> int:
        if requested is not None:
            if not 0 < requested < (1 << 64):
                raise ValueError("A TypeDef id must be between 1 and 2**64 - 1.")
            if requested in self._by_id:
                raise ValueError(f"TypeDef id {requested} is already registered.")
            return requested
        while True:
            self._counter += 1
            if self._counter not in self._by_id:
                return self._counter

    def add(self, definition: TypeDefinition) -> TypeDefinition:
        """Register a prebuilt definition (for example one received from a peer)."""
        if definition.id in self._by_id:
            raise ValueError(f"TypeDef id {definition.id} is already registered.")
        if definition.python_type is not None and definition.python_type in self._by_type:
            raise ValueError(f"{definition.python_type.__name__} is already registered.")
        self._by_id[definition.id] = definition
        if definition.python_type is not None:
            self._by_type[definition.python_type] = definition
        return definition

    def register_record(
        self,
        cls: type,
        properties: Sequence[str | tuple[str, Tru | None] | TypeDefProperty] | None = None,
        *,
        name: str | None = None,
        id: int | None = None,
        factory: Callable[[], Any] | None = None,
    ) -> TypeDefinition:
        """Register ``cls`` as a record. ``properties`` lists, in wire order, each property's
        attribute name (optionally with its declared Tru); it defaults to a dataclass's fields."""
        if properties is None:
            if not dataclasses.is_dataclass(cls):
                raise TypeError("List the record's properties, or register a dataclass.")
            properties = [f.name for f in dataclasses.fields(cls)]
        normalized = tuple(_property(p) for p in properties)
        names = [p.name for p in normalized]
        if len(set(names)) != len(names):
            raise ValueError("A record cannot have two properties with the same name.")
        return self.add(
            TypeDefinition(
                self._allocate(id), TypeDefKind.RECORD, name or cls.__name__, normalized,
                (), cls, factory,
            )
        )

    def register_enum(
        self, cls: type[enum.Enum], *, name: str | None = None, id: int | None = None
    ) -> TypeDefinition:
        """Register an ``Enum``; a member travels as its position in definition order."""
        constants = tuple(
            TypeDefConstant(member.name, member.value, index)
            for index, member in enumerate(cls)
        )
        if len(constants) > 256:
            raise ValueError("An enum travels as a one-byte index, so it has at most 256 members.")
        return self.add(
            TypeDefinition(
                self._allocate(id), TypeDefKind.ENUM, name or cls.__name__, (), constants, cls
            )
        )

    def by_id(self, type_id: int) -> TypeDefinition:
        try:
            return self._by_id[type_id]
        except KeyError:
            raise ParserError(f"TypeDef {type_id} is not registered.") from None

    def name_of(self, type_id: int) -> str:
        """The name a TypeDef id stands for; raises ``KeyError`` for an unregistered id."""
        try:
            return self._by_id[type_id].name
        except KeyError:
            raise KeyError(f"TypeDef {type_id} is not registered.") from None

    def definition_of(self, value: Any) -> TypeDefinition | None:
        """The definition of a registered record or enum value, or ``None``."""
        # Exact type only, like esiur-ts: a subclass has members the definition does not list.
        return self._by_type.get(type(value))

    def __len__(self) -> int:
        return len(self._by_id)


def _property(spec: str | tuple[str, Tru | None] | TypeDefProperty) -> TypeDefProperty:
    if isinstance(spec, TypeDefProperty):
        return spec
    if isinstance(spec, str):
        return TypeDefProperty(spec)
    return TypeDefProperty(spec[0], spec[1])
