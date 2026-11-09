"""A hosted class's exported surface: the members its decorators declared, and the TypeDef a
peer is shown (port of esiur-ts ``getTypeDef`` and ``typeDefInfoFromTypeDef``)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from esiur.data import (
    ArgumentDefFlags,
    ArgumentDefInfo,
    EventDefFlags,
    EventDefInfo,
    FunctionDefFlags,
    FunctionDefInfo,
    PropertyDefFlags,
    PropertyDefInfo,
    TypeDefInfo,
    TypeDefKind,
)
from esiur.data.typedef_signature import typedef_signature

from .members import Event, Function, Property
from .typedef import TypeDef


@dataclass(eq=False)
class HostedType:
    """One hosted class: its members by wire index, and its definition."""

    cls: type
    id: int
    info: TypeDefInfo
    typedef: TypeDef
    properties: tuple[Property[object], ...]
    functions: tuple[Function, ...]
    events: tuple[Event, ...]

    @property
    def name(self) -> str:
        return self.info.name

    def __repr__(self) -> str:
        return f"HostedType({self.name!r}, id={self.id})"


def declared_members(
    cls: type,
) -> tuple[tuple[Property[object], ...], tuple[Function, ...], tuple[Event, ...]]:
    """The members of ``cls`` in index order: base classes first, each in the order it declared
    them; a subclass that redeclares a member keeps its place."""
    found: dict[str, Property[object] | Function | Event] = {}
    for klass in reversed(cls.__mro__):
        for attribute, value in vars(klass).items():
            if isinstance(value, Property | Function | Event):
                found[attribute] = value  # redeclaring keeps the member's place
    properties = tuple(m for m in found.values() if isinstance(m, Property))
    functions = tuple(m for m in found.values() if isinstance(m, Function))
    events = tuple(m for m in found.values() if isinstance(m, Event))
    for kind in (properties, functions, events):
        names = [member.name for member in kind]
        if len(set(names)) != len(names):
            raise TypeError(f"{cls.__name__} exports two members of one kind named alike.")
    return properties, functions, events


def describe(cls: type, type_id: int, name_of: Callable[[int], str]) -> HostedType:
    """Build the definition of ``cls`` under ``type_id``."""
    properties, functions, events = declared_members(cls)
    info = TypeDefInfo(
        id=type_id,
        kind=TypeDefKind.RESOURCE,
        name=cls.__name__,
        namespace=None,
        description=(cls.__doc__ or "").strip() or None,
    )
    info.properties = [_property_info(i, p) for i, p in enumerate(properties)]
    info.functions = [_function_info(i, f) for i, f in enumerate(functions)]
    info.events = [_event_info(i, e) for i, e in enumerate(events)]
    info.constants = []
    info.signature = typedef_signature(info, name_of)
    return HostedType(cls, type_id, info, TypeDef(info), properties, functions, events)


def _property_info(index: int, source: Property[object]) -> PropertyDefInfo:
    return PropertyDefInfo(
        index=index,
        name=source.name,
        flags=int(PropertyDefFlags.READ_ONLY if source.read_only else PropertyDefFlags.NONE),
        value_type=source.type,
        description=source.description,
    )


def _function_info(index: int, source: Function) -> FunctionDefInfo:
    flags = FunctionDefFlags.NONE
    if source.static:
        flags |= FunctionDefFlags.STATIC
    if source.read_only:
        flags |= FunctionDefFlags.READ_ONLY
    if source.idempotent:
        flags |= FunctionDefFlags.IDEMPOTENT
    return FunctionDefInfo(
        index=index,
        name=source.name,
        flags=int(flags),
        return_type=source.returns,
        description=source.description,
        arguments=[
            ArgumentDefInfo(
                index=position,
                name=parameter.name,
                flags=int(
                    ArgumentDefFlags.OPTIONAL
                    if parameter.default is not parameter.empty
                    else ArgumentDefFlags.NONE
                ),
                value_type=argument_type,
            )
            for position, (parameter, argument_type) in enumerate(
                zip(source.parameters, source.argument_types, strict=True)
            )
        ],
    )


def _event_info(index: int, source: Event) -> EventDefInfo:
    return EventDefInfo(
        index=index,
        name=source.name,
        flags=int(EventDefFlags.AUTO_DELIVERED if source.auto_delivered else EventDefFlags.NONE),
        argument_type=source.type,
        argument_name=source.argument_name,
        description=source.description,
    )
