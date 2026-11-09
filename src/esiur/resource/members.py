"""Declaring what a resource class exports (the Python counterpart of esiur-ts ``@Export``).

::

    class Greeter(Resource):
        visits = Property(t.i32, default=0)           # a notifying property
        label = Property(t.string, default="hello")
        ping = Event(t.string)                        # a subscribable event
        tick = Event(t.string, auto_delivered=True)   # pushed to every attached peer

        @function(t.string, [t.string])
        def greet(self, name):                        # an exported function (sync or async)
            self.visits += 1
            self.ping.emit(f"greeted {name}")
            return f"Hi {name}"

Members are indexed in definition order (base classes first), which is what peers address them
by, so reorder or remove them only together with their clients. The declared types describe the
members to peers; values are written as they are, the way esiur-ts writes them.
"""

from __future__ import annotations

import inspect
import logging
import types
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast, overload

from esiur.data import Tru, t

if TYPE_CHECKING:
    from .resource import Resource

logger = logging.getLogger("esiur.resource")

_T = TypeVar("_T")

_NOT_GIVEN: Any = object()


class Property(Generic[_T]):
    """A property that tells its resource's :class:`~esiur.resource.Instance` when it changes,
    so attached peers are notified. Assign to it like any attribute."""

    def __init__(
        self,
        type: Tru | None = None,
        *,
        default: _T = _NOT_GIVEN,
        default_factory: Callable[[], _T] | None = None,
        read_only: bool = False,
        historical: bool = False,
        description: str | None = None,
        name: str | None = None,
    ) -> None:
        if historical:
            raise NotImplementedError("Historical members are not supported yet.")
        if default is not _NOT_GIVEN and default_factory is not None:
            raise ValueError("Give a default or a default_factory, not both.")
        self.type = type if type is not None else t.dynamic
        self.read_only = read_only
        self.description = description
        self.name = name or ""
        self._default = default
        self._default_factory = default_factory
        self.attribute = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self.attribute = name
        self.name = self.name or name

    def initial(self) -> _T:
        if self._default_factory is not None:
            return self._default_factory()
        return None if self._default is _NOT_GIVEN else self._default  # type: ignore[return-value]

    @overload
    def __get__(self, obj: None, owner: type) -> Property[_T]: ...
    @overload
    def __get__(self, obj: object, owner: type) -> _T: ...
    def __get__(self, obj: object | None, owner: type) -> Property[_T] | _T:
        if obj is None:
            return self
        values = obj.__dict__
        if self.attribute not in values:
            values[self.attribute] = self.initial()
        return values[self.attribute]  # type: ignore[no-any-return]

    def __set__(self, obj: object, value: _T) -> None:
        obj.__dict__[self.attribute] = value
        instance = getattr(obj, "instance", None)
        if instance is not None:
            instance.modified(self, value)


class EventSource:
    """The object an :class:`Event` attribute evaluates to on a resource."""

    def __init__(self, resource: Resource, event: Event) -> None:
        self._resource = resource
        self._event = event
        self._listeners: list[Callable[[Any], Any]] = []

    def listen(self, listener: Callable[[Any], Any]) -> None:
        """Call ``listener(value)`` whenever the event is raised in this process."""
        self._listeners.append(listener)

    def unlisten(self, listener: Callable[[Any], Any]) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def emit(self, value: Any = None) -> None:
        """Raise the event: local listeners run, then attached peers that want it are told."""
        for listener in list(self._listeners):
            try:
                result = listener(value)
                if inspect.isawaitable(result):
                    _ensure_future(result)
            except Exception:
                logger.exception("A listener of %s.%s failed", type(self._resource).__name__,
                                 self._event.name)
        instance = self._resource.instance
        if instance is not None:
            instance.event_occurred(self._event, value)


def _ensure_future(awaitable: Any) -> None:
    import asyncio

    asyncio.ensure_future(awaitable)


class Event:
    """An exported event. Raise it with ``self.<name>.emit(value)``."""

    def __init__(
        self,
        type: Tru | None = None,
        *,
        auto_delivered: bool = False,
        historical: bool = False,
        description: str | None = None,
        argument_name: str | None = None,
        name: str | None = None,
    ) -> None:
        if historical:
            raise NotImplementedError("Historical members are not supported yet.")
        self.type = type if type is not None else t.void
        self.auto_delivered = auto_delivered
        self.description = description
        self.argument_name = argument_name
        self.name = name or ""
        self.attribute = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self.attribute = name
        self.name = self.name or name

    @overload
    def __get__(self, obj: None, owner: type) -> Event: ...
    @overload
    def __get__(self, obj: object, owner: type) -> EventSource: ...
    def __get__(self, obj: object | None, owner: type) -> Event | EventSource:
        if obj is None:
            return self
        source = obj.__dict__.get(self.attribute)
        if not isinstance(source, EventSource):
            source = obj.__dict__[self.attribute] = EventSource(cast("Resource", obj), self)
        return source


class Function:
    """An exported function: what ``@function`` turns a method into. Calling it on a resource
    object still just calls the method."""

    def __init__(
        self,
        implementation: Callable[..., Any],
        returns: Tru | None,
        args: list[Tru] | None,
        *,
        static: bool,
        read_only: bool,
        idempotent: bool,
        description: str | None,
        name: str | None,
    ) -> None:
        self.implementation = implementation
        self.returns = returns if returns is not None else t.dynamic
        self.static = static
        self.read_only = read_only
        self.idempotent = idempotent
        self.description = description
        self.name = name or implementation.__name__
        self.attribute = implementation.__name__

        parameters = list(inspect.signature(implementation).parameters.values())
        if not static:
            if not parameters:
                raise TypeError(f"'{self.name}' must take 'self' (or be exported static=True).")
            parameters = parameters[1:]
        if any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD, p.KEYWORD_ONLY) for p in parameters):
            raise TypeError(f"'{self.name}': exported functions take positional parameters only.")
        self.parameters = parameters
        self.argument_types: list[Tru]
        if args is None:
            self.argument_types = [t.dynamic] * len(parameters)
        elif len(args) != len(parameters):
            raise TypeError(
                f"'{self.name}' declares {len(args)} argument types but takes "
                f"{len(parameters)} parameters."
            )
        else:
            self.argument_types = list(args)

    def __set_name__(self, owner: type, name: str) -> None:
        self.attribute = name

    @overload
    def __get__(self, obj: None, owner: type) -> Function: ...
    @overload
    def __get__(self, obj: object, owner: type) -> Callable[..., Any]: ...
    def __get__(self, obj: object | None, owner: type) -> Function | Callable[..., Any]:
        if obj is None:
            return self
        if self.static:
            return self.implementation
        return types.MethodType(self.implementation, obj)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - class-level use
        return self.implementation(*args, **kwargs)


@overload
def function(returns: Callable[..., Any], /) -> Function: ...
@overload
def function(
    returns: Tru | None = None,
    args: list[Tru] | None = None,
    *,
    static: bool = False,
    read_only: bool = False,
    idempotent: bool = False,
    description: str | None = None,
    name: str | None = None,
) -> Callable[[Callable[..., Any]], Function]: ...
def function(
    returns: Any = None,
    args: list[Tru] | None = None,
    *,
    static: bool = False,
    read_only: bool = False,
    idempotent: bool = False,
    description: str | None = None,
    name: str | None = None,
) -> Any:
    """Export a method (sync or ``async``). Used bare, or with the return type and the argument
    types: ``@function(t.string, [t.string])``. ``static=True`` exports a function that belongs to
    the type, not to a resource (it takes no ``self``)."""
    if callable(returns) and not isinstance(returns, Tru):
        return Function(
            returns, None, None, static=False, read_only=False, idempotent=False,
            description=None, name=None,
        )

    def decorate(implementation: Callable[..., Any]) -> Function:
        return Function(
            implementation, returns, args, static=static, read_only=read_only,
            idempotent=idempotent, description=description, name=name,
        )

    return decorate
