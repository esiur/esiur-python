"""What a connection does for a peer that asks for the resources a warehouse hosts (the server
side of esiur-ts ``EpConnection``: ``epRequestAttachResource`` and its siblings).

A :class:`HostedSession` belongs to one connection. It answers the peer's requests (attach,
invoke, set, subscribe, TypeDefs ...), and keeps the peer informed of the changes of every
resource it attached to.

Not ported yet, and answered ``NOT_IMPLEMENTED``: reattach, TypeDef synchronization, queries,
creating, deleting and moving resources, streaming calls and journal queries.
"""

from __future__ import annotations

import datetime as dt
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.data import (
    ParsedTdu,
    ParserError,
    ResourceId,
    UInt8,
    UInt64,
    compose,
)
from esiur.resource import (
    EventOccurred,
    Function,
    Property,
    PropertyModified,
    Resource,
    Warehouse,
)
from esiur.security.permissions import ActionType

from .packets import EpPacketNotification, EpPacketReply, EpPacketRequest

if TYPE_CHECKING:
    from .connection import EpConnection

logger = logging.getLogger("esiur.net")

Handler = Callable[[int, ParsedTdu | None], Awaitable[None]]


class _Refusal(Exception):
    """A request the peer is answered with an error for."""

    def __init__(
        self, kind: ErrorType, code: ExceptionCode, message: str = ""
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.code = code
        self.message = message


def _refuse(code: ExceptionCode, message: str = "") -> _Refusal:
    return _Refusal(ErrorType.MANAGEMENT, code, message)


class HostedSession:
    """The server half of one :class:`~esiur.net.EpConnection`."""

    def __init__(self, connection: EpConnection, warehouse: Warehouse) -> None:
        self.connection = connection
        self.warehouse = warehouse
        #: Attached instance id -> stops the notifications for the peer.
        self._attached: dict[int, Callable[[], None]] = {}
        #: Instance id -> indexes of the events the peer subscribed to.
        self._events: dict[int, set[int]] = {}
        self._attaching: set[int] = set()
        self._handlers: dict[int, Handler] = {
            EpPacketRequest.ATTACH_RESOURCE: self._attach,
            EpPacketRequest.DETACH_RESOURCE: self._detach,
            EpPacketRequest.GET_RESOURCE_ID_BY_LINK: self._resource_id_by_link,
            EpPacketRequest.TYPEDEF_BY_ID: self._typedef_by_id,
            EpPacketRequest.TYPEDEF_BY_RESOURCE_ID: self._typedef_by_resource_id,
            EpPacketRequest.INVOKE_FUNCTION: self._invoke,
            EpPacketRequest.STATIC_CALL: self._static_call,
            EpPacketRequest.SET_PROPERTY: self._set_property,
            EpPacketRequest.SUBSCRIBE: self._subscribe,
            EpPacketRequest.UNSUBSCRIBE: self._unsubscribe,
        }

    # ---- entry points ---------------------------------------------------------------------

    def handler_for(self, action: int) -> Handler | None:
        return self._handlers.get(action)

    async def run(self, handler: Handler, callback_id: int, tdu: ParsedTdu | None) -> None:
        """Run a handler and turn whatever goes wrong into the error reply it deserves."""
        try:
            await handler(callback_id, tdu)
        except _Refusal as refusal:
            self.connection.send_error(refusal.kind, callback_id, refusal.code, refusal.message)
        except AsyncException as error:
            self.connection.send_error(error.type, callback_id, error.code, error.message)
        except (ParserError, NotImplementedError) as error:
            self.connection.send_error(
                ErrorType.MANAGEMENT, callback_id, ExceptionCode.PARSE_ERROR, str(error)
            )
        except Exception as error:
            logger.exception("EP request %s failed", handler.__name__)
            self.connection.send_error(
                ErrorType.EXCEPTION,
                callback_id,
                ExceptionCode.RUNTIME_EXCEPTION,
                f"{type(error).__name__}: {error}",
            )

    def close(self) -> None:
        """The connection ended: stop watching every resource."""
        stops, self._attached = list(self._attached.values()), {}
        self._events.clear()
        for stop in stops:
            stop()

    # ---- helpers --------------------------------------------------------------------------

    def _values(self, tdu: ParsedTdu | None, minimum: int) -> list[Any]:
        if tdu is None:
            raise _refuse(ExceptionCode.PARSE_ERROR, "The request carries no value.")
        value = self.connection.decode(tdu)
        if minimum == 1 and not isinstance(value, list):
            return [value]
        if not isinstance(value, list) or len(value) < minimum:
            raise _refuse(ExceptionCode.PARSE_ERROR, f"The request needs {minimum} values.")
        return value

    @staticmethod
    def _integer(value: Any, what: str = "value") -> int:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        raise _refuse(ExceptionCode.PARSE_ERROR, f"The {what} must be an integer.")

    def _resource(self, instance_id: Any) -> Resource:
        resource = self.warehouse.get_by_id(self._integer(instance_id, "resource id"))
        if resource is None or resource.instance is None:
            raise _refuse(ExceptionCode.RESOURCE_NOT_FOUND)
        return resource

    def _permit(
        self,
        resource: Resource | None,
        action: ActionType,
        member: Any,
        code: ExceptionCode,
    ) -> None:
        verdict = self.warehouse.evaluate(
            resource, getattr(self.connection, "session", None), action, member, self.connection
        )
        if not verdict.allowed:
            raise _refuse(code, verdict.reason or "")

    async def _materialize(self, value: Any) -> Any:
        """Replace the resource references of a decoded argument with the resources: the
        ones this node hosts, and proxies for the ones the peer hosts."""
        if isinstance(value, ResourceId):
            if value.local:
                resource = self.warehouse.get_by_id(value.id)
                if resource is None:
                    raise _refuse(ExceptionCode.RESOURCE_NOT_FOUND)
                return resource
            return await self.connection._resolve_resource(value.id)
        if isinstance(value, list) and _has_reference(value):
            return [await self._materialize(item) for item in value]
        if isinstance(value, tuple) and _has_reference(value):
            return tuple([await self._materialize(item) for item in value])
        if isinstance(value, dict) and _has_reference(value):
            return {key: await self._materialize(item) for key, item in value.items()}
        return value

    def _compose(self, value: Any) -> bytes:
        return self.connection.compose_value(value)

    # ---- attach and detach ----------------------------------------------------------------

    async def _attach(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        instance_id = self._integer(self._values(tdu, 1)[0], "resource id")
        if instance_id in self._attached or instance_id in self._attaching:
            raise _refuse(
                ExceptionCode.ALREADY_ATTACHED,
                f"Resource {instance_id} is already attached or being attached by this "
                "connection.",
            )
        self._attaching.add(instance_id)
        try:
            resource = self._resource(instance_id)
            self._permit(resource, ActionType.ATTACH, None, ExceptionCode.ATTACH_DENIED)
            instance = resource.instance
            assert instance is not None
            cursor = instance.cursor
            snapshot = b"".join(
                self._compose(part)
                for index in range(len(instance.type.properties))
                for part in (
                    instance.age_of(index),
                    instance.modified_at(index),
                    instance.value_of(index),
                )
            )
            self._watch(instance_id, resource)
            self.connection.send_reply(
                EpPacketReply.COMPLETED,
                callback_id,
                UInt64(instance.type.id),
                cursor.generation_bytes,
                UInt64(cursor.revision),
                instance.link or "",
                UInt8(0),  # hops
                snapshot,
            )
        finally:
            self._attaching.discard(instance_id)

    def _watch(self, instance_id: int, resource: Resource) -> None:
        instance = resource.instance
        assert instance is not None

        def property_changed(change: PropertyModified) -> None:
            self._notify(
                EpPacketNotification.PROPERTY_MODIFIED,
                instance_id,
                change.cursor,
                change.recorded_at,
                change.index,
                change.value,
            )

        def event_raised(occurrence: EventOccurred) -> None:
            event = instance.type.events[occurrence.index]
            if (
                not event.auto_delivered
                and occurrence.index not in self._events.get(instance_id, ())
            ):
                return
            self._notify(
                EpPacketNotification.EVENT_OCCURRED,
                instance_id,
                occurrence.cursor,
                occurrence.recorded_at,
                occurrence.index,
                occurrence.value,
            )

        instance.add_property_listener(property_changed)
        instance.add_event_listener(event_raised)

        def stop() -> None:
            instance.remove_property_listener(property_changed)
            instance.remove_event_listener(event_raised)

        self._attached[instance_id] = stop

    def _notify(
        self,
        action: EpPacketNotification,
        instance_id: int,
        cursor: Any,
        recorded_at: dt.datetime,
        index: int,
        value: Any,
    ) -> None:
        try:
            self.connection.send_notification(
                action,
                instance_id,
                cursor.generation_bytes,
                UInt64(cursor.revision),
                recorded_at,
                index,
                value,
            )
        except Exception:
            # A value this peer cannot be sent must not stop the others from being told.
            logger.exception("EP could not send a notification of resource %d", instance_id)

    async def _detach(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        resource = self._resource(self._values(tdu, 1)[0])
        self._permit(resource, ActionType.DETACH, None, ExceptionCode.NOT_ALLOWED)
        assert resource.instance is not None
        instance_id = resource.instance.id
        stop = self._attached.pop(instance_id, None)
        self._events.pop(instance_id, None)
        if stop is not None:
            stop()
        self.connection.send_reply(EpPacketReply.COMPLETED, callback_id)

    # ---- links and types ------------------------------------------------------------------

    async def _resource_id_by_link(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        link = self._values(tdu, 1)[0]
        resource = await self.warehouse.query(str(link or ""))
        if resource is None or resource.instance is None:
            raise _refuse(ExceptionCode.RESOURCE_NOT_FOUND)
        self.connection.send_reply(EpPacketReply.COMPLETED, callback_id, resource.instance.id)

    async def _typedef_by_id(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        type_id = self._integer(self._values(tdu, 1)[0], "type id")
        try:
            hosted = self.warehouse.type_by_id(type_id)
        except KeyError:
            raise _refuse(ExceptionCode.TYPEDEF_NOT_FOUND) from None
        self._permit(None, ActionType.VIEW_TYPEDEF, None, ExceptionCode.NOT_ALLOWED)
        # Like esiur-ts, the definition travels as raw data holding a complete TypeDef TDU.
        self.connection.send_reply(
            EpPacketReply.COMPLETED, callback_id, compose(hosted.info, types=self.warehouse.registry)
        )

    async def _typedef_by_resource_id(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        resource = self._resource(self._values(tdu, 1)[0])
        self._permit(resource, ActionType.VIEW_TYPEDEF, None, ExceptionCode.NOT_ALLOWED)
        assert resource.instance is not None
        self.connection.send_reply(
            EpPacketReply.COMPLETED,
            callback_id,
            compose(resource.instance.type.info, types=self.warehouse.registry),
        )

    # ---- calls and writes -----------------------------------------------------------------

    async def _invoke(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        values = self._values(tdu, 2)
        resource = self._resource(values[0])
        assert resource.instance is not None
        function = self._function(resource.instance.type.functions, values[1])
        self._permit(resource, ActionType.EXECUTE, function, ExceptionCode.ACCESS_DENIED)
        arguments = await self._arguments(values[2] if len(values) > 2 else None)
        await self._call(callback_id, function, resource, arguments)

    async def _static_call(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        values = self._values(tdu, 2)
        type_id = self._integer(values[0], "type id")
        try:
            hosted = self.warehouse.type_by_id(type_id)
        except KeyError:
            raise _refuse(ExceptionCode.TYPEDEF_NOT_FOUND) from None
        function = self._function(hosted.functions, values[1])
        if not function.static:
            raise _refuse(ExceptionCode.METHOD_NOT_FOUND)
        self._permit(None, ActionType.EXECUTE, function, ExceptionCode.INVOKE_DENIED)
        arguments = await self._arguments(values[2] if len(values) > 2 else None)
        await self._call(callback_id, function, None, arguments)

    def _function(self, functions: tuple[Function, ...], index: Any) -> Function:
        position = self._integer(index, "function index")
        if not 0 <= position < len(functions):
            raise _refuse(ExceptionCode.METHOD_NOT_FOUND)
        return functions[position]

    async def _arguments(self, raw: Any) -> list[Any]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise _refuse(ExceptionCode.PARSE_ERROR, "The arguments must be a list.")
        return [await self._materialize(item) for item in raw]

    async def _call(
        self,
        callback_id: int,
        function: Function,
        resource: Resource | None,
        arguments: list[Any],
    ) -> None:
        try:
            if resource is None or function.static:
                result = function.implementation(*arguments)
            else:
                result = function.implementation(resource, *arguments)
            if inspect.isawaitable(result):
                result = await result
        except Exception as error:
            self.connection.send_error(
                ErrorType.EXCEPTION,
                callback_id,
                ExceptionCode.RUNTIME_EXCEPTION,
                f"{type(error).__name__}: {error}",
            )
            return
        self.connection.send_reply(EpPacketReply.COMPLETED, callback_id, result)

    async def _set_property(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        values = self._values(tdu, 3)
        resource = self._resource(values[0])
        assert resource.instance is not None
        properties = resource.instance.type.properties
        position = self._integer(values[1], "property index")
        if not 0 <= position < len(properties):
            raise _refuse(ExceptionCode.PROPERTY_NOT_FOUND)
        property_: Property[Any] = properties[position]
        self._permit(resource, ActionType.SET_PROPERTY, property_, ExceptionCode.ACCESS_DENIED)
        if property_.read_only:
            raise _refuse(ExceptionCode.READ_ONLY_PROPERTY, f"'{property_.name}' is read-only.")
        setattr(resource, property_.attribute, await self._materialize(values[2]))
        self.connection.send_reply(EpPacketReply.COMPLETED, callback_id)

    # ---- events ---------------------------------------------------------------------------

    def _event_target(self, values: list[Any]) -> tuple[Resource, int]:
        resource = self._resource(values[0])
        assert resource.instance is not None
        instance_id = resource.instance.id
        if instance_id not in self._attached:
            raise _refuse(ExceptionCode.NOT_ATTACHED)
        index = self._integer(values[1], "event index")
        if not 0 <= index < len(resource.instance.type.events):
            raise _refuse(ExceptionCode.GENERAL_FAILURE)
        return resource, index

    async def _subscribe(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        resource, index = self._event_target(self._values(tdu, 2))
        instance = resource.instance
        assert instance is not None
        event = instance.type.events[index]
        if event.auto_delivered:
            raise _refuse(ExceptionCode.NOT_SUBSCRIBABLE)
        self._permit(resource, ActionType.SUBSCRIBE, event, ExceptionCode.ACCESS_DENIED)
        self._permit(resource, ActionType.RECEIVE_EVENT, event, ExceptionCode.NOT_ALLOWED)
        subscribed = self._events.setdefault(instance.id, set())
        if index in subscribed:
            raise _refuse(ExceptionCode.ALREADY_LISTENED)
        subscribed.add(index)
        head = instance.cursor
        self.connection.send_reply(
            EpPacketReply.COMPLETED, callback_id, head.generation_bytes, UInt64(head.revision)
        )

    async def _unsubscribe(self, callback_id: int, tdu: ParsedTdu | None) -> None:
        resource, index = self._event_target(self._values(tdu, 2))
        instance = resource.instance
        assert instance is not None
        event = instance.type.events[index]
        subscribed = self._events.get(instance.id)
        if subscribed is None or index not in subscribed:
            raise _refuse(ExceptionCode.ALREADY_UNSUBSCRIBED)
        self._permit(resource, ActionType.UNSUBSCRIBE, event, ExceptionCode.ACCESS_DENIED)
        subscribed.discard(index)
        self.connection.send_reply(EpPacketReply.COMPLETED, callback_id)


def _has_reference(value: Any) -> bool:
    if isinstance(value, ResourceId):
        return True
    if isinstance(value, list | tuple):
        return any(_has_reference(item) for item in value)
    if isinstance(value, dict):
        return any(_has_reference(item) for item in value.values())
    return False
