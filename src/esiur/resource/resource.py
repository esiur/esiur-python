"""The base class of the objects Esiur hosts (port of esiur-ts ``Resource``)."""

from __future__ import annotations

import enum
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .instance import Instance

logger = logging.getLogger("esiur.resource")


class ResourceOperation(enum.IntEnum):
    """A lifecycle step the :class:`~esiur.resource.Warehouse` hands to a resource's
    :meth:`Resource.handle` (same values as esiur-dotnet)."""

    OPEN = 0
    INITIALIZE = 1
    CONFIGURE = 2
    CLOSE = 3
    TERMINATE = 4
    SYSTEM_READY = 5
    SYSTEM_RELOADING = 6
    SYSTEM_RELOADED = 7
    SYSTEM_TERMINATING = 8
    #: The second termination phase; it shares ``SYSTEM_TERMINATING``'s value, as in dotnet.
    SYSTEM_TERMINATED = 8
    SAVE = 9
    LOAD = 10
    PAUSE = 11
    RESUME = 12


DestroyHandler = Callable[["Resource"], None]


class Resource:
    """Subclass this and declare :class:`~esiur.resource.Property`, ``Event`` and ``@function``
    members to host an object. A resource gets its :attr:`instance` when it is put into a
    :class:`~esiur.resource.Warehouse`; until then it is an ordinary object."""

    #: The resource's identity and change stream; set by the warehouse on put.
    instance: Instance | None = None

    async def handle(self, operation: ResourceOperation, context: Any = None) -> bool:
        """React to a lifecycle step; return ``False`` to report failure. The default runs
        :meth:`create` on ``INITIALIZE`` and accepts everything else."""
        if operation == ResourceOperation.INITIALIZE:
            return self.create()
        return True

    def create(self) -> bool:
        """Set-up that needs the resource to be in a warehouse; return ``False`` to fail."""
        return True

    def add_destroy_handler(self, handler: DestroyHandler) -> None:
        self.__dict__.setdefault("_destroy_handlers", []).append(handler)

    def remove_destroy_handler(self, handler: DestroyHandler) -> None:
        handlers = self.__dict__.get("_destroy_handlers", [])
        if handler in handlers:
            handlers.remove(handler)

    def destroy(self) -> None:
        """Tell everything watching this resource that it is gone."""
        for handler in list(self.__dict__.get("_destroy_handlers", ())):
            try:
                handler(self)
            except Exception:
                logger.exception("A destroy handler of %s failed", type(self).__name__)
