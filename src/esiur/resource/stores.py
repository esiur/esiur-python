"""Stores: the resources that keep other resources and resolve their links (port of esiur-ts
``IStore`` and ``MemoryStore``)."""

from __future__ import annotations

import datetime as dt
from typing import Any

from .resource import Resource


class Store(Resource):
    """Base class of a store. A store is itself a resource, put at a one-segment path (``"sys"``)
    that becomes the first segment of the links of everything it keeps (``"sys/greeter"``)."""

    async def get(self, path: str) -> Resource | None:
        """The resource kept at ``path`` (relative to the store), if any."""
        raise NotImplementedError

    async def put(self, resource: Resource, path: str) -> bool:
        """Keep ``resource`` at ``path`` (relative to the store); ``False`` refuses it."""
        raise NotImplementedError

    def link(self, resource: Resource) -> str | None:
        """The path of ``resource`` within this store."""
        raise NotImplementedError

    def modify(
        self, resource: Resource, index: int, value: Any, age: int, date: dt.datetime
    ) -> bool:
        """A kept resource's property ``index`` changed; a persistent store writes it down."""
        return True

    async def remove(self, resource: Resource) -> bool:
        """Forget ``resource``; ``False`` if this store was not keeping it."""
        raise NotImplementedError


class MemoryStore(Store):
    """A store that keeps its resources in memory. Besides its links, a resource can be
    resolved as ``$<instance id>``."""

    def __init__(self) -> None:
        self._resources: dict[int, Resource] = {}

    def link(self, resource: Resource) -> str | None:
        instance = resource.instance
        if instance is None or instance.store is not self:
            return None
        link = instance.variables.get("link")
        return link if isinstance(link, str) else None

    async def get(self, path: str) -> Resource | None:
        if path.startswith("$"):
            try:
                return self._resources.get(int(path[1:]))
            except ValueError:
                return None
        for resource in self._resources.values():
            if self.link(resource) == path:
                return resource
        return None

    async def put(self, resource: Resource, path: str) -> bool:
        assert resource.instance is not None
        resource.instance.variables["link"] = path
        self._resources[resource.instance.id] = resource
        return True

    async def remove(self, resource: Resource) -> bool:
        instance = resource.instance
        if instance is None or instance.store is not self:
            return False
        return self._resources.pop(instance.id, None) is not None
