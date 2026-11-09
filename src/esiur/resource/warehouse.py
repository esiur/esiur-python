"""The warehouse: every resource a node hosts, how to find it, and who may touch it (port of
esiur-ts ``Warehouse``, minus the remote-connection and rate-control/auditing parts).

::

    warehouse = Warehouse()
    await warehouse.put("sys", MemoryStore())
    greeter = await warehouse.put("sys/greeter", Greeter())
    await warehouse.open()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, TypeVar

from esiur.data import TypeRegistry
from esiur.security.authentication import AuthenticationProvider
from esiur.security.encryption import EncryptionProvider
from esiur.security.permissions import (
    ActionType,
    PermissionsManager,
    Ruling,
    default_permissions,
)

from .hosted import HostedType, describe
from .instance import Instance
from .resource import Resource, ResourceOperation
from .stores import Store

logger = logging.getLogger("esiur.resource")

_R = TypeVar("_R", bound=Resource)


@dataclass(frozen=True, slots=True)
class Evaluation:
    """The verdict of the permissions managers on one operation."""

    allowed: bool
    reason: str | None = None


class Warehouse:
    """Owns the resources of a node. Put stores in first, then resources into them; a peer
    reaches a resource by its link (``"sys/greeter"``) or its instance id."""

    def __init__(self, *, registry: TypeRegistry | None = None) -> None:
        #: Record and enum definitions that exported types may refer to.
        self.registry = registry
        self._resources: dict[int, Resource] = {}
        self._stores: list[Store] = []
        self._counter = 0
        self._opened = False
        self._types_by_class: dict[type, HostedType] = {}
        self._types_by_id: dict[int, HostedType] = {}
        self._type_counter = 0
        self._permissions: list[PermissionsManager] = []
        self._authentication_providers: dict[str, AuthenticationProvider] = {}
        self._encryption_providers: dict[str, EncryptionProvider] = {}

    # ---- authentication and encryption providers ------------------------------------------

    def register_authentication_provider(
        self, provider: AuthenticationProvider, name: str | None = None
    ) -> None:
        """Let peers authenticate with ``provider``, selected by its protocol name."""
        self._authentication_providers[name or provider.default_name] = provider

    def try_get_authentication_provider(self, name: str) -> AuthenticationProvider | None:
        return self._authentication_providers.get(name)

    def register_encryption_provider(
        self, provider: EncryptionProvider, name: str | None = None
    ) -> None:
        """Let connections encrypt with ``provider``, negotiated by its name."""
        key = name or provider.default_name
        if key in self._encryption_providers:
            raise ValueError(f"An encryption provider named '{key}' is already registered.")
        self._encryption_providers[key] = provider

    def try_get_encryption_provider(self, name: str) -> EncryptionProvider | None:
        return self._encryption_providers.get(name)

    @property
    def encryption_provider_names(self) -> tuple[str, ...]:
        return tuple(self._encryption_providers)

    # ---- permissions ----------------------------------------------------------------------

    def register_permissions(self, manager: PermissionsManager) -> None:
        """Ask ``manager`` about every operation a peer attempts. Any denial wins."""
        if manager in self._permissions:
            raise ValueError("That permissions manager is already registered.")
        self._permissions.append(manager)

    def remove_permissions(self, manager: PermissionsManager) -> bool:
        if manager not in self._permissions:
            return False
        self._permissions.remove(manager)
        return True

    def evaluate(
        self,
        resource: Resource | None,
        session: Any,
        action: ActionType,
        member: Any = None,
        inquirer: Any = None,
    ) -> Evaluation:
        """Combine the managers' votes: a denial (or a manager that fails) wins, otherwise an
        allowance, otherwise :func:`default_permissions`."""
        allowed = denied = False
        reason: str | None = None
        for manager in self._permissions:
            try:
                ruling = manager.applicable(resource, session, action, member, inquirer)
            except Exception:
                logger.exception("A permissions manager failed")
                denied = True
                reason = reason or "A permissions manager failed while evaluating the operation."
                continue
            if ruling == Ruling.DENIED:
                denied = True
                reason = reason or (
                    f"Permissions manager '{type(manager).__name__}' denied the operation."
                )
            elif ruling == Ruling.ALLOWED:
                allowed = True
        verdict = (
            Ruling.DENIED
            if denied
            else Ruling.ALLOWED
            if allowed
            else default_permissions(action)
        )
        return Evaluation(verdict == Ruling.ALLOWED, reason if verdict == Ruling.DENIED else None)

    # ---- types ----------------------------------------------------------------------------

    def hosted_type(self, cls: type) -> HostedType:
        """The definition peers are shown for the resource class ``cls``, created (and given
        the next type id) on first use."""
        existing = self._types_by_class.get(cls)
        if existing is not None:
            return existing
        self._type_counter += 1
        hosted = describe(cls, self._type_counter, self._name_of_type)
        self._types_by_class[cls] = hosted
        self._types_by_id[hosted.id] = hosted
        return hosted

    def type_by_id(self, type_id: int) -> HostedType:
        """The definition with ``type_id``; ``KeyError`` if this warehouse never issued it."""
        return self._types_by_id[type_id]

    def _name_of_type(self, type_id: int) -> str:
        hosted = self._types_by_id.get(type_id)
        if hosted is not None:
            return hosted.name
        if self.registry is not None:
            return self.registry.name_of(type_id)
        raise KeyError(f"TypeDef {type_id} is unknown.")

    # ---- resources ------------------------------------------------------------------------

    def get_by_id(self, instance_id: int) -> Resource | None:
        """The hosted resource with this instance id."""
        return self._resources.get(instance_id)

    @property
    def stores(self) -> tuple[Store, ...]:
        return tuple(self._stores)

    @property
    def is_open(self) -> bool:
        return self._opened

    async def put(self, path: str, resource: _R, context: Any = None) -> _R:
        """Host ``resource`` at ``path`` and give it its :attr:`~Resource.instance`. A path of
        one segment must be a :class:`Store`; a longer one puts the resource into the store of
        its parent path. Returns the resource."""
        if resource.instance is not None:
            raise ValueError("The resource is already hosted.")
        if not path or not path.strip("/"):
            raise ValueError("Invalid path.")
        location = path.lstrip("/").split("/")
        name = location[-1]

        store: Store
        if len(location) == 1:
            if not isinstance(resource, Store):
                raise ValueError("A resource that is not a store cannot be put at the root.")
            store = resource
        else:
            parent = await self.query("/".join(location[:-1]))
            if parent is None or parent.instance is None:
                raise LookupError("Can't find the parent resource.")
            store = parent.instance.store

        self._counter += 1
        instance_id = self._counter
        resource.instance = Instance(
            self, instance_id, name, resource, store, self.hosted_type(type(resource))
        )

        if isinstance(resource, Store):
            self._stores.append(resource)
        elif resource is not store and not await store.put(resource, "/".join(location[1:])):
            resource.instance = None
            self._counter -= 1
            raise RuntimeError("The store refused the resource.")
        self._resources[instance_id] = resource

        if self._opened:
            await resource.handle(ResourceOperation.INITIALIZE, context)
            if isinstance(resource, Store):
                await resource.handle(ResourceOperation.OPEN, context)
        return resource

    async def query(self, path: str) -> Resource | None:
        """The hosted resource at a link such as ``"sys/greeter"``, or ``None``."""
        parts = path.strip().strip("/").split("/")
        for store in self._stores:
            if store.instance is not None and parts[0] == store.instance.name:
                if len(parts) == 1:
                    return store
                return await store.get("/".join(parts[1:]))
        return None

    async def remove(self, resource: Resource) -> bool:
        """Stop hosting ``resource``: its store forgets it and it is destroyed, which detaches
        every peer."""
        instance = resource.instance
        if instance is None:
            return False
        self._resources.pop(instance.id, None)
        if isinstance(resource, Store) and resource in self._stores:
            self._stores.remove(resource)
        if instance.store is not resource:
            await instance.store.remove(resource)
        resource.destroy()
        resource.instance = None
        return True

    # ---- lifecycle ------------------------------------------------------------------------

    async def open(self) -> bool:
        """Initialize every resource and open every store. Resources put afterwards are
        initialized as they arrive."""
        self._opened = True
        for resource in list(self._resources.values()):
            await resource.handle(ResourceOperation.INITIALIZE)
        for store in list(self._stores):
            await store.handle(ResourceOperation.OPEN)
        return True

    async def close(self) -> bool:
        """Terminate every resource in two phases (``TERMINATE``, then ``SYSTEM_TERMINATED``).
        Every resource is told even if some fail; the failures are raised together."""
        resources = [*self._resources.values(), *(s for s in self._stores)]
        errors: list[BaseException] = []
        for operation in (ResourceOperation.TERMINATE, ResourceOperation.SYSTEM_TERMINATED):
            for resource in dict.fromkeys(resources):
                try:
                    await resource.handle(operation)
                except Exception as error:  # noqa: BLE001 - every resource must be told
                    errors.append(error)
        self._opened = False
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise RuntimeError(
                f"{len(errors)} resources failed while closing the warehouse: "
                + "; ".join(f"{type(error).__name__}: {error}" for error in errors)
            ) from errors[0]
        return True
