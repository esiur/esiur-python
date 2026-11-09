"""Who may do what with a hosted resource (port of esiur-ts ``security/permissions``).

A :class:`PermissionsManager` is asked about every operation a peer attempts. Managers vote
``DENIED`` or ``ALLOWED`` (or ``DONT_CARE``); any denial wins, an allowance counts only when
nothing denied, and when nobody cared the operation falls back to :func:`default_permissions`:
reading and listening are allowed, changing things is not.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from esiur.data import EventDefInfo, FunctionDefInfo, PropertyDefInfo
    from esiur.resource.resource import Resource

    MemberDef = PropertyDefInfo | FunctionDefInfo | EventDefInfo


class ActionType(enum.IntEnum):
    """The kind of operation being asked about (same values as esiur-dotnet)."""

    ATTACH = 0
    DELETE = 1
    EXECUTE = 2
    GET_PROPERTY = 3
    SET_PROPERTY = 4
    CREATE_RESOURCE = 5
    UPDATE_ATTRIBUTES = 6
    INQUIRE_ATTRIBUTES = 7
    ADD_PARENT = 8
    REMOVE_PARENT = 9
    ADD_CHILD = 10
    REMOVE_CHILD = 11
    RENAME = 12
    RECEIVE_EVENT = 13
    VIEW_TYPEDEF = 14
    DETACH = 15
    SUBSCRIBE = 16
    UNSUBSCRIBE = 17
    PULL_STREAM = 18
    TERMINATE_EXECUTION = 19
    HALT_EXECUTION = 20
    RESUME_EXECUTION = 21


class Ruling(enum.IntEnum):
    DENIED = 0
    ALLOWED = 1
    DONT_CARE = 2


_ALLOWED_BY_DEFAULT = frozenset(
    {
        ActionType.GET_PROPERTY,
        ActionType.VIEW_TYPEDEF,
        ActionType.RECEIVE_EVENT,
        ActionType.ATTACH,
        ActionType.EXECUTE,
        ActionType.DETACH,
        ActionType.SUBSCRIBE,
        ActionType.UNSUBSCRIBE,
        ActionType.PULL_STREAM,
        ActionType.TERMINATE_EXECUTION,
        ActionType.HALT_EXECUTION,
        ActionType.RESUME_EXECUTION,
    }
)


def default_permissions(action: ActionType) -> Ruling:
    """The verdict when no manager voted: read-like and lifecycle actions are allowed, anything
    that changes or administers a resource is denied."""
    return Ruling.ALLOWED if action in _ALLOWED_BY_DEFAULT else Ruling.DENIED


class PermissionsManager:
    """Base class of a permissions manager. Override :meth:`applicable`; the default has no
    opinion."""

    def applicable(
        self,
        resource: Resource | None,
        session: Any,
        action: ActionType,
        member: MemberDef | None,
        inquirer: Any = None,
    ) -> Ruling:
        """Vote on ``action`` on ``resource`` (``None`` for an operation on no particular
        resource, such as viewing a type). ``session`` is the peer's authentication session
        (``None`` for an anonymous peer) and ``inquirer`` the connection asking."""
        return Ruling.DONT_CARE


class AllowAll(PermissionsManager):
    """Allows every operation: for tests, and for servers that trust every peer."""

    def applicable(
        self,
        resource: Resource | None,
        session: Any,
        action: ActionType,
        member: MemberDef | None,
        inquirer: Any = None,
    ) -> Ruling:
        return Ruling.ALLOWED


class CallbackPermissions(PermissionsManager):
    """A manager that delegates to a function ``(resource, session, action, member, inquirer)``."""

    def __init__(self, callback: Callable[..., Ruling]) -> None:
        self._callback = callback

    def applicable(
        self,
        resource: Resource | None,
        session: Any,
        action: ActionType,
        member: MemberDef | None,
        inquirer: Any = None,
    ) -> Ruling:
        return self._callback(resource, session, action, member, inquirer)
