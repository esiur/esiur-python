"""Errors that cross the wire (ports of esiur-ts ``ErrorType``, ``ExceptionCode`` and
``AsyncException``). The numeric values are wire-significant: error replies carry them."""

from __future__ import annotations

import enum
from typing import Any


class ErrorType(enum.IntEnum):
    """Category of an :class:`AsyncException`; it selects the error reply that carries it."""

    MANAGEMENT = 0
    EXCEPTION = 1
    WARNING = 2


class ExceptionCode(enum.IntEnum):
    """Esiur management error codes (the order matches the .NET enum)."""

    RUNTIME_EXCEPTION = 0
    HOST_NOT_REACHABLE = 1
    ACCESS_DENIED = 2
    USER_OR_TOKEN_NOT_FOUND = 3
    CHALLENGE_FAILED = 4
    RESOURCE_NOT_FOUND = 5
    ATTACH_DENIED = 6
    INVALID_METHOD = 7
    INVOKE_DENIED = 8
    CREATE_DENIED = 9
    ADD_PARENT_DENIED = 10
    ADD_CHILD_DENIED = 11
    VIEW_ATTRIBUTE_DENIED = 12
    UPDATE_ATTRIBUTE_DENIED = 13
    STORE_NOT_FOUND = 14
    PARENT_NOT_FOUND = 15
    CHILD_NOT_FOUND = 16
    RESOURCE_IS_NOT_STORE = 17
    DELETE_DENIED = 18
    DELETE_FAILED = 19
    UPDATE_ATTRIBUTE_FAILED = 20
    GET_ATTRIBUTES_FAILED = 21
    CLEAR_ATTRIBUTES_FAILED = 22
    TYPEDEF_NOT_FOUND = 23
    RENAME_DENIED = 24
    CLASS_NOT_FOUND = 25
    METHOD_NOT_FOUND = 26
    PROPERTY_NOT_FOUND = 27
    SET_PROPERTY_DENIED = 28
    READ_ONLY_PROPERTY = 29
    GENERAL_FAILURE = 30
    ADD_TO_STORE_FAILED = 31
    NOT_ATTACHED = 32
    ALREADY_LISTENED = 33
    ALREADY_UNSUBSCRIBED = 34
    NOT_SUBSCRIBABLE = 35
    PARSE_ERROR = 36
    TIMEOUT = 37
    NOT_SUPPORTED = 38
    NOT_IMPLEMENTED = 39
    NOT_ALLOWED = 40
    RATE_LIMIT_EXCEEDED = 41
    PARSER_LIMIT_EXCEEDED = 42
    ATTACHMENT_LIMIT_EXCEEDED = 43
    ALREADY_ATTACHED = 44
    CONNECTION_LIMIT_EXCEEDED = 45
    CURSOR_EXPIRED = 46


class AsyncException(Exception):
    """An error reported by, or sent to, a peer: a category, a code and a message.

    ``code`` is an :class:`ExceptionCode` for codes this version knows, otherwise the plain
    integer the peer sent.
    """

    def __init__(self, type: ErrorType, code: int, message: str = "") -> None:
        super().__init__(type, code, message)
        self.type = type
        self.code: int = _known_code(code)
        self.message = message

    def __str__(self) -> str:
        name = self.code.name if isinstance(self.code, ExceptionCode) else str(self.code)
        return f"{name}: {self.message}" if self.message else name

    @classmethod
    def from_error(cls, value: Any) -> AsyncException:
        """Coerce any raised value: an :class:`AsyncException` is returned as it is, anything
        else becomes an ``EXCEPTION`` with code ``RUNTIME_EXCEPTION``."""
        if isinstance(value, AsyncException):
            return value
        exception = cls(ErrorType.EXCEPTION, ExceptionCode.RUNTIME_EXCEPTION, str(value))
        if isinstance(value, BaseException):
            exception.__cause__ = value
        return exception


def _known_code(code: int) -> int:
    try:
        return ExceptionCode(code)
    except ValueError:
        return code
