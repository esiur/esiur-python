"""Endpoint URLs (port of esiur-ts ``EpProtocol``)."""

from __future__ import annotations

from urllib.parse import urlsplit

#: Default native EP port used when an Esiur endpoint omits its port.
ESIUR_DEFAULT_PORT = 51018

#: ``ep``/``eps`` are the Esiur names for WebSocket/secure WebSocket.
_WEBSOCKET_ALIASES = {"ep": "ws", "eps": "wss"}


def normalize_endpoint(value: str) -> str:
    """Validate an endpoint and add :data:`ESIUR_DEFAULT_PORT` when it has no port.

    Explicit ports are kept as they are, including the standard 80 and 443. ``http(s)`` URLs
    (EP over plain HTTP requests) ride a web server's own scheme-defined port and are returned
    unchanged.
    """
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError(f"Invalid EP endpoint: {value}") from None
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"Invalid EP endpoint: {value}")
    if parts.scheme in ("http", "https"):
        return value
    if port is None:
        return parts._replace(netloc=f"{parts.netloc}:{ESIUR_DEFAULT_PORT}").geturl()
    if not 0 < port < 65536:
        raise ValueError(f"EP endpoint ports must be from 1 through 65535: {value}")
    return value


def websocket_url(value: str) -> str:
    """The ``ws``/``wss`` form of an ``ep``/``eps`` endpoint; other schemes are unchanged."""
    scheme = urlsplit(value).scheme
    if scheme in _WEBSOCKET_ALIASES:
        return _WEBSOCKET_ALIASES[scheme] + value[len(scheme) :]
    return value
