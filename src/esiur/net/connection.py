"""The EP connection (port of the transport, handshake and request/reply core of esiur-ts
``EpConnection``).

A connection owns one socket and speaks one of two roles. The *initiator* (client) sends an
``Initialize`` auth packet and waits for the responder's ``SessionEstablished``; the *responder*
(server) answers the peer's ``Initialize``. Once the handshake completes, both sides exchange EP
packets: requests (answered by replies, matched through a callback id), and notifications.

With a ``warehouse`` the connection also serves the resources it hosts (see
:mod:`esiur.net.hosting`); without one it is a pure client.

Not yet ported, and refused rather than ignored: authentication providers (a peer asking for
anything but anonymous access gets ``NotSupported``), transport encryption, reconnection and
keep-alive.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import inspect
import logging
import secrets
import struct
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.data import (
    ParsedTdu,
    ParserError,
    ParserLimitError,
    ResourceId,
    TypeDefInfo,
    TypedMap,
    TypeRegistry,
    UInt8,
    UInt64,
    compose,
    parse,
    parse_with_length,
    t,
)
from esiur.resource import Resource, ResourceCursor, TypeDef, Warehouse
from esiur.security.authentication import (
    AuthenticationContext,
    AuthenticationDirection,
    AuthenticationHandler,
    AuthenticationMaterial,
    AuthenticationMaterialType,
    AuthenticationProvider,
    AuthenticationResult,
    AuthenticationRuling,
    AuthenticationSession,
)
from esiur.security.encryption import (
    AesEncryptionProvider,
    EncryptionContext,
    EncryptionProvider,
    SymmetricCipher,
)
from esiur.security.encryption import available as encryption_available
from esiur.security.modes import AuthenticationMode, EncryptionMode

from .configuration import ParserConfiguration
from .endpoint import normalize_endpoint, websocket_url
from .ep_resource import EpResource
from .hosting import HostedSession
from .packets import (
    EpAuthPacket,
    EpAuthPacketCommand,
    EpAuthPacketHeader,
    EpAuthPacketMethod,
    EpPacket,
    EpPacketMethod,
    EpPacketNotification,
    EpPacketReply,
    EpPacketRequest,
)
from .sockets import ISocket, SocketState, TcpSocket, WebSocketSocket

logger = logging.getLogger("esiur.net")

#: Called for an inbound request when this node does not answer it itself:
#: ``(connection, action, callback_id, tdu)``. It may be a coroutine function; the reply is
#: sent with :meth:`EpConnection.send_reply` / :meth:`EpConnection.send_error`.
RequestHandler = Callable[["EpConnection", int, int, ParsedTdu | None], Any]
#: Called for an inbound notification: ``(connection, action, tdu)``. May be a coroutine function.
NotificationHandler = Callable[["EpConnection", int, ParsedTdu | None], Any]

_MAXIMUM_CALLBACK_ID = 0xFFFF_FFFF


@dataclass(slots=True, eq=False)
class _Pending:
    future: asyncio.Future[Any]
    on_progress: Callable[[int, int], Any] | None = None
    on_warning: Callable[[int, str], Any] | None = None
    on_propagated: Callable[[Any], Any] | None = None
    on_chunk: Callable[[Any], Any] | None = None
    #: Whether resource references in the result are attached before the request completes.
    resolve: bool = True


class EpConnection:
    """One EP session over a socket."""

    def __init__(
        self,
        *,
        registry: TypeRegistry | None = None,
        parser: ParserConfiguration | None = None,
        domain: str = "",
        allow_unauthorized: bool = True,
        authentication_timeout: float | None = 30.0,
        warehouse: Warehouse | None = None,
        authentication_mode: AuthenticationMode = AuthenticationMode.NONE,
        encryption_mode: EncryptionMode = EncryptionMode.NONE,
        authentication_provider: AuthenticationProvider | None = None,
        authentication_protocol: str = "password-sha3-v1",
        identity: str | None = None,
        responder_identity: str | None = None,
        encryption_providers: Iterable[EncryptionProvider] | None = None,
    ) -> None:
        #: Record and enum definitions used to encode and decode values.
        self.registry = registry
        #: The resources this node hosts for the peer (``None`` for a pure client).
        self.warehouse = warehouse
        #: Limits applied to what this connection receives (and advertised to the peer).
        self.parser = parser or ParserConfiguration()
        self.domain = domain
        #: Responder: accept anonymous peers.
        self.allow_unauthorized = allow_unauthorized
        #: Longest the handshake may take, in seconds; ``None`` or ``0`` disables the deadline.
        self.authentication_timeout = authentication_timeout
        self.on_request: RequestHandler | None = None
        self.on_notification: NotificationHandler | None = None
        #: Called with this connection when it closes (from either side).
        self.on_close: list[Callable[[EpConnection], None]] = []

        self._socket: ISocket | None = None
        self._buffer = bytearray()
        self._packet = EpPacket()
        self._auth_packet = EpAuthPacket()
        self._requests: dict[int, _Pending] = {}
        self._callback_counter = 0
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closed = asyncio.Event()

        # Remote resources. ``_attached`` holds finished proxies; ``_needed`` the one being
        # filled in, so a reference back to it resolves to the placeholder instead of waiting
        # on itself; ``_attaching`` shares one attach between concurrent callers.
        self._attached: dict[int, EpResource] = {}
        self._needed: dict[int, EpResource] = {}
        self._attaching: dict[int, asyncio.Future[EpResource]] = {}
        self._typedefs: dict[int, TypeDef] = {}
        self._notifications: asyncio.Task[None] | None = None
        self._hosted = HostedSession(self, warehouse) if warehouse is not None else None

        # Handshake state. A connection assigned a socket without a handshake is authenticated,
        # like a directly assigned connection in esiur-ts.
        self._authenticated = True
        self._session_established = True
        self._direction: str | None = None
        self._host_name: str | None = None
        self._authentication_mode = AuthenticationMode(authentication_mode)
        self._encryption_mode = EncryptionMode(encryption_mode)
        self._authentication_provider = authentication_provider
        self._authentication_protocol = authentication_protocol
        self._authentication_handler: AuthenticationHandler | None = None
        self._local_identity = identity
        self._remote_identity: str | None = None
        self._responder_identity = responder_identity
        self._session_key: bytes | None = None
        self._variables: dict[str, Any] = {}
        self._encryption_providers: dict[str, EncryptionProvider] = {
            p.default_name: p for p in (encryption_providers or ())
        }
        self._offered_encryption: list[str] = []
        self._encryption_provider: EncryptionProvider | None = None
        self._cipher: SymmetricCipher | None = None
        self._decrypt_inbound = False
        self._encryption_active = False
        self._ready: asyncio.Future[None] | None = None
        self._deadline: asyncio.TimerHandle | None = None
        self._local_headers: dict[int, Any] = {}
        self._remote_headers: dict[int, Any] = {}

    # ---- state ----------------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self._socket is not None and self._socket.state == SocketState.ESTABLISHED

    @property
    def is_authenticated(self) -> bool:
        """True once the handshake has completed."""
        return self._authenticated

    @property
    def remote_headers(self) -> dict[int, Any]:
        """The headers of the peer's handshake packets, keyed by :class:`EpAuthPacketHeader`."""
        return dict(self._remote_headers)

    def remote_limit(self, header: EpAuthPacketHeader) -> int:
        """A budget the peer advertised in its headers; ``0`` when it advertised none."""
        value = self._remote_headers.get(header, 0)
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0

    # ---- lifecycle ------------------------------------------------------------------------

    @classmethod
    async def connect(
        cls,
        url: str,
        *,
        registry: TypeRegistry | None = None,
        parser: ParserConfiguration | None = None,
        domain: str | None = None,
        authentication_timeout: float | None = 30.0,
        connect_timeout: float | None = 30.0,
        warehouse: Warehouse | None = None,
        authentication_mode: AuthenticationMode = AuthenticationMode.NONE,
        encryption_mode: EncryptionMode = EncryptionMode.NONE,
        authentication_provider: AuthenticationProvider | None = None,
        authentication_protocol: str = "password-sha3-v1",
        identity: str | None = None,
        responder_identity: str | None = None,
        encryption_providers: Iterable[EncryptionProvider] | None = None,
    ) -> EpConnection:
        """Open a client connection to ``url`` (``ws://``, ``wss://``, ``ep://``, ``eps://`` or
        ``tcp://``), run the handshake, and return once the session is established.

        By default the handshake is anonymous. For an authenticated session give an
        ``authentication_mode``, a provider for the protocol (here, or registered on
        ``warehouse``) and the ``identity`` to prove; ``encryption_mode`` additionally encrypts
        everything after the handshake (``pip install esiur[crypto]``)."""
        endpoint = normalize_endpoint(url)
        socket_url = websocket_url(endpoint)
        scheme = urlsplit(socket_url).scheme
        socket: ISocket
        if scheme == "tcp":
            socket = TcpSocket()
        elif scheme in ("ws", "wss"):
            socket = WebSocketSocket(
                maximum_message_size=(parser or ParserConfiguration()).maximum_encrypted_record_size
                or None
            )
        else:
            raise ValueError(f"Unsupported EP transport '{scheme}'.")

        connection = cls(
            registry=registry,
            parser=parser,
            authentication_timeout=authentication_timeout,
            warehouse=warehouse,
            authentication_mode=authentication_mode,
            encryption_mode=encryption_mode,
            authentication_provider=authentication_provider,
            authentication_protocol=authentication_protocol,
            identity=identity,
            responder_identity=responder_identity,
            encryption_providers=encryption_providers,
        )
        connection._host_name = urlsplit(socket_url).hostname
        connection.start_initiator_handshake(domain or urlsplit(socket_url).hostname or "")
        connection.assign(socket)
        try:
            await asyncio.wait_for(socket.connect(socket_url), connect_timeout)
            await connection.when_ready()
        except BaseException:
            connection.close()
            raise
        return connection

    def assign(self, socket: ISocket) -> None:
        """Attach a socket and route its events here. A socket that is already established
        starts the handshake (or serves the responder) straight away."""
        self._socket = socket
        socket.receiver = self
        if socket.state == SocketState.ESTABLISHED:
            self.network_connect(socket)

    def start_initiator_handshake(self, domain: str = "") -> None:
        """Begin the client-side handshake, which runs once the socket is established; await
        :meth:`when_ready` for its end."""
        self._authenticated = False
        self._session_established = False
        self._direction = "initiator"
        if domain:
            self.domain = domain
        self._authentication_handler = None
        self._remote_headers.clear()
        self._local_headers.clear()
        if self.domain:
            self._local_headers[EpAuthPacketHeader.DOMAIN] = self.domain
        self._ready = asyncio.get_running_loop().create_future()
        # Whoever is waiting reports a failure; one nobody awaits must not warn.
        self._ready.add_done_callback(lambda f: f.cancelled() or f.exception())
        self._restart_deadline()

    def start_responder_handshake(self) -> None:
        """Begin the server-side handshake: wait for the peer's ``Initialize``."""
        self._authenticated = False
        self._session_established = False
        self._direction = "responder"
        self._authentication_handler = None
        self._remote_headers.clear()
        self._local_headers.clear()
        self._local_identity = None
        self._remote_identity = None
        self._session_key = None
        self._restart_deadline()

    async def when_ready(self) -> None:
        """Wait for the handshake to complete; raises ``AsyncException`` if it fails."""
        if self._ready is not None:
            await asyncio.shield(self._ready)

    def close(self) -> None:
        """Close the connection. Pending requests fail with ``HOST_NOT_REACHABLE``."""
        self._cancel_deadline()
        if self._socket is not None:
            self._socket.close()

    async def wait_closed(self) -> None:
        await self._closed.wait()

    async def __aenter__(self) -> EpConnection:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.close()
        if self._socket is not None:
            await self.wait_closed()

    # ---- socket events --------------------------------------------------------------------

    def network_connect(self, sender: ISocket) -> None:
        if sender is not self._socket:
            return
        if self._direction == "initiator" and not self._authenticated:
            self._declare()

    def network_close(self, sender: ISocket) -> None:
        if sender is not self._socket:
            return
        self._cancel_deadline()
        closed = AsyncException(
            ErrorType.MANAGEMENT, ExceptionCode.HOST_NOT_REACHABLE, "Connection closed."
        )
        if self._ready is not None and not self._ready.done():
            self._ready.set_exception(
                AsyncException(
                    ErrorType.MANAGEMENT,
                    ExceptionCode.HOST_NOT_REACHABLE,
                    "Connection closed during handshake.",
                )
            )
        self._attached.clear()
        self._needed.clear()
        if self._hosted is not None:
            self._hosted.close()
        pending, self._requests = list(self._requests.values()), {}
        for request in pending:
            if not request.future.done():
                request.future.set_exception(closed)
        for task in list(self._tasks):
            task.cancel()
        if self._authenticated and self._authentication_provider is not None:
            self._run_provider_hook("logout")  # after the cancelling, so an async hook runs
        self._closed.set()
        for handler in list(self.on_close):
            try:
                handler(self)
            except Exception:
                logger.exception("EP on_close handler failed")

    def network_receive(self, sender: ISocket, data: bytes) -> None:
        if sender is not self._socket or sender.state == SocketState.CLOSED:
            return
        self._buffer += data
        try:
            self._drain()
        except ParserError as error:
            # Malformed or oversized input: the stream cannot be resynchronized.
            log = logger.warning if isinstance(error, ParserLimitError) else logger.error
            log("EP closing a connection after a protocol violation: %s", error)
            self.close()

    def _drain(self) -> None:
        # Work on an immutable snapshot, so a packet's TDU stays valid while it is handled.
        message = bytes(self._buffer)
        offset, ends = 0, len(message)
        limit = self.parser.maximum_packet_size
        try:
            while offset < ends and self.is_connected:
                if self._decrypt_inbound:
                    consumed = self._receive_record(message, offset, ends)
                    if consumed <= 0:
                        break
                    offset += consumed
                elif not self._authenticated:
                    consumed = self._auth_packet.parse(
                        message, offset, ends, maximum_payload_length=limit
                    )
                    if consumed < 0:
                        break
                    offset += consumed
                    self._handle_auth_packet(self._auth_packet)
                else:
                    consumed = self._packet.parse(
                        message, offset, ends, maximum_payload_length=limit
                    )
                    if consumed < 0:
                        break
                    offset += consumed
                    self._dispatch(self._packet)
        finally:
            del self._buffer[:offset]

    # ---- sending --------------------------------------------------------------------------

    def _receive_record(self, message: bytes, offset: int, ends: int) -> int:
        """Decrypt and dispatch one encrypted record; returns the bytes consumed, or ``0``
        when more are needed (or the connection was closed)."""
        remaining = ends - offset
        if remaining < _RECORD_HEADER_SIZE:
            return 0
        length: int = struct.unpack_from(">I", message, offset)[0]
        limit = self.parser.maximum_encrypted_record_size
        if limit and length > limit:
            raise ParserLimitError(f"An encrypted record of {length} bytes exceeds {limit}.")
        total = _RECORD_HEADER_SIZE + length
        if remaining < total:
            return 0
        assert self._cipher is not None
        try:
            plaintext = self._cipher.decrypt(message[offset + _RECORD_HEADER_SIZE : offset + total])
        except Exception as error:
            self._fail_authentication(error, suppress_send=True)
            return 0
        self._dispatch_plaintext(plaintext)
        return total

    def _dispatch_plaintext(self, plaintext: bytes) -> None:
        """Dispatch every packet of a decrypted record. The record arrived whole, so a
        truncated packet is a protocol error, not a wait for more bytes."""
        offset, ends = 0, len(plaintext)
        limit = self.parser.maximum_packet_size
        while offset < ends and self.is_connected:
            if not self._authenticated:
                consumed = self._auth_packet.parse(
                    plaintext, offset, ends, maximum_payload_length=limit
                )
                if consumed <= 0:
                    raise ParserError("Truncated encrypted auth packet.")
                offset += consumed
                self._handle_auth_packet(self._auth_packet)
            else:
                consumed = self._packet.parse(
                    plaintext, offset, ends, maximum_payload_length=limit
                )
                if consumed <= 0:
                    raise ParserError("Truncated encrypted packet.")
                offset += consumed
                self._dispatch(self._packet)

    def send(self, message: bytes) -> None:
        """Write raw, already-composed bytes to the socket, as one encrypted record once
        encryption is active."""
        if self._socket is None:
            raise AsyncException(
                ErrorType.MANAGEMENT, ExceptionCode.HOST_NOT_REACHABLE, "Connection closed."
            )
        if self._encryption_active and self._cipher is not None:
            limit = self.remote_limit(EpAuthPacketHeader.MAXIMUM_ENCRYPTED_RECORD_SIZE)
            overhead = (
                self._encryption_provider.maximum_record_overhead
                if self._encryption_provider is not None
                else 0
            )
            if limit and len(message) + overhead > limit:
                raise AsyncException(
                    ErrorType.MANAGEMENT,
                    ExceptionCode.PARSER_LIMIT_EXCEEDED,
                    f"Encrypted record would exceed the peer's advertised {limit}-byte limit.",
                )
            protected = self._cipher.encrypt(message)
            message = struct.pack(">I", len(protected)) + protected
        self._socket.send(message)

    def send_request(
        self,
        action: EpPacketRequest | int,
        *args: Any,
        on_progress: Callable[[int, int], Any] | None = None,
        on_warning: Callable[[int, str], Any] | None = None,
        on_propagated: Callable[[Any], Any] | None = None,
        on_chunk: Callable[[Any], Any] | None = None,
        resolve_resources: bool = True,
    ) -> asyncio.Future[Any]:
        """Send a request now and return a future for the peer's answer.

        No arguments are sent as no value, one as itself, several as a list. A failure (the
        connection is down, the arguments cannot be composed, the peer refuses) is raised when
        the future is awaited, as an :class:`~esiur.core.AsyncException`. Cancelling the future
        abandons the request; a late reply is dropped. Resource references in the result are
        attached and returned as :class:`EpResource` proxies unless ``resolve_resources`` is
        false, which leaves them as :class:`~esiur.data.ResourceId`.
        """
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        if not self.is_connected:
            future.set_exception(
                AsyncException(
                    ErrorType.MANAGEMENT,
                    ExceptionCode.HOST_NOT_REACHABLE,
                    "Connection is not available.",
                )
            )
            return future
        callback_id = self._next_callback_id()
        self._requests[callback_id] = _Pending(
            future, on_progress, on_warning, on_propagated, on_chunk, resolve_resources
        )
        try:
            self.send(EpPacket.compose_request(action, callback_id, self._compose_args(args)))
        except Exception as error:
            self._requests.pop(callback_id, None)
            future.set_exception(AsyncException.from_error(error))
            return future

        def forget_if_cancelled(done: asyncio.Future[Any]) -> None:
            if done.cancelled():
                self._requests.pop(callback_id, None)

        future.add_done_callback(forget_if_cancelled)
        return future

    def _next_callback_id(self) -> int:
        while True:
            self._callback_counter = self._callback_counter % _MAXIMUM_CALLBACK_ID + 1
            if self._callback_counter not in self._requests:
                return self._callback_counter

    def send_reply(self, action: EpPacketReply | int, callback_id: int, *args: Any) -> None:
        """Answer a peer's request."""
        self.send(EpPacket.compose_reply(action, callback_id, self._compose_args(args)))

    def send_notification(self, action: EpPacketNotification | int, *args: Any) -> None:
        """Send a notification, which expects no reply."""
        self.send(EpPacket.compose_notification(action, self._compose_args(args)))

    def send_error(
        self, type: ErrorType, callback_id: int, code: int, message: str = ""
    ) -> None:
        """Answer a request with an error: ``MANAGEMENT`` and ``EXCEPTION`` end it, ``WARNING``
        does not."""
        action = {
            ErrorType.MANAGEMENT: EpPacketReply.PERMISSION_ERROR,
            ErrorType.EXCEPTION: EpPacketReply.EXECUTION_ERROR,
        }.get(type, EpPacketReply.WARNING)
        self.send_reply(action, callback_id, int(code), message)

    def send_progress(self, callback_id: int, value: int, maximum: int) -> None:
        self.send_reply(EpPacketReply.PROGRESS, callback_id, value, maximum)

    def _compose_args(self, args: tuple[Any, ...]) -> bytes | None:
        if not args:
            return None
        tdu = compose(
            args[0] if len(args) == 1 else list(args),
            types=self.registry,
            resources=self._compose_resource,
        )
        limit = self.remote_limit(EpAuthPacketHeader.MAXIMUM_PACKET_SIZE)
        if limit:
            size = ParsedTdu.measure(tdu, 0, len(tdu), 0).payload_length
            if size > limit:
                raise AsyncException(
                    ErrorType.MANAGEMENT,
                    ExceptionCode.PARSER_LIMIT_EXCEEDED,
                    f"Composed packet payload of {size} bytes exceeds the peer's advertised "
                    f"{limit}-byte limit.",
                )
        return tdu

    def decode(self, tdu: ParsedTdu | None) -> Any:
        """Decode the value of a received packet (``None`` when it carried none)."""
        if tdu is None:
            return None
        return parse(tdu.tdu_bytes, types=self.registry, **self.parser.parse_limits())

    # ---- inbound packets ------------------------------------------------------------------

    def _dispatch(self, packet: EpPacket) -> None:
        if packet.method == EpPacketMethod.REPLY:
            self._dispatch_reply(packet.action, packet.callback_id, packet.tdu)
        elif packet.method == EpPacketMethod.REQUEST:
            self._process_request(packet.action, packet.callback_id, packet.tdu)
        elif packet.method == EpPacketMethod.NOTIFICATION:
            if packet.action in (
                EpPacketNotification.PROPERTY_MODIFIED,
                EpPacketNotification.EVENT_OCCURRED,
            ):
                self._resource_notification(packet.action, packet.tdu)
            elif self.on_notification is not None:
                self._run_handler(self.on_notification, self, packet.action, packet.tdu)
        # Extension packets carry nothing this version understands.

    def _process_request(self, action: int, callback_id: int, tdu: ParsedTdu | None) -> None:
        if self._hosted is not None:
            handler = self._hosted.handler_for(action)
            if handler is not None:
                self._spawn(self._hosted.run(handler, callback_id, tdu))
                return
        if self.on_request is not None:
            self._run_handler(self.on_request, self, action, callback_id, tdu)
            return
        # esiur-ts leaves a request nobody handles unanswered, so the peer waits forever.
        self.send_error(
            ErrorType.MANAGEMENT,
            callback_id,
            ExceptionCode.NOT_IMPLEMENTED,
            "This node does not handle that request.",
        )

    def _run_handler(self, handler: Callable[..., Any], *args: Any) -> None:
        try:
            result = handler(*args)
        except Exception:
            logger.exception("EP handler failed")
            return
        if inspect.isawaitable(result):
            self._spawn(result)

    def _spawn(self, awaitable: Awaitable[Any]) -> asyncio.Task[None]:
        async def run() -> None:
            try:
                await awaitable
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("EP handler failed")

        task = asyncio.get_running_loop().create_task(run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _dispatch_reply(self, action: int, callback_id: int, tdu: ParsedTdu | None) -> None:
        pending = self._requests.get(callback_id)
        if pending is None:
            return  # abandoned, or already answered
        try:
            if action == EpPacketReply.COMPLETED:
                del self._requests[callback_id]
                value = self.decode(tdu)
                if pending.resolve and _has_remote_reference(value):
                    self._spawn(self._settle_resolved(pending, value))
                else:
                    self._settle(pending, value)
            elif action in (EpPacketReply.PERMISSION_ERROR, EpPacketReply.EXECUTION_ERROR):
                del self._requests[callback_id]
                kind = (
                    ErrorType.MANAGEMENT
                    if action == EpPacketReply.PERMISSION_ERROR
                    else ErrorType.EXCEPTION
                )
                code, message = _error_fields(self.decode(tdu))
                self._settle_error(pending, AsyncException(kind, code, message))
            elif action == EpPacketReply.PROPAGATED:
                _notify(pending.on_propagated, self.decode(tdu))
            elif action == EpPacketReply.CHUNK:
                _notify(pending.on_chunk, self.decode(tdu))
            elif action == EpPacketReply.WARNING:
                _notify(pending.on_warning, *_error_fields(self.decode(tdu)))
            elif action == EpPacketReply.PROGRESS:
                values = _as_list(self.decode(tdu))
                _notify(pending.on_progress, _int_at(values, 0), _int_at(values, 1))
            # STREAM only announces that chunks follow.
        except (ParserError, NotImplementedError) as error:
            self._requests.pop(callback_id, None)
            self._settle_error(pending, _decode_failure(error))

    async def _settle_resolved(self, pending: _Pending, value: Any) -> None:
        try:
            self._settle(pending, await self._resolve_value(value))
        except asyncio.CancelledError:  # the connection closed meanwhile
            self._settle_error(
                pending,
                AsyncException(
                    ErrorType.MANAGEMENT, ExceptionCode.HOST_NOT_REACHABLE, "Connection closed."
                ),
            )
            raise
        except Exception as error:
            self._settle_error(pending, AsyncException.from_error(error))

    @staticmethod
    def _settle(pending: _Pending, value: Any) -> None:
        if not pending.future.done():
            pending.future.set_result(value)

    @staticmethod
    def _settle_error(pending: _Pending, error: AsyncException) -> None:
        if not pending.future.done():
            pending.future.set_exception(error)

    # ---- remote resources -----------------------------------------------------------------

    def _compose_resource(self, value: Any) -> ResourceId | None:
        """How a resource object is written to this peer. A proxy this connection attached is
        the peer's own resource (a ``LocalResource`` reference from the receiver's view); a
        resource of this node's warehouse is one the peer attaches to (a ``RemoteResource``)."""
        if isinstance(value, EpResource):
            if value.connection is not self:
                raise ValueError(
                    "A resource attached through another connection cannot be sent here."
                )
            return ResourceId(True, value.instance_id)
        if isinstance(value, Resource):
            instance = value.instance
            if self.warehouse is None or instance is None or instance.warehouse is not self.warehouse:
                raise ValueError("Only resources hosted by this connection's warehouse can be sent.")
            return ResourceId(False, instance.id)
        return None

    def compose_value(self, value: Any) -> bytes:
        """One value as a TDU, the way it is written to this peer."""
        return compose(value, types=self.registry, resources=self._compose_resource)

    async def get(self, link: str) -> EpResource:
        """Resolve a resource link on the peer (``"sys/greeter"``) and attach to it."""
        return await self.attach(await self.get_resource_id(link))

    async def get_resource_id(self, link: str) -> int:
        """The instance id of the resource at ``link``."""
        found = await self.send_request(
            EpPacketRequest.GET_RESOURCE_ID_BY_LINK, link, resolve_resources=False
        )
        if isinstance(found, ResourceId):
            return found.id
        if isinstance(found, int) and not isinstance(found, bool):
            return found
        raise AsyncException(
            ErrorType.MANAGEMENT,
            ExceptionCode.PARSE_ERROR,
            "GetResourceIdByLink did not return a resource id.",
        )

    async def attach(self, instance_id: int) -> EpResource:
        """Attach to the peer's resource ``instance_id``: fetch its type and current property
        values, and start receiving its notifications. Attaching again returns the same proxy."""
        existing = self._attached.get(instance_id)
        if existing is not None:
            return existing
        inflight = self._attaching.get(instance_id)
        if inflight is not None:
            return await asyncio.shield(inflight)
        attached: asyncio.Future[EpResource] = asyncio.get_running_loop().create_future()
        attached.add_done_callback(lambda f: f.cancelled() or f.exception())
        self._attaching[instance_id] = attached
        try:
            resource = await self._attach(instance_id)
        except BaseException as error:
            if not attached.done():
                attached.set_exception(
                    error if isinstance(error, Exception) else AsyncException.from_error(error)
                )
            raise
        else:
            attached.set_result(resource)
            return resource
        finally:
            self._attaching.pop(instance_id, None)
            self._needed.pop(instance_id, None)

    async def _attach(self, instance_id: int) -> EpResource:
        reply = await self.send_request(
            EpPacketRequest.ATTACH_RESOURCE, instance_id, resolve_resources=False
        )
        # [type id, generation, revision, link, hops, property values]
        if not isinstance(reply, list) or len(reply) < 5:
            raise _malformed("AttachResource did not return the resource's description.")
        type_id = _as_int(reply[0])
        cursor = _cursor(reply[1], reply[2])
        typedef = await self._typedef_of(instance_id, type_id)
        resource = EpResource(
            self,
            instance_id,
            typedef,
            type_id=typedef.id or type_id,
            cursor=cursor,
            link=reply[3] if isinstance(reply[3], str) else "",
            hops=_as_int(reply[4]),
        )
        # Published before its values are decoded, so a value that refers back to this
        # resource resolves to it instead of waiting for an attach that is waiting on it.
        self._needed[instance_id] = resource
        raw = reply[5] if len(reply) > 5 else None
        if isinstance(raw, bytes):
            await self._apply_snapshot(resource, raw)
        self._attached[instance_id] = resource
        return resource

    async def _apply_snapshot(self, resource: EpResource, raw: bytes) -> None:
        """Read the ``(age, date, value)`` triples, one per property in definition order."""
        offset = 0
        limits = self.parser.parse_limits()
        for property_ in resource.typedef.properties:
            parts: list[Any] = []
            for _ in range(3):
                try:
                    value, used = parse_with_length(raw, offset, types=self.registry, **limits)
                except (ParserError, NotImplementedError) as error:
                    raise _decode_failure(error) from error
                parts.append(value)
                offset += used
            age, date, value = parts
            resource._set_snapshot(
                property_.index,
                _as_int(age),
                date if isinstance(date, dt.datetime) else None,
                await self._resolve_value(value),
            )

    async def _typedef_of(self, instance_id: int, type_id: int) -> TypeDef:
        """The definition of an attached resource's type: by the id the peer reported, and
        through the resource itself when the peer does not serve the type by id (it reports 0
        for a resource it relays)."""
        if type_id != 0:
            known = self._typedefs.get(type_id)
            if known is not None:
                return known
            try:
                return await self.fetch_typedef(type_id)
            except AsyncException:
                pass
        return await self.fetch_typedef_by_resource_id(instance_id)

    async def fetch_typedef(self, type_id: int) -> TypeDef:
        """A type's definition by the id the peer knows it by."""
        known = self._typedefs.get(type_id)
        if known is not None:
            return known
        info = await self.send_request(EpPacketRequest.TYPEDEF_BY_ID, UInt64(type_id))
        return self._remember_typedef(info, type_id)

    async def fetch_typedef_by_resource_id(self, instance_id: int) -> TypeDef:
        """The definition of the type of the peer's resource ``instance_id``."""
        info = await self.send_request(EpPacketRequest.TYPEDEF_BY_RESOURCE_ID, instance_id)
        return self._remember_typedef(info, 0)

    def _remember_typedef(self, info: Any, requested_id: int) -> TypeDef:
        if isinstance(info, bytes):
            # esiur-ts sends the definition as raw data holding a complete TypeDef TDU.
            try:
                info = parse(info, types=self.registry, **self.parser.parse_limits())
            except (ParserError, NotImplementedError) as error:
                raise _decode_failure(error) from error
        if not isinstance(info, TypeDefInfo):
            raise _malformed("The peer did not return a TypeDef.")
        typedef = TypeDef(info)
        if info.id != 0:
            self._typedefs[info.id] = typedef
        elif requested_id != 0:
            self._typedefs[requested_id] = typedef
        return typedef

    def invoke(self, instance_id: int, index: int, *args: Any) -> asyncio.Future[Any]:
        """Call function ``index`` of the peer's resource ``instance_id``."""
        return self.send_request(
            EpPacketRequest.INVOKE_FUNCTION, instance_id, UInt8(index), list(args)
        )

    def static_call(self, type_id: int, index: int, *args: Any) -> asyncio.Future[Any]:
        """Call static function ``index`` of the peer's type ``type_id``; no resource is involved."""
        return self.send_request(
            EpPacketRequest.STATIC_CALL, UInt64(type_id), UInt8(index), list(args)
        )

    def set_property(self, instance_id: int, index: int, value: Any) -> asyncio.Future[Any]:
        """Write property ``index`` of the peer's resource ``instance_id``."""
        return self.send_request(EpPacketRequest.SET_PROPERTY, instance_id, UInt8(index), value)

    async def subscribe(
        self, instance_id: int, index: int, after: ResourceCursor | None = None
    ) -> ResourceCursor:
        """Ask the peer to push event ``index`` of resource ``instance_id``. The peer rejects a
        second subscription to the same event, so callers must track their own (see
        :meth:`EpResource.on_event`). Occurrences it replays arrive before this returns."""
        after = after or ResourceCursor.empty()
        result = await self.send_request(
            EpPacketRequest.SUBSCRIBE,
            instance_id,
            UInt8(index),
            after.generation_bytes,
            UInt64(after.revision),
        )
        if self._notifications is not None and not self._notifications.done():
            await asyncio.gather(self._notifications, return_exceptions=True)
        if not isinstance(result, list) or len(result) < 2:
            raise _malformed("Subscribe did not return a cursor.")
        return _cursor(result[0], result[1])

    def unsubscribe(self, instance_id: int, index: int) -> asyncio.Future[Any]:
        """Stop the peer pushing event ``index`` of resource ``instance_id``."""
        return self.send_request(EpPacketRequest.UNSUBSCRIBE, instance_id, UInt8(index))

    async def detach(self, instance_id: int) -> None:
        """Stop receiving a resource's notifications; it keeps living for other peers."""
        await self.send_request(EpPacketRequest.DETACH_RESOURCE, instance_id)
        self._attached.pop(instance_id, None)

    async def _resolve_value(self, value: Any) -> Any:
        """Replace the peer's resource references in a decoded value with attached proxies."""
        if isinstance(value, ResourceId):
            return value if value.local else await self._resolve_resource(value.id)
        if not _has_remote_reference(value):
            return value
        if isinstance(value, list):
            return [await self._resolve_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple([await self._resolve_value(item) for item in value])
        if isinstance(value, dict):
            return {key: await self._resolve_value(item) for key, item in value.items()}
        return value

    async def _resolve_resource(self, instance_id: int) -> EpResource:
        return (
            self._attached.get(instance_id)
            or self._needed.get(instance_id)
            or await self.attach(instance_id)
        )

    def _resource_notification(self, action: int, tdu: ParsedTdu | None) -> None:
        """A ``PropertyModified`` or ``EventOccurred`` notification. Values that refer to
        resources are attached first, and nothing overtakes a notification still waiting for
        that, so listeners see changes in the order the peer made them."""
        try:
            values = self.decode(tdu)
        except (ParserError, NotImplementedError) as error:
            logger.error("EP closing a connection after an undecodable notification: %s", error)
            self.close()
            return
        previous = self._notifications
        if (previous is None or previous.done()) and not _has_remote_reference(values):
            self._apply_notification(action, values)
        else:
            self._notifications = self._spawn(self._queued_notification(previous, action, values))

    async def _queued_notification(
        self, previous: asyncio.Task[None] | None, action: int, values: Any
    ) -> None:
        if previous is not None:
            await asyncio.gather(previous, return_exceptions=True)
        try:
            self._apply_notification(action, await self._resolve_value(values))
        except Exception:
            logger.exception("EP closing a connection after a failed notification")
            self.close()

    def _apply_notification(self, action: int, values: Any) -> None:
        # [instance id, generation, revision, date, member index, value]
        try:
            if not isinstance(values, list) or len(values) < 6:
                raise ValueError("a notification carries six values")
            resource = self._attached.get(_as_int(values[0]))
            if resource is None:
                return  # detached, or still being attached
            cursor = _cursor(values[1], values[2])
            index = _as_int(values[4])
            if action == EpPacketNotification.PROPERTY_MODIFIED:
                date = values[3] if isinstance(values[3], dt.datetime) else None
                resource._update_property(index, values[5], cursor, date)
            else:
                resource._apply_event(index, values[5], cursor)
        except (ValueError, AsyncException) as error:
            logger.error("EP closing a connection after a malformed notification: %s", error)
            self.close()

    def _notify_listener(self, listener: Callable[[Any], Any], value: Any) -> None:
        _notify(listener, value)

    # ---- handshake ------------------------------------------------------------------------

    def _declare(self) -> None:
        """Send the initiator's ``Initialize`` packet: the limits, and when asked for the
        encryption offer and the first step of the authentication."""
        try:
            headers = self._limit_headers() | self._local_headers
            if self.domain:
                headers[EpAuthPacketHeader.DOMAIN] = self.domain
            if self._encryption_mode != EncryptionMode.NONE:
                self._prepare_encryption_offer(headers)
            if self._authentication_mode != AuthenticationMode.NONE:
                handler = self._initiator_handler()
                first = handler.process(None)
                if first.ruling == AuthenticationRuling.FAILED:
                    raise AsyncException(
                        ErrorType.MANAGEMENT, ExceptionCode.ACCESS_DENIED, "Authentication failed."
                    )
                headers[EpAuthPacketHeader.AUTHENTICATION_PROTOCOL] = handler.protocol
                headers[EpAuthPacketHeader.AUTHENTICATION_DATA] = first.authentication_data
            self.send(
                EpAuthPacket.compose_initialize(
                    self._authentication_mode,
                    self._encryption_mode,
                    self._compose_auth_headers(headers),
                )
            )
        except Exception as error:
            self._fail_authentication(error)

    # ---- encryption negotiation -----------------------------------------------------------

    def _encryption_names(self) -> list[str]:
        names = list(self._encryption_providers)
        if self.warehouse is not None:
            names += [n for n in self.warehouse.encryption_provider_names if n not in names]
        if not names and self._direction == "initiator" and encryption_available():
            self._encryption_providers[AesEncryptionProvider.NAME] = AesEncryptionProvider()
            names = [AesEncryptionProvider.NAME]
        return names

    def _encryption_provider_named(self, name: str) -> EncryptionProvider | None:
        found = self._encryption_providers.get(name)
        if found is None and self.warehouse is not None:
            found = self.warehouse.try_get_encryption_provider(name)
        return found

    def _prepare_encryption_offer(self, headers: dict[int, Any]) -> None:
        """Initiator: offer the supported cipher names and a fresh nonce."""
        if self._authentication_mode == AuthenticationMode.NONE:
            raise ValueError("Session-key encryption requires an authenticated session.")
        if self._encryption_mode != EncryptionMode.ENCRYPT_WITH_SESSION_KEY:
            raise ValueError(f"Unsupported encryption mode `{int(self._encryption_mode)}`.")
        offered = [n for n in self._encryption_names() if self._encryption_provider_named(n)]
        if not offered:
            raise ValueError(
                "Encryption was requested but none of the offered providers are registered."
            )
        self._offered_encryption = offered
        nonce = secrets.token_bytes(32)
        for target in (self._local_headers, headers):
            target[EpAuthPacketHeader.SUPPORTED_CIPHERS] = offered
            target[EpAuthPacketHeader.CIPHER_NONCE] = nonce
        self._local_headers.pop(EpAuthPacketHeader.CIPHER_TYPE, None)

    def _negotiate_encryption(self, packet: EpAuthPacket, local: dict[int, Any]) -> bool:
        """Responder: pick an offered cipher this node has, and answer with it and a nonce."""
        requested = packet.encryption_mode
        if requested == EncryptionMode.NONE:
            self._encryption_mode = EncryptionMode.NONE
            return True
        if requested != EncryptionMode.ENCRYPT_WITH_SESSION_KEY:
            return self._reject_encryption("The requested encryption mode is not supported.")
        self._encryption_mode = EncryptionMode.ENCRYPT_WITH_SESSION_KEY
        if packet.auth_mode == AuthenticationMode.NONE:
            return self._reject_encryption("Session-key encryption requires authentication.")
        offered = _strings(self._remote_headers.get(EpAuthPacketHeader.SUPPORTED_CIPHERS))
        selected = next((n for n in offered if self._encryption_provider_named(n)), None)
        if selected is None:
            return self._reject_encryption("No mutually supported encryption provider is available.")
        if not _valid_nonce(self._remote_headers.get(EpAuthPacketHeader.CIPHER_NONCE)):
            return self._reject_encryption("The initiator did not supply a valid cipher nonce.")
        self._encryption_provider = self._encryption_provider_named(selected)
        supported = [n for n in self._encryption_names() if self._encryption_provider_named(n)]
        nonce = secrets.token_bytes(32)
        for target in (self._local_headers, local):
            target[EpAuthPacketHeader.SUPPORTED_CIPHERS] = supported
            target[EpAuthPacketHeader.CIPHER_TYPE] = selected
            target[EpAuthPacketHeader.CIPHER_NONCE] = nonce
        return True

    def _accept_encryption(self) -> bool:
        """Initiator: take the responder's cipher selection from its Acknowledge headers."""
        selected = self._remote_headers.get(EpAuthPacketHeader.CIPHER_TYPE)
        if self._encryption_mode == EncryptionMode.NONE:
            return selected is None or self._reject_encryption(
                "The responder selected encryption that was not requested."
            )
        if (
            not isinstance(selected, str)
            or not selected.strip()
            or selected not in self._offered_encryption
        ):
            return self._reject_encryption("The responder did not select an offered provider.")
        if not _valid_nonce(self._remote_headers.get(EpAuthPacketHeader.CIPHER_NONCE)):
            return self._reject_encryption("The responder did not supply a valid cipher nonce.")
        provider = self._encryption_provider_named(selected)
        if provider is None:
            return self._reject_encryption(
                f"Encryption provider `{selected}` is not registered locally."
            )
        self._encryption_provider = provider
        return True

    def _reject_encryption(self, message: str) -> bool:
        try:
            self._send_auth_data(EpAuthPacketMethod.ERROR_MUST_ENCRYPT, message)
        except Exception:
            logger.debug("EP could not report an encryption refusal", exc_info=True)
        self._fail_authentication(message, suppress_send=True)
        return False

    def _start_encryption(self) -> None:
        """Derive the session cipher and turn record protection on, both directions."""
        if self._cipher is not None:
            return
        key = self._session_key
        if not key:
            raise ValueError("The authentication provider did not derive a session key.")
        if self._encryption_provider is None:
            raise ValueError("No encryption provider was negotiated.")
        initiator = self._direction == "initiator"
        local, remote = self._local_headers, self._remote_headers
        nonce = EpAuthPacketHeader.CIPHER_NONCE
        initiator_nonce, responder_nonce = (
            (local.get(nonce), remote.get(nonce))
            if initiator
            else (remote.get(nonce), local.get(nonce))
        )
        if not isinstance(initiator_nonce, bytes) or not isinstance(responder_nonce, bytes):
            raise TypeError("Missing negotiated cipher nonce.")
        if initiator:
            offered = tuple(self._offered_encryption)
            protocol = self._authentication_handler.protocol if self._authentication_handler else ""
            selected = str(remote.get(EpAuthPacketHeader.CIPHER_TYPE))
            domain = self.domain
        else:
            offered = tuple(_strings(remote.get(EpAuthPacketHeader.SUPPORTED_CIPHERS)))
            protocol = str(remote.get(EpAuthPacketHeader.AUTHENTICATION_PROTOCOL) or "")
            selected = str(local.get(EpAuthPacketHeader.CIPHER_TYPE))
            domain = str(remote.get(EpAuthPacketHeader.DOMAIN) or "")
        self._cipher = self._encryption_provider.create_cipher(
            EncryptionContext(
                key=key,
                direction=(
                    AuthenticationDirection.INITIATOR
                    if initiator
                    else AuthenticationDirection.RESPONDER
                ),
                mode=self._encryption_mode,
                protocol=selected,
                offered_protocols=offered,
                authentication_mode=self._authentication_mode,
                authentication_protocol=protocol,
                domain=domain,
                initiator_nonce=initiator_nonce,
                responder_nonce=responder_nonce,
            )
        )
        self._decrypt_inbound = True
        self._encryption_active = True

    # ---- handshake ------------------------------------------------------------------------

    def _initiator_handler(self) -> AuthenticationHandler:
        if self._authentication_handler is not None:
            return self._authentication_handler
        provider = self._authentication_provider
        if provider is None and self.warehouse is not None:
            provider = self.warehouse.try_get_authentication_provider(self._authentication_protocol)
        if provider is None:
            raise AsyncException(
                ErrorType.MANAGEMENT, ExceptionCode.ACCESS_DENIED, "Authentication provider not found."
            )
        handler = provider.create_handler(
            AuthenticationContext(
                direction=AuthenticationDirection.INITIATOR,
                mode=self._authentication_mode,
                domain=self.domain,
                host_name=self._host_name,
                initiator_identity=self._local_identity,
                responder_identity=self._responder_identity,
            )
        )
        if handler is None:
            raise AsyncException(
                ErrorType.MANAGEMENT, ExceptionCode.NOT_SUPPORTED, "Authentication handler not found."
            )
        self._authentication_provider = provider
        self._authentication_handler = handler
        return handler

    def _require_handler(self) -> AuthenticationHandler:
        if self._authentication_handler is None:
            raise AsyncException(
                ErrorType.MANAGEMENT,
                ExceptionCode.ACCESS_DENIED,
                "Authentication handler is not initialized.",
            )
        return self._authentication_handler

    def _send_auth_headers(self, method: EpAuthPacketMethod, headers: dict[int, Any]) -> None:
        self.send(EpAuthPacket.compose_method(method, self._compose_auth_headers(headers)))

    def _handle_auth_initialize(self, packet: EpAuthPacket) -> None:
        if self._direction != "responder":
            raise AsyncException(
                ErrorType.MANAGEMENT, ExceptionCode.ACCESS_DENIED, "Unexpected Initialize packet."
            )
        self._remote_headers, remote_data = self._parse_auth_headers(packet)
        local = self._limit_headers() | self._local_headers
        if not self._negotiate_encryption(packet, local):
            return

        if packet.auth_mode == AuthenticationMode.NONE:
            if not self.allow_unauthorized:
                self._send_auth_data(
                    EpAuthPacketMethod.ERROR_TERMINATE, "Unauthorized access not allowed."
                )
                self._fail_authentication("Unauthorized access not allowed.", suppress_send=True)
                return
            self._send_auth_headers(EpAuthPacketMethod.SESSION_ESTABLISHED, local)
            self._authentication_mode = AuthenticationMode.NONE
            self._complete_authentication()
            return

        protocol = self._remote_headers.get(EpAuthPacketHeader.AUTHENTICATION_PROTOCOL)
        if not isinstance(protocol, str):
            self._refuse_authentication(local, "Authentication protocol is missing.")
            return
        provider = None
        if self.warehouse is not None:
            provider = self.warehouse.try_get_authentication_provider(protocol)
        if (
            provider is None
            and self._authentication_provider is not None
            and self._authentication_provider.default_name == protocol
        ):
            provider = self._authentication_provider
        if provider is None:
            self._refuse_authentication(local, "Authentication provider not found.")
            return

        self._authentication_mode = AuthenticationMode(packet.auth_mode)
        self._authentication_protocol = protocol
        self._authentication_provider = provider
        handler = provider.create_handler(
            AuthenticationContext(
                direction=AuthenticationDirection.RESPONDER,
                mode=self._authentication_mode,
                domain=str(self._remote_headers.get(EpAuthPacketHeader.DOMAIN) or self.domain or ""),
                host_name=self._host_name,
                materials=(AuthenticationMaterial(AuthenticationMaterialType.DATA, remote_data),),
            )
        )
        if handler is None:
            self._refuse_authentication(local, "Authentication handler not found.")
            return

        self._authentication_handler = handler
        result = handler.process(remote_data)
        local[EpAuthPacketHeader.AUTHENTICATION_DATA] = result.authentication_data
        if result.ruling == AuthenticationRuling.FAILED:
            self._send_auth_headers(EpAuthPacketMethod.DENIED, local)
            self._fail_authentication("Authentication failed.", suppress_send=True)
        elif result.ruling == AuthenticationRuling.IN_PROGRESS:
            self._send_auth_headers(EpAuthPacketMethod.PROCEED_TO_HANDSHAKE, local)
        else:
            self._send_auth_headers(EpAuthPacketMethod.SESSION_ESTABLISHED, local)
            self._complete_authentication(result)

    def _refuse_authentication(self, local: dict[int, Any], message: str) -> None:
        self._send_auth_headers(EpAuthPacketMethod.NOT_SUPPORTED, local)
        self._fail_authentication(message, suppress_send=True)

    def _handle_auth_acknowledge(self, packet: EpAuthPacket) -> None:
        if self._authentication_mode == AuthenticationMode.NONE:
            if packet.method == EpAuthPacketMethod.SESSION_ESTABLISHED:
                self._remote_headers, _ = self._parse_auth_headers(packet)
                self._complete_authentication()
            else:
                self._fail_authentication(self._read_auth_error_message(packet), suppress_send=True)
            return

        if packet.method in (EpAuthPacketMethod.DENIED, EpAuthPacketMethod.NOT_SUPPORTED):
            self._fail_authentication(self._read_auth_error_message(packet), suppress_send=True)
            return
        if packet.method not in (
            EpAuthPacketMethod.PROCEED_TO_HANDSHAKE,
            EpAuthPacketMethod.PROCEED_TO_FINAL_HANDSHAKE,
            EpAuthPacketMethod.SESSION_ESTABLISHED,
        ):
            return

        self._remote_headers, remote_data = self._parse_auth_headers(packet)
        if not self._accept_encryption():
            return
        result = self._require_handler().process(remote_data)
        if result.ruling == AuthenticationRuling.FAILED:
            self._fail_authentication("Authentication failed.")
        elif result.ruling == AuthenticationRuling.IN_PROGRESS:
            if packet.method == EpAuthPacketMethod.PROCEED_TO_HANDSHAKE:
                self._send_auth_data(EpAuthPacketMethod.HANDSHAKE, result.authentication_data)
            else:
                self._fail_authentication("Bad authentication protocol sequence.")
        else:
            self._store_authentication_result(result)
            if packet.method == EpAuthPacketMethod.SESSION_ESTABLISHED:
                self._complete_authentication(result)
            else:
                self._send_auth_data(EpAuthPacketMethod.FINAL_HANDSHAKE, result.authentication_data)

    def _handle_auth_action(self, packet: EpAuthPacket) -> None:
        if packet.method not in (EpAuthPacketMethod.HANDSHAKE, EpAuthPacketMethod.FINAL_HANDSHAKE):
            return
        result = self._require_handler().process(self.decode(packet.tdu))
        if result.ruling == AuthenticationRuling.FAILED:
            self._fail_authentication("Authentication failed.")
        elif result.ruling == AuthenticationRuling.IN_PROGRESS:
            self._send_auth_data(EpAuthPacketMethod.HANDSHAKE, result.authentication_data)
        else:
            self._store_authentication_result(result)
            if result.authentication_data is not None:
                self._send_auth_data(EpAuthPacketMethod.FINAL_HANDSHAKE, result.authentication_data)
            if (
                packet.method == EpAuthPacketMethod.FINAL_HANDSHAKE
                or result.authentication_data is None
            ):
                self.send(EpAuthPacket.compose_method(EpAuthPacketMethod.ESTABLISHED))
                self._complete_authentication(result)

    def _store_authentication_result(self, result: AuthenticationResult) -> None:
        self._session_established = True
        self._local_identity = result.local_identity
        self._remote_identity = result.remote_identity
        self._session_key = result.session_key

    def _complete_authentication(self, result: AuthenticationResult | None = None) -> None:
        if result is not None:
            self._store_authentication_result(result)
        self._session_established = True
        if self._encryption_mode != EncryptionMode.NONE:
            # Everything up to here was the last plaintext; from now on records are protected.
            try:
                self._start_encryption()
            except Exception as error:
                self._fail_authentication(error)
                return
        self._cancel_deadline()
        self._authenticated = True
        if self._ready is not None and not self._ready.done():
            self._ready.set_result(None)
        self._run_provider_hook("login")

    def _run_provider_hook(self, name: str) -> None:
        provider = self._authentication_provider
        if provider is None:
            return
        try:
            result = getattr(provider, name)(self.session)
            if inspect.isawaitable(result):
                self._spawn(result)
        except Exception:
            logger.exception("EP authentication provider %s hook failed", name)

    @property
    def session(self) -> AuthenticationSession:
        """What is known about the peer: identities, key, headers, encryption state. A new
        snapshot each time, sharing its ``variables`` with the connection."""
        return AuthenticationSession(
            authentication_mode=self._authentication_mode,
            local_headers=self._local_headers,
            remote_headers=self._remote_headers,
            local_identity=self._local_identity,
            remote_identity=self._remote_identity,
            key=self._session_key,
            authenticated=self._authenticated,
            variables=self._variables,
            encryption_mode=self._encryption_mode,
            encryption_active=self._encryption_active,
            remote_maximum_packet_size=self.remote_limit(EpAuthPacketHeader.MAXIMUM_PACKET_SIZE),
            remote_maximum_allocation_size=self.remote_limit(
                EpAuthPacketHeader.MAXIMUM_ALLOCATION_SIZE
            ),
            remote_maximum_collection_items=self.remote_limit(
                EpAuthPacketHeader.MAXIMUM_COLLECTION_ITEMS
            ),
            remote_maximum_type_metadata_depth=self.remote_limit(
                EpAuthPacketHeader.MAXIMUM_TYPE_METADATA_DEPTH
            ),
            remote_maximum_encrypted_record_size=self.remote_limit(
                EpAuthPacketHeader.MAXIMUM_ENCRYPTED_RECORD_SIZE
            ),
        )

    @property
    def local_identity(self) -> str | None:
        """The identity this node proved (``None`` for an anonymous session)."""
        return self._local_identity

    @property
    def remote_identity(self) -> str | None:
        """The identity the peer proved (``None`` if it proved none)."""
        return self._remote_identity

    @property
    def session_key(self) -> bytes | None:
        """The secret the authentication protocol derived, if it derives one."""
        return self._session_key

    @property
    def is_encrypted(self) -> bool:
        return self._encryption_active

    def _limit_headers(self) -> dict[int, Any]:
        parser = self.parser
        return {
            EpAuthPacketHeader.MAXIMUM_PACKET_SIZE: parser.maximum_packet_size,
            EpAuthPacketHeader.MAXIMUM_ALLOCATION_SIZE: parser.maximum_allocation_size,
            EpAuthPacketHeader.MAXIMUM_COLLECTION_ITEMS: parser.maximum_collection_items,
            EpAuthPacketHeader.MAXIMUM_TYPE_METADATA_DEPTH: parser.maximum_type_metadata_depth,
            EpAuthPacketHeader.MAXIMUM_ENCRYPTED_RECORD_SIZE: parser.maximum_encrypted_record_size,
        }

    def _compose_auth_headers(self, headers: dict[int, Any]) -> bytes:
        return compose(TypedMap(t.u8, t.dynamic, dict(headers)), types=self.registry)

    def _handle_auth_packet(self, packet: EpAuthPacket) -> None:
        try:
            match packet.command:
                case EpAuthPacketCommand.INITIALIZE:
                    self._handle_auth_initialize(packet)
                case EpAuthPacketCommand.ACKNOWLEDGE:
                    self._handle_auth_acknowledge(packet)
                case EpAuthPacketCommand.ACTION:
                    self._handle_auth_action(packet)
                case EpAuthPacketCommand.EVENT:
                    self._handle_auth_event(packet)
        except Exception as error:
            self._fail_authentication(error)

    def _handle_auth_event(self, packet: EpAuthPacket) -> None:
        if packet.method == EpAuthPacketMethod.ESTABLISHED:
            if self._session_established:
                self._complete_authentication()
            else:
                self._fail_authentication("Authentication error.")
        elif packet.method in (
            EpAuthPacketMethod.ERROR_TERMINATE,
            EpAuthPacketMethod.ERROR_MUST_ENCRYPT,
            EpAuthPacketMethod.ERROR_RETRY,
        ):
            self._fail_authentication(self._read_auth_error_message(packet), suppress_send=True)

    def _send_auth_data(self, method: EpAuthPacketMethod, data: Any) -> None:
        tdu = None if data is None else compose(data, types=self.registry)
        self.send(EpAuthPacket.compose_method(method, tdu))

    def _parse_auth_headers(self, packet: EpAuthPacket) -> tuple[dict[int, Any], Any]:
        """The headers of an auth packet, and the authentication data among them."""
        value = self.decode(packet.tdu)
        if value is None:
            return {}, None
        if not isinstance(value, dict):
            raise AsyncException(
                ErrorType.MANAGEMENT,
                ExceptionCode.PARSE_ERROR,
                "Authentication headers must be a map.",
            )
        headers = {int(key): item for key, item in value.items()}
        return headers, headers.pop(EpAuthPacketHeader.AUTHENTICATION_DATA, None)

    def _read_auth_error_message(self, packet: EpAuthPacket) -> str:
        try:
            value = self.decode(packet.tdu)
        except (ParserError, NotImplementedError):
            return "Authentication error."
        if isinstance(value, str):
            return value
        if isinstance(value, dict) and value.get(EpAuthPacketHeader.ERROR_MESSAGE) is not None:
            return str(value[EpAuthPacketHeader.ERROR_MESSAGE])
        return "Authentication error."

    def _fail_authentication(self, error: object, *, suppress_send: bool = False) -> None:
        self._cancel_deadline()
        exception = (
            error
            if isinstance(error, AsyncException)
            else AsyncException(ErrorType.MANAGEMENT, ExceptionCode.ACCESS_DENIED, str(error))
        )
        if self._ready is not None and not self._ready.done():
            self._ready.set_exception(exception)
        if not suppress_send:
            try:
                self._send_auth_data(EpAuthPacketMethod.ERROR_TERMINATE, exception.message)
            except Exception:
                logger.debug("EP could not report an authentication failure", exc_info=True)
        self.close()

    def _restart_deadline(self) -> None:
        self._cancel_deadline()
        if not self.authentication_timeout:
            return
        self._deadline = asyncio.get_running_loop().call_later(
            self.authentication_timeout, self._deadline_expired
        )

    def _deadline_expired(self) -> None:
        self._deadline = None
        if self._authenticated:
            return
        self._fail_authentication(
            AsyncException(
                ErrorType.MANAGEMENT,
                ExceptionCode.TIMEOUT,
                "Authentication did not complete before the configured deadline.",
            ),
            suppress_send=True,
        )

    def _cancel_deadline(self) -> None:
        if self._deadline is not None:
            self._deadline.cancel()
            self._deadline = None


def _has_remote_reference(value: Any) -> bool:
    """Whether a decoded value holds a reference to one of the peer's resources."""
    if isinstance(value, ResourceId):
        return not value.local
    if isinstance(value, list | tuple):
        return any(_has_remote_reference(item) for item in value)
    if isinstance(value, dict):
        return any(_has_remote_reference(item) for item in value.values())
    return False


_RECORD_HEADER_SIZE = 4


def _strings(value: Any) -> list[str]:
    """The strings of a list header; anything else is an empty list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _valid_nonce(value: Any) -> bool:
    return isinstance(value, bytes) and 16 <= len(value) <= 64


def _malformed(message: str) -> AsyncException:
    return AsyncException(ErrorType.MANAGEMENT, ExceptionCode.PARSE_ERROR, message)


def _as_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise _malformed(f"Expected an integer, received {type(value).__name__}.")


def _cursor(generation: Any, revision: Any) -> ResourceCursor:
    try:
        return ResourceCursor.from_wire(generation, revision)
    except ValueError as error:
        raise _malformed(str(error)) from error


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if hasattr(value, "values") and isinstance(value.values, list):  # a TypedList
        return list(value.values)
    return []


def _int_at(values: list[Any], index: int) -> int:
    item = values[index] if index < len(values) else 0
    return item if isinstance(item, int) and not isinstance(item, bool) else 0


def _error_fields(value: Any) -> tuple[int, str]:
    """The ``[code, message]`` an error or warning reply carries."""
    values = _as_list(value)
    message = values[1] if len(values) > 1 else ""
    return _int_at(values, 0), "" if message is None else str(message)


def _notify(callback: Callable[..., Any] | None, *args: Any) -> None:
    if callback is None:
        return
    try:
        result = callback(*args)
        if inspect.isawaitable(result):
            asyncio.ensure_future(result)
    except Exception:
        logger.exception("EP reply callback failed")


def _decode_failure(error: Exception) -> AsyncException:
    if isinstance(error, ParserLimitError):
        code = ExceptionCode.PARSER_LIMIT_EXCEEDED
    elif isinstance(error, NotImplementedError):
        code = ExceptionCode.NOT_IMPLEMENTED
    else:
        code = ExceptionCode.PARSE_ERROR
    return AsyncException(ErrorType.MANAGEMENT, code, str(error))
