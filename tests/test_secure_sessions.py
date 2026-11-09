"""Authenticated and encrypted sessions: a Python client against a Python server on real sockets."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from hosted_types import Greeter

from esiur.core import AsyncException, ExceptionCode
from esiur.net import EpConnection, EpServer
from esiur.resource import MemoryStore, Warehouse
from esiur.security import (
    ActionType,
    AesEncryptionProvider,
    AllowAll,
    AuthenticationMode,
    AuthenticationSession,
    CallbackPermissions,
    EncryptionMode,
    Ruling,
    StaticPasswordProvider,
)

pytest.importorskip("cryptography")

MARKER = "secret-marker-3f9a"


class Recording(StaticPasswordProvider):
    """A password provider that notes the sessions it logs in and out."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.logins: list[AuthenticationSession] = []
        self.logouts: list[AuthenticationSession] = []

    def login(self, session: AuthenticationSession) -> bool:
        self.logins.append(session)
        return True

    async def logout(self, session: AuthenticationSession) -> bool:  # type: ignore[override]
        self.logouts.append(session)
        return True


def server_provider() -> Recording:
    return Recording(
        accounts={"alice": "wonderland", "bob": "builder"},
        credentials={"server": "srv-secret"},
        identity="server",
    )


def client_provider(identity: str = "alice", password: str = "wonderland") -> StaticPasswordProvider:
    return StaticPasswordProvider(
        accounts={"server": "srv-secret"}, credentials={identity: password}, identity=identity
    )


class Relay:
    """A TCP relay in front of a server that keeps every byte it carries, and can corrupt the
    server-to-client direction."""

    def __init__(self, target_port: int) -> None:
        self.target_port = target_port
        self.to_server = bytearray()
        self.to_client = bytearray()
        self.corrupt = False
        self.port = 0
        self._server: asyncio.Server | None = None
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> Relay:
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            "127.0.0.1", self.target_port
        )
        self._tasks += [
            asyncio.create_task(self._pump(reader, upstream_writer, self.to_server, False)),
            asyncio.create_task(self._pump(upstream_reader, writer, self.to_client, True)),
        ]

    async def _pump(
        self,
        source: asyncio.StreamReader,
        sink: asyncio.StreamWriter,
        record: bytearray,
        outbound_to_client: bool,
    ) -> None:
        try:
            while data := await source.read(65536):
                record += data
                if outbound_to_client and self.corrupt:
                    data = data[:-1] + bytes([data[-1] ^ 1])
                sink.write(data)
                await sink.drain()
        except OSError:
            pass
        finally:
            sink.close()

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._server.wait_closed()


async def build(**server_options: Any) -> SimpleNamespace:
    warehouse = Warehouse()
    warehouse.register_permissions(AllowAll())
    provider = server_provider()
    warehouse.register_authentication_provider(provider)
    warehouse.register_encryption_provider(AesEncryptionProvider())
    await warehouse.put("sys", MemoryStore())
    greeter = await warehouse.put("sys/greeter", Greeter())
    await warehouse.open()
    options = {"allow_unauthorized": False, "transport": "tcp"} | server_options
    server = await EpServer.listen(warehouse, port=0, **options)
    return SimpleNamespace(
        warehouse=warehouse, greeter=greeter, server=server, provider=provider,
        url=f"tcp://127.0.0.1:{server.port}",
    )


@pytest_asyncio.fixture
async def served() -> AsyncIterator[SimpleNamespace]:
    context = await build()
    try:
        yield context
    finally:
        await context.server.close()
        await context.warehouse.close()


def server_side(served: SimpleNamespace) -> EpConnection:
    (connection,) = served.server.connections
    return connection


# ---- authentication --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    [
        AuthenticationMode.INITIALIZER_IDENTITY,
        AuthenticationMode.RESPONDER_IDENTITY,
        AuthenticationMode.DUAL_IDENTITY,
    ],
)
async def test_every_authentication_mode_gives_a_working_session(
    served: SimpleNamespace, mode: AuthenticationMode
) -> None:
    async with await EpConnection.connect(
        served.url,
        authentication_mode=mode,
        authentication_provider=client_provider(),
        identity=None if mode == AuthenticationMode.RESPONDER_IDENTITY else "alice",
    ) as connection:
        assert connection.is_authenticated and not connection.is_encrypted
        peer = server_side(served)
        assert connection.session_key is not None and len(connection.session_key) == 64
        assert connection.session_key == peer.session_key
        proves_client = mode != AuthenticationMode.RESPONDER_IDENTITY
        proves_server = mode != AuthenticationMode.INITIALIZER_IDENTITY
        assert connection.local_identity == ("alice" if proves_client else None)
        assert connection.remote_identity == ("server" if proves_server else None)
        assert peer.remote_identity == ("alice" if proves_client else None)
        assert peer.local_identity == ("server" if proves_server else None)
        greeter = await connection.get("sys/greeter")
        assert await greeter.greet("authenticated") == "Hi authenticated"


async def test_the_password_provider_hears_about_logins_and_logouts(
    served: SimpleNamespace,
) -> None:
    async with await EpConnection.connect(
        served.url,
        authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
        authentication_provider=client_provider(),
        identity="alice",
    ):
        await asyncio.sleep(0.05)
        (login,) = served.provider.logins
        assert login.authenticated and login.remote_identity == "alice"
        assert login.remote_headers  # what the client announced, such as its limits
    await asyncio.sleep(0.2)
    assert [s.remote_identity for s in served.provider.logouts] == ["alice"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"provider": client_provider("alice", "wrong password"), "identity": "alice"},
        {"provider": client_provider("mallory", "anything"), "identity": "mallory"},
    ],
)
async def test_wrong_credentials_are_refused(
    served: SimpleNamespace, arguments: dict[str, Any]
) -> None:
    with pytest.raises(AsyncException):
        await EpConnection.connect(
            served.url,
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=arguments["provider"],
            identity=arguments["identity"],
        )
    await asyncio.sleep(0.1)
    assert not served.server.connections


async def test_a_client_that_distrusts_the_server_account_fails() -> None:
    context = await build()
    try:
        impostor = StaticPasswordProvider(
            accounts={"server": "a different server password"},
            credentials={"alice": "wonderland"},
            identity="alice",
        )
        with pytest.raises(AsyncException):
            await EpConnection.connect(
                context.url,
                authentication_mode=AuthenticationMode.DUAL_IDENTITY,
                authentication_provider=impostor,
                identity="alice",
            )
    finally:
        await context.server.close()
        await context.warehouse.close()


async def test_a_client_without_a_provider_cannot_authenticate(served: SimpleNamespace) -> None:
    with pytest.raises(AsyncException, match="provider not found"):
        await EpConnection.connect(
            served.url, authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY, identity="a"
        )


class OtherProtocol(StaticPasswordProvider):
    """The same exchange announced under a name the server has no provider for."""

    default_name = "other-v1"

    def create_handler(self, context: Any) -> Any:
        handler = super().create_handler(context)
        handler.protocol = "other-v1"
        return handler


async def test_an_unknown_authentication_protocol_is_refused(served: SimpleNamespace) -> None:
    with pytest.raises(AsyncException):
        await EpConnection.connect(
            served.url,
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=OtherProtocol(credentials={"alice": "x"}, identity="alice"),
            identity="alice",
        )
    await asyncio.sleep(0.1)
    assert not served.server.connections


async def test_the_provider_can_be_registered_on_the_clients_warehouse(
    served: SimpleNamespace,
) -> None:
    warehouse = Warehouse()
    warehouse.register_authentication_provider(client_provider())
    async with await EpConnection.connect(
        served.url,
        warehouse=warehouse,
        authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
        identity="alice",
    ) as connection:
        assert connection.is_authenticated


async def test_a_server_that_allows_anonymous_peers_also_accepts_authenticated_ones() -> None:
    context = await build(allow_unauthorized=True)
    try:
        async with await EpConnection.connect(context.url) as anonymous:
            assert (await anonymous.get("sys/greeter")).typedef.name == "Greeter"
            assert anonymous.local_identity is None and anonymous.session_key is None
        async with await EpConnection.connect(
            context.url,
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=client_provider(),
            identity="alice",
        ) as authenticated:
            assert authenticated.session_key is not None
    finally:
        await context.server.close()
        await context.warehouse.close()


# ---- permissions see the session -------------------------------------------------------------


async def test_a_permissions_manager_decides_by_the_peers_identity() -> None:
    seen: list[str | None] = []

    def only_alice_writes(
        resource: Any, session: AuthenticationSession | None, action: ActionType, *_: Any
    ) -> Ruling:
        if action != ActionType.SET_PROPERTY:
            return Ruling.DONT_CARE
        seen.append(session.remote_identity if session else None)
        return Ruling.ALLOWED if session and session.remote_identity == "alice" else Ruling.DENIED

    context = await build(allow_unauthorized=True)
    context.warehouse.register_permissions(CallbackPermissions(only_alice_writes))
    try:
        async with await EpConnection.connect(
            context.url,
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=client_provider("alice", "wonderland"),
            identity="alice",
        ) as alice:
            await (await alice.get("sys/greeter")).set("label", "set by alice")
        async with await EpConnection.connect(
            context.url,
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=StaticPasswordProvider(
                credentials={"bob": "builder"}, identity="bob"
            ),
            identity="bob",
        ) as bob:
            with pytest.raises(AsyncException) as denied:
                await (await bob.get("sys/greeter")).set("label", "set by bob")
            assert denied.value.code == ExceptionCode.ACCESS_DENIED
        async with await EpConnection.connect(context.url) as anonymous:
            with pytest.raises(AsyncException):
                await (await anonymous.get("sys/greeter")).set("label", "set by nobody")
        assert context.greeter.label == "set by alice"
        assert seen == ["alice", "bob", None]
    finally:
        await context.server.close()
        await context.warehouse.close()


# ---- encryption ------------------------------------------------------------------------------


async def test_an_encrypted_session_serves_resources_and_hides_the_traffic() -> None:
    context = await build()
    relay = await Relay(context.server.port).start()
    try:
        async with await EpConnection.connect(
            f"tcp://127.0.0.1:{relay.port}",
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            encryption_mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
            authentication_provider=client_provider(),
            identity="alice",
        ) as connection:
            assert connection.is_encrypted and server_side(context).is_encrypted
            greeter = await connection.get("sys/greeter")
            heard: list[str] = []
            await greeter.on_event("ping", heard.append)
            assert await greeter.greet(MARKER) == f"Hi {MARKER}"
            await greeter.fire_ping(MARKER)
            await greeter.set("label", MARKER)
            for _ in range(100):
                if heard:
                    break
                await asyncio.sleep(0.01)
            assert heard == [MARKER]
            assert context.greeter.label == MARKER
            assert connection.session.encryption_active
        wire = bytes(relay.to_server) + bytes(relay.to_client)
        assert MARKER.encode() not in wire
        assert b"Greeter" not in wire  # not even the type name
    finally:
        await relay.stop()
        await context.server.close()
        await context.warehouse.close()


async def test_the_same_traffic_without_encryption_is_readable_on_the_wire() -> None:
    context = await build()
    relay = await Relay(context.server.port).start()
    try:
        async with await EpConnection.connect(
            f"tcp://127.0.0.1:{relay.port}",
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=client_provider(),
            identity="alice",
        ) as connection:
            greeter = await connection.get("sys/greeter")
            await greeter.greet(MARKER)
        assert MARKER.encode() in bytes(relay.to_server) + bytes(relay.to_client)
    finally:
        await relay.stop()
        await context.server.close()
        await context.warehouse.close()


@pytest.mark.parametrize("mode", [AuthenticationMode.RESPONDER_IDENTITY, AuthenticationMode.DUAL_IDENTITY])
async def test_encryption_works_with_every_authentication_mode(
    served: SimpleNamespace, mode: AuthenticationMode
) -> None:
    async with await EpConnection.connect(
        served.url,
        authentication_mode=mode,
        encryption_mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
        authentication_provider=client_provider(),
        identity=None if mode == AuthenticationMode.RESPONDER_IDENTITY else "alice",
    ) as connection:
        assert connection.is_encrypted
        assert await (await connection.get("sys/greeter")).add(20, 22) == 42


async def test_a_large_message_is_one_encrypted_record_in_each_direction() -> None:
    context = await build()
    try:
        async with await EpConnection.connect(
            context.url,
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            encryption_mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
            authentication_provider=client_provider(),
            identity="alice",
        ) as connection:
            greeter = await connection.get("sys/greeter")
            big = "x" * 300_000
            assert await greeter.greet(big) == "Hi " + big
            results = await asyncio.gather(*(greeter.add(i, 1) for i in range(100)))
            assert results == [i + 1 for i in range(100)]
    finally:
        await context.server.close()
        await context.warehouse.close()


async def test_corrupting_a_record_closes_the_connection() -> None:
    context = await build()
    relay = await Relay(context.server.port).start()
    try:
        connection = await EpConnection.connect(
            f"tcp://127.0.0.1:{relay.port}",
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            encryption_mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
            authentication_provider=client_provider(),
            identity="alice",
        )
        greeter = await connection.get("sys/greeter")
        assert await greeter.add(1, 1) == 2
        relay.corrupt = True
        with pytest.raises(AsyncException) as failed:
            await asyncio.wait_for(greeter.add(2, 2), 5)
        assert failed.value.code == ExceptionCode.HOST_NOT_REACHABLE
        await asyncio.wait_for(connection.wait_closed(), 5)
    finally:
        await relay.stop()
        await context.server.close()
        await context.warehouse.close()


@pytest.mark.parametrize(
    ("client_options", "server_options"),
    [
        # The server has no matching encryption provider.
        ({}, {"register_encryption": False}),
        # Encryption without authentication has no key to use.
        ({"authentication_mode": AuthenticationMode.NONE}, {}),
        # A mode this version does not implement.
        ({"encryption_mode": EncryptionMode.ENCRYPT_WITH_SESSION_KEY_AND_ADDRESS}, {}),
    ],
)
async def test_encryption_that_cannot_be_negotiated_fails_the_connection(
    client_options: dict[str, Any], server_options: dict[str, Any]
) -> None:
    warehouse = Warehouse()
    warehouse.register_authentication_provider(server_provider())
    if server_options.get("register_encryption", True):
        warehouse.register_encryption_provider(AesEncryptionProvider())
    await warehouse.put("sys", MemoryStore())
    await warehouse.open()
    options: dict[str, Any] = {
        "authentication_mode": AuthenticationMode.INITIALIZER_IDENTITY,
        "encryption_mode": EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
        "authentication_provider": client_provider(),
        "identity": "alice",
        "encryption_providers": [AesEncryptionProvider()],
    } | client_options
    async with await EpServer.listen(warehouse, port=0, transport="tcp") as server:
        with pytest.raises(AsyncException):
            await EpConnection.connect(f"tcp://127.0.0.1:{server.port}", **options)
        await asyncio.sleep(0.1)
        assert not server.connections
    await warehouse.close()


async def test_a_server_refuses_unknown_encryption_modes_and_missing_authentication() -> None:
    """Drive the responder directly with hand-made Initialize packets."""
    from memory_socket import MemorySocket  # type: ignore[import-not-found]

    from esiur.data import TypedMap, compose, t
    from esiur.net.packets import EpAuthPacket, EpAuthPacketHeader, EpAuthPacketMethod

    for auth_mode, enc_mode in (
        (AuthenticationMode.INITIALIZER_IDENTITY, 3),
        (AuthenticationMode.NONE, EncryptionMode.ENCRYPT_WITH_SESSION_KEY),
    ):
        left, right = MemorySocket.pair()
        warehouse = Warehouse()
        warehouse.register_encryption_provider(AesEncryptionProvider())
        server = EpConnection(warehouse=warehouse)
        server.start_responder_handshake()
        server.assign(right)
        received: list[bytes] = []
        left.receiver = SimpleNamespace(  # type: ignore[assignment]
            network_connect=lambda s: None,
            network_receive=lambda s, d, sink=received: sink.append(d),
            network_close=lambda s: None,
        )
        headers = TypedMap(
            t.u8, t.dynamic, {EpAuthPacketHeader.SUPPORTED_CIPHERS: ["aes-gcm"],
                              EpAuthPacketHeader.CIPHER_NONCE: b"n" * 32}
        )
        left.send(EpAuthPacket.compose_initialize(auth_mode, enc_mode, compose(headers)))
        await asyncio.sleep(0.05)
        assert received, "the server answers before it closes"
        assert received[0][0] & 0xDF == EpAuthPacketMethod.ERROR_MUST_ENCRYPT
        await server.wait_closed()
