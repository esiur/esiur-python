"""Authentication and encryption between Python and real esiur-ts nodes, in both directions:
a Python client against the esiur-ts server (tools/ts-test-server.mjs), and an esiur-ts client
(tools/ts-test-client.mjs) against a Python server."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest
from test_hosting_net import build_warehouse

from esiur.core import AsyncException
from esiur.net import EpConnection, EpServer
from esiur.security import (
    AesEncryptionProvider,
    AllowAll,
    AuthenticationMode,
    EncryptionMode,
    StaticPasswordProvider,
)

pytest.importorskip("cryptography")

MODES = [
    AuthenticationMode.INITIALIZER_IDENTITY,
    AuthenticationMode.RESPONDER_IDENTITY,
    AuthenticationMode.DUAL_IDENTITY,
]
ENCRYPTION = [EncryptionMode.NONE, EncryptionMode.ENCRYPT_WITH_SESSION_KEY]


def alice(password: str = "wonderland") -> StaticPasswordProvider:
    """What the Python client brings: it proves alice, and can check the server account."""
    return StaticPasswordProvider(
        accounts={"server": "srv-secret"}, credentials={"alice": password}, identity="alice"
    )


# ---- Python client, esiur-ts server ----------------------------------------------------------


@pytest.mark.parametrize("encryption", ENCRYPTION, ids=["plain", "encrypted"])
@pytest.mark.parametrize("mode", MODES, ids=["initiator", "responder", "dual"])
async def test_python_authenticates_to_an_esiur_ts_server(
    ts_server: dict[str, Any], mode: AuthenticationMode, encryption: EncryptionMode
) -> None:
    async with await EpConnection.connect(
        f"ws://127.0.0.1:{ts_server['port']}",
        authentication_mode=mode,
        encryption_mode=encryption,
        authentication_provider=alice(),
        identity=None if mode == AuthenticationMode.RESPONDER_IDENTITY else "alice",
    ) as connection:
        assert connection.is_authenticated
        assert connection.is_encrypted == (encryption != EncryptionMode.NONE)
        assert connection.session_key is not None and len(connection.session_key) == 64
        assert connection.local_identity == (
            None if mode == AuthenticationMode.RESPONDER_IDENTITY else "alice"
        )
        assert connection.remote_identity == (
            None if mode == AuthenticationMode.INITIALIZER_IDENTITY else "server"
        )
        greeter = await connection.get("sys/greeter")
        assert await greeter.add(20, 22) == 42
        heard: list[str] = []
        await greeter.on_event("ping", heard.append)
        await greeter.fire_ping("secured")
        for _ in range(100):
            if heard:
                break
            await asyncio.sleep(0.01)
        assert heard == ["secured"]
        big = "y" * 200_000
        assert await greeter.greet(big) == "Hi " + big


async def test_an_esiur_ts_server_refuses_a_wrong_password(ts_server: dict[str, Any]) -> None:
    with pytest.raises(AsyncException):
        await EpConnection.connect(
            f"ws://127.0.0.1:{ts_server['port']}",
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            authentication_provider=alice("not wonderland"),
            identity="alice",
        )


async def test_python_refuses_an_esiur_ts_server_it_cannot_verify(
    ts_server: dict[str, Any],
) -> None:
    impostor = StaticPasswordProvider(
        accounts={"server": "some other password"}, credentials={"alice": "wonderland"}, identity="alice"
    )
    with pytest.raises(AsyncException):
        await EpConnection.connect(
            f"ws://127.0.0.1:{ts_server['port']}",
            authentication_mode=AuthenticationMode.DUAL_IDENTITY,
            authentication_provider=impostor,
            identity="alice",
        )


async def test_python_cannot_encrypt_to_a_server_that_has_no_cipher(
    ts_server: dict[str, Any],
) -> None:
    class Unnamed(AesEncryptionProvider):
        default_name = "no-such-cipher"

    with pytest.raises(AsyncException):
        await EpConnection.connect(
            f"ws://127.0.0.1:{ts_server['port']}",
            authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,
            encryption_mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
            authentication_provider=alice(),
            identity="alice",
            encryption_providers=[Unnamed()],
        )


# ---- esiur-ts client, Python server ----------------------------------------------------------


async def run_ts_client(
    command: list[str], options: dict[str, Any], python_changes: Callable[[], None] | None = None
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Run the esiur-ts client scenario; returns its ``attached`` (or ``error``) report and its
    ``final`` one."""
    process = await asyncio.create_subprocess_exec(
        *command, json.dumps(options),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdout is not None and process.stdin is not None
    reports: dict[str, dict[str, Any]] = {}
    try:
        while "attached" not in reports and "error" not in reports:
            line = await asyncio.wait_for(process.stdout.readline(), 90)
            if not line:
                stderr = await process.stderr.read() if process.stderr else b""
                raise AssertionError(f"the esiur-ts client ended early: {stderr.decode()}")
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and "phase" in value:
                reports[value["phase"]] = value
        if "error" in reports:
            return reports["error"], None
        if python_changes is not None:
            python_changes()
        process.stdin.write(b"go\n")
        await process.stdin.drain()
        while "final" not in reports:
            line = await asyncio.wait_for(process.stdout.readline(), 30)
            if not line:
                break
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and "phase" in value:
                reports[value["phase"]] = value
        await asyncio.wait_for(process.wait(), 30)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    return reports["attached"], reports.get("final")


def python_server_provider() -> StaticPasswordProvider:
    return StaticPasswordProvider(
        accounts={"alice": "wonderland"}, credentials={"server": "srv-secret"}, identity="server"
    )


@pytest.mark.parametrize("encryption", ENCRYPTION, ids=["plain", "encrypted"])
@pytest.mark.parametrize("mode", MODES, ids=["initiator", "responder", "dual"])
async def test_an_esiur_ts_client_authenticates_to_a_python_server(
    ts_client_command: Callable[[int], list[str]],
    mode: AuthenticationMode,
    encryption: EncryptionMode,
) -> None:
    warehouse, greeter, _ = await build_warehouse(AllowAll())
    async with await EpServer.listen(
        warehouse,
        port=0,
        allow_unauthorized=False,
        authentication_provider=python_server_provider(),
        encryption_providers=[AesEncryptionProvider()],
    ) as server:
        written: list[str] = []

        def change_in_python() -> None:
            written.append(greeter.label)  # what the client wrote, before this overwrites it
            greeter.label = "changed in python"

        attached, final = await run_ts_client(
            ts_client_command(server.port),
            {"authenticationMode": int(mode), "encryptionMode": int(encryption)},
            python_changes=change_in_python,
        )
        assert "error" not in attached, attached
        assert attached["encrypted"] is (encryption != EncryptionMode.NONE)
        assert attached["keyLength"] == 64
        assert attached["greet"] == "Hi TS" and attached["echoId"] == attached["otherId"]
        assert written == ["written by ts"]  # the client wrote it over the secured session
        assert final is not None and final["label"] == "changed in python"
        # The server saw the same peer the client claims to be.
        assert attached["localIdentity"] == (
            None if mode == AuthenticationMode.RESPONDER_IDENTITY else "alice"
        )
        assert attached["remoteIdentity"] == (
            None if mode == AuthenticationMode.INITIALIZER_IDENTITY else "server"
        )
    await warehouse.close()


async def test_an_esiur_ts_client_with_a_wrong_password_is_refused(
    ts_client_command: Callable[[int], list[str]],
) -> None:
    warehouse, _, _ = await build_warehouse(AllowAll())
    async with await EpServer.listen(
        warehouse,
        port=0,
        allow_unauthorized=False,
        authentication_provider=python_server_provider(),
        encryption_providers=[AesEncryptionProvider()],
    ) as server:
        report, final = await run_ts_client(
            ts_client_command(server.port),
            {
                "authenticationMode": int(AuthenticationMode.INITIALIZER_IDENTITY),
                "password": "not wonderland",
            },
        )
        assert report["phase"] == "error" and final is None
        await asyncio.sleep(0.1)
        assert not server.connections
    await warehouse.close()


async def test_an_esiur_ts_client_cannot_use_a_python_server_without_a_cipher(
    ts_client_command: Callable[[int], list[str]],
) -> None:
    warehouse, _, _ = await build_warehouse(AllowAll())
    async with await EpServer.listen(
        warehouse,
        port=0,
        allow_unauthorized=False,
        authentication_provider=python_server_provider(),
    ) as server:
        report, _ = await run_ts_client(
            ts_client_command(server.port),
            {
                "authenticationMode": int(AuthenticationMode.INITIALIZER_IDENTITY),
                "encryptionMode": int(EncryptionMode.ENCRYPT_WITH_SESSION_KEY),
            },
        )
        assert report["phase"] == "error"
    await warehouse.close()
