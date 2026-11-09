"""A real esiur-ts client against a Python server (tools/ts-test-client.mjs bundles esiur-ts)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from hosted_types import Greeter
from test_hosting_net import build_warehouse

from esiur.net import EpServer
from esiur.security import AllowAll


async def read_phase(process: asyncio.subprocess.Process, phase: str) -> dict[str, Any]:
    assert process.stdout is not None
    while True:
        line = await asyncio.wait_for(process.stdout.readline(), 90)
        if not line:
            stderr = await process.stderr.read() if process.stderr else b""
            raise AssertionError(f"the esiur-ts client ended early: {stderr.decode()}")
        try:
            value = json.loads(line)
        except ValueError:
            continue  # something the library logged
        if isinstance(value, dict) and value.get("phase") == phase:
            return value


async def test_a_ts_client_uses_a_python_server(ts_client_command: Callable[[int], list[str]]) -> None:
    warehouse, greeter, other = await build_warehouse(AllowAll())
    extra = await warehouse.put("sys/extra", Greeter())
    async with await EpServer.listen(warehouse, port=0) as server:
        process = await asyncio.create_subprocess_exec(
            *ts_client_command(server.port),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            attached = await read_phase(process, "attached")

            # What the client learned from the TypeDef and the attach reply.
            assert attached["typeName"] == "Greeter"
            assert attached["properties"] == ["label", "partner", "serial", "visits"]
            assert attached["functions"] == sorted(
                ["greet", "fire_ping", "fire_tick", "range", "echo", "add", "fail", "slow", "version"]
            )
            assert attached["events"] == ["ping", "tick"]
            assert (attached["visits0"], attached["label0"], attached["serial0"]) == (
                0, "hello", "S-1",
            )
            assert attached["greeterId"] == greeter.instance.id
            assert attached["partnerId"] == attached["otherId"] == other.instance.id
            assert attached["cycle"] is True

            # Calls, with results and errors.
            assert attached["greet"] == "Hi TS"
            assert attached["add"] == 42
            assert attached["range"] == [0, 1, 2, 3]
            assert attached["slow"] == "QUIET"
            assert "RuntimeError: boom" in attached["fail"]
            assert "TypeError" in attached["badCall"]
            assert attached["echoId"] == other.instance.id  # a resource out and back in

            # What the client did to the server's objects.
            assert greeter.label == "written by ts"
            assert attached["visitsAfterGreets"] == greeter.visits == 1
            assert attached["pings"] == ["from ts"]
            assert attached["ticks"] == ["tick from ts"]

            # Changes the server makes on its own reach the client.
            greeter.visits = 99
            greeter.label = "from python"
            greeter.partner = extra  # a resource the client has not attached yet
            greeter.ping.emit("from python")
            greeter.tick.emit("tick from python")
            assert process.stdin is not None
            process.stdin.write(b"go\n")
            await process.stdin.drain()

            final = await read_phase(process, "final")
            assert final["visits"] == 99
            assert final["label"] == "from python"
            assert final["partnerId"] == extra.instance.id
            assert final["pings"] == ["from ts", "from python"]
            assert final["ticks"] == ["tick from ts", "tick from python"]
            assert await asyncio.wait_for(process.wait(), 30) == 0
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    await warehouse.close()
