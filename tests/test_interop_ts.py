"""Interop against a real esiur-ts server.

The ``ts_server`` fixture (tests/conftest.py) starts ``tools/ts-test-server.mjs``, an esiur-ts
``EpServer`` over WebSocket. Tests are skipped when Node or an esiur-ts checkout with its
dependencies is not available; point ``ESIUR_TS_PATH`` at a checkout other than ``../esiur-ts``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from esiur.core import AsyncException, ErrorType, ExceptionCode
from esiur.net import EpConnection
from esiur.net.packets import EpAuthPacketHeader, EpPacketRequest


def url(server: dict[str, Any], scheme: str = "ws") -> str:
    return f"{scheme}://127.0.0.1:{server['port']}"


async def test_the_handshake_with_an_esiur_ts_server(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as client:
        assert client.is_authenticated and client.is_connected
        # The server advertises its parser budgets in its Acknowledge headers.
        assert client.remote_limit(EpAuthPacketHeader.MAXIMUM_PACKET_SIZE) == 8 * 1024 * 1024
        assert client.remote_limit(EpAuthPacketHeader.MAXIMUM_COLLECTION_ITEMS) == 65_536


async def test_ep_scheme_urls_connect_over_websocket(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server, "ep")) as client:
        assert client.is_authenticated


async def test_a_resource_link_resolves_to_its_id(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as client:
        found = await client.send_request(EpPacketRequest.GET_RESOURCE_ID_BY_LINK, "sys/greeter")
        assert found == ts_server["greeterId"]


async def test_an_unknown_link_is_a_management_error(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as client:
        with pytest.raises(AsyncException) as missing:
            await client.send_request(EpPacketRequest.GET_RESOURCE_ID_BY_LINK, "sys/nothing")
        assert missing.value.type == ErrorType.MANAGEMENT
        assert missing.value.code == ExceptionCode.RESOURCE_NOT_FOUND
        # The connection is still usable after an error reply.
        assert (
            await client.send_request(EpPacketRequest.GET_RESOURCE_ID_BY_LINK, "sys/greeter")
            == ts_server["greeterId"]
        )


async def test_an_unknown_typedef_name_is_reported(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as client:
        with pytest.raises(AsyncException) as missing:
            await client.send_request(EpPacketRequest.TYPEDEF_IDS_BY_NAMES, ["No.Such.Type"])
        assert missing.value.code == ExceptionCode.TYPEDEF_NOT_FOUND


async def test_requests_in_flight_together_are_each_answered(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as client:
        results = await asyncio.gather(
            *(
                client.send_request(EpPacketRequest.GET_RESOURCE_ID_BY_LINK, "sys/greeter")
                for _ in range(50)
            )
        )
        assert results == [ts_server["greeterId"]] * 50


async def test_a_value_larger_than_one_websocket_frame_round_trips(ts_server: dict[str, Any]) -> None:
    async with await EpConnection.connect(url(ts_server)) as client:
        with pytest.raises(AsyncException) as missing:
            await client.send_request(
                EpPacketRequest.GET_RESOURCE_ID_BY_LINK, "sys/" + "x" * 1_000_000
            )
        assert missing.value.code == ExceptionCode.RESOURCE_NOT_FOUND


async def test_a_request_the_ts_server_does_not_handle_is_not_answered_by_this_node(
    ts_server: dict[str, Any],
) -> None:
    # esiur-ts has no KeepAlive handler, so nothing comes back; the request must stay pending
    # (and be dropped cleanly when the connection closes) rather than break anything.
    async with await EpConnection.connect(url(ts_server)) as client:
        silent = client.send_request(EpPacketRequest.KEEP_ALIVE)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(silent), 0.3)
    with pytest.raises(AsyncException) as lost:
        await silent
    assert lost.value.code == ExceptionCode.HOST_NOT_REACHABLE


async def test_connecting_to_a_closed_port_fails() -> None:
    with pytest.raises(OSError):
        await EpConnection.connect("ws://127.0.0.1:1", connect_timeout=5)
