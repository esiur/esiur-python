"""Differential test of the packet layer against the real esiur-ts parser and composer.

Regenerate the fixture with ``node tools/gen-packet-vectors.mjs ../esiur-ts``.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from esiur.data import ParsedTdu, ParserLimitError
from esiur.net.packets import EpAuthPacket, EpPacket

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "ts-packet-vectors.json").read_text("utf-8")
)


def _assert_tdu(tdu: ParsedTdu | None, expect: dict[str, Any] | None, base: int) -> None:
    if expect is None:
        assert tdu is None
        return
    assert tdu is not None
    assert tdu.identifier == expect["identifier"]
    assert tdu.index == expect["index"]
    assert tdu.tdu_class == expect["tduClass"]
    assert tdu.tdu_offset - base == expect["offset"]
    assert tdu.payload_offset - base == expect["payloadOffset"]
    assert tdu.payload_length == expect["payloadLength"]
    assert tdu.total_length == expect["totalLength"]


def _check_packet(data: bytes, offset: int, expect: dict[str, Any]) -> None:
    packet = EpPacket()
    if "error" in expect:
        with pytest.raises(ParserLimitError):
            packet.parse(data, offset)
        return
    ret = packet.parse(data, offset)
    assert ret == expect["ret"]
    if ret < 0:
        assert packet == EpPacket()  # a short buffer leaves the packet untouched
        return
    assert packet.method == expect["method"]
    assert packet.action == expect["action"]
    assert packet.callback_id == expect["callbackId"]
    assert packet.has_tdu == expect["hasTdu"]
    _assert_tdu(packet.tdu, expect["tdu"], offset)


def _check_auth(data: bytes, offset: int, expect: dict[str, Any]) -> None:
    packet = EpAuthPacket()
    if "error" in expect:
        with pytest.raises(ParserLimitError):
            packet.parse(data, offset)
        return
    ret = packet.parse(data, offset)
    assert ret == expect["ret"]
    if ret < 0:
        assert packet == EpAuthPacket()
        return
    assert packet.command == expect["command"]
    assert packet.has_tdu == expect["hasTdu"]
    if packet.command == 0:
        assert packet.auth_mode == expect["authMode"]
        assert packet.encryption_mode == expect["encryptionMode"]
    else:
        assert packet.method == expect["method"]
    _assert_tdu(packet.tdu, expect["tdu"], offset)


@pytest.mark.parametrize("vector", FIXTURE["compose"], ids=[v["name"] for v in FIXTURE["compose"]])
def test_compose_matches_esiur_ts(vector: dict[str, Any]) -> None:
    args = vector["args"]
    tdu = bytes.fromhex(args["tdu"]) if "tdu" in args else None
    match vector["kind"]:
        case "request":
            composed = EpPacket.compose_request(args["action"], args["callbackId"], tdu)
        case "reply":
            composed = EpPacket.compose_reply(args["action"], args["callbackId"], tdu)
        case "notification":
            composed = EpPacket.compose_notification(args["action"], tdu)
        case "auth_initialize":
            composed = EpAuthPacket.compose_initialize(
                args["authMode"], args["encryptionMode"], tdu
            )
        case "auth_method":
            composed = EpAuthPacket.compose_method(args["method"], tdu)
        case other:
            raise AssertionError(other)
    assert composed.hex() == vector["hex"]


@pytest.mark.parametrize("index", range(256))
def test_every_ep_packet_header_byte_parses_like_esiur_ts(index: int) -> None:
    vector = FIXTURE["packetSweep"][index]
    _check_packet(bytes.fromhex(vector["hex"]), 0, vector["expect"])


@pytest.mark.parametrize("index", range(256))
def test_every_auth_packet_header_byte_parses_like_esiur_ts(index: int) -> None:
    vector = FIXTURE["authSweep"][index]
    _check_auth(bytes.fromhex(vector["hex"]), 0, vector["expect"])


def test_every_truncation_reports_the_same_shortfall_as_esiur_ts() -> None:
    for vector in FIXTURE["prefixes"]:
        check = _check_packet if vector["kind"] == "packet" else _check_auth
        check(bytes.fromhex(vector["hex"]), 0, vector["expect"])


@pytest.mark.parametrize("vector", FIXTURE["edges"], ids=[v["name"] for v in FIXTURE["edges"]])
def test_edge_cases_match_esiur_ts(vector: dict[str, Any]) -> None:
    check = _check_packet if vector["kind"] == "packet" else _check_auth
    check(bytes.fromhex(vector["hex"]), vector["offset"], vector["expect"])
