import pytest

from esiur.data import ParsedTdu, ParserLimitError, TypedMap, compose, parse, t
from esiur.net.packets import (
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
from esiur.security import AuthenticationMode, EncryptionMode


def test_a_request_round_trips_and_its_value_decodes() -> None:
    argument = compose([1, "two", None])
    wire = EpPacket.compose_request(EpPacketRequest.INVOKE_FUNCTION, 41, argument)
    packet = EpPacket()
    assert packet.parse(wire) == len(wire)
    assert packet.method == EpPacketMethod.REQUEST
    assert packet.action == EpPacketRequest.INVOKE_FUNCTION
    assert packet.callback_id == 41 and packet.has_tdu
    assert packet.tdu is not None and packet.tdu.tdu_bytes == argument
    assert parse(packet.tdu.tdu_bytes) == [1, "two", None]


def test_replies_and_notifications_use_their_own_headers() -> None:
    reply = EpPacket.compose_reply(EpPacketReply.EXECUTION_ERROR, 3)
    assert reply == bytes([0x80 | 5, 3, 0, 0, 0])
    notification = EpPacket.compose_notification(EpPacketNotification.EVENT_OCCURRED, compose(1))
    assert notification[0] == 0x20 | 1 and len(notification) == 1 + len(compose(1))
    parsed = EpPacket()
    parsed.parse(notification)
    assert parsed.method == EpPacketMethod.NOTIFICATION and parsed.callback_id == 0


def test_a_packet_without_a_value_has_no_tdu() -> None:
    packet = EpPacket()
    assert packet.parse(EpPacket.compose_request(EpPacketRequest.KEEP_ALIVE, 1)) == 5
    assert packet.tdu is None and not packet.has_tdu


def test_a_value_is_framed_without_being_decoded() -> None:
    # A Typed TDU's metadata is not read at this layer: the payload spans metadata and value.
    value = compose(t.nullable(t.i32))  # a TRU value
    plain = ParsedTdu.measure(compose([1, 2, 3]), 0)
    assert plain.valid and plain.metadata is None and plain.total_length == len(compose([1, 2, 3]))
    packet = EpPacket()
    packet.parse(EpPacket.compose_notification(0, value))
    assert packet.tdu is not None and packet.tdu.tdu_bytes == value


def test_a_short_buffer_reports_how_much_is_missing_and_changes_nothing() -> None:
    wire = EpPacket.compose_request(EpPacketRequest.QUERY, 9, compose("hello"))
    packet = EpPacket()
    for cut in range(len(wire)):
        needed = packet.parse(wire[:cut])
        assert needed < 0
        assert packet == EpPacket()
        # Supplying exactly what was asked for always makes progress.
        assert -needed >= 1
    assert packet.parse(wire) == len(wire)


def test_feeding_a_stream_one_byte_at_a_time_yields_every_packet() -> None:
    stream = b"".join(
        [
            EpPacket.compose_request(EpPacketRequest.KEEP_ALIVE, 1),
            EpPacket.compose_reply(EpPacketReply.COMPLETED, 1, compose("ok")),
            EpPacket.compose_notification(EpPacketNotification.PROPERTY_MODIFIED, compose(5)),
        ]
    )
    buffer = bytearray()
    seen: list[tuple[int, int]] = []
    for byte in stream:
        buffer.append(byte)
        while buffer:
            packet = EpPacket()
            used = packet.parse(bytes(buffer))
            if used < 0:
                break
            seen.append((packet.method, packet.action))
            del buffer[:used]
    assert seen == [(1, 0x18), (2, 0), (0, 0)] and not buffer


def test_parsing_reuses_a_packet_without_leaking_the_previous_one() -> None:
    packet = EpPacket()
    packet.parse(EpPacket.compose_request(EpPacketRequest.QUERY, 77, compose(1)))
    packet.parse(EpPacket.compose_notification(EpPacketNotification.EVENT_OCCURRED))
    assert packet.callback_id == 0 and packet.tdu is None

    auth = EpAuthPacket()
    auth.parse(EpAuthPacket.compose_initialize(AuthenticationMode.DUAL_IDENTITY, 2))
    auth.parse(EpAuthPacket.compose_method(EpAuthPacketMethod.HANDSHAKE))
    assert auth.method == EpAuthPacketMethod.HANDSHAKE
    assert auth.auth_mode == AuthenticationMode.NONE
    assert auth.encryption_mode == EncryptionMode.NONE
    auth.parse(EpAuthPacket.compose_initialize(1, 1))
    assert auth.method == EpAuthPacketMethod.INITIALIZE  # not the previous packet's method


def test_the_declared_size_budget_is_enforced_before_waiting_for_the_body() -> None:
    declares_one_megabyte = bytes([0x20, 0x59, 0x10, 0x00, 0x00])  # 3 length bytes: 1 MiB
    # Within the default budget the packet is merely incomplete ...
    assert EpPacket().parse(declares_one_megabyte) < 0
    # ... but a tighter one rejects it outright.
    with pytest.raises(ParserLimitError):
        EpPacket().parse(declares_one_megabyte, maximum_payload_length=1024)
    with pytest.raises(ParserLimitError):
        EpAuthPacket().parse(declares_one_megabyte, maximum_payload_length=1024)


def test_the_parse_window_must_lie_inside_the_buffer() -> None:
    wire = EpPacket.compose_request(EpPacketRequest.KEEP_ALIVE, 1)
    packet = EpPacket()
    with pytest.raises(ValueError):
        packet.parse(wire, 6)
    with pytest.raises(ValueError):
        packet.parse(wire, 0, 99)
    with pytest.raises(ValueError):
        packet.parse(wire, -1)
    assert packet.parse(wire + b"\xff", 0, len(wire)) == len(wire)  # bytes past `ends` are not read
    assert packet.parse(b"", 0) == -1


def test_unknown_actions_are_carried_not_rejected() -> None:
    packet = EpPacket()
    packet.parse(bytes([0x40 | 0x05, 1, 0, 0, 0]))  # request action 5 has no name
    assert packet.action == 5 and packet.method == EpPacketMethod.REQUEST
    assert EpPacket.compose_request(5, 1) == bytes([0x45, 1, 0, 0, 0])


def test_composing_validates_every_field() -> None:
    with pytest.raises(ValueError, match="five bits"):
        EpPacket.compose_request(32, 1)
    with pytest.raises(ValueError, match="five bits"):
        EpPacket.compose_notification(-1)
    with pytest.raises(ValueError, match="32 bits"):
        EpPacket.compose_reply(0, 1 << 32)
    with pytest.raises(ValueError, match="32 bits"):
        EpPacket.compose_reply(0, -1)
    for bad in (b"", compose("x") + b"\x00", compose("hello")[:-1], bytes([0x49])):  # the last is a string missing its length byte
        with pytest.raises(ValueError, match="one complete TDU"):
            EpPacket.compose_request(0, 1, bad)
        with pytest.raises(ValueError, match="one complete TDU"):
            EpAuthPacket.compose_method(EpAuthPacketMethod.HANDSHAKE, bad)


def test_a_value_larger_than_the_default_budget_can_still_be_composed() -> None:
    # The budget belongs to the receiver (negotiated in the handshake), not to the composer.
    huge = compose(bytes(9 * 1024 * 1024))
    wire = EpPacket.compose_notification(0, huge)
    assert wire[1:] == huge


# ---------------------------------------------------------------------------- auth packets --


def test_initialize_packs_both_modes_into_the_header() -> None:
    wire = EpAuthPacket.compose_initialize(
        AuthenticationMode.RESPONDER_IDENTITY, EncryptionMode.ENCRYPT_WITH_SESSION_KEY_AND_ADDRESS
    )
    assert wire == bytes([0b0000_1010])
    packet = EpAuthPacket()
    assert packet.parse(wire) == 1
    assert packet.command == EpAuthPacketCommand.INITIALIZE
    assert packet.auth_mode == AuthenticationMode.RESPONDER_IDENTITY
    assert packet.encryption_mode == EncryptionMode.ENCRYPT_WITH_SESSION_KEY_AND_ADDRESS


def test_an_encryption_mode_this_version_lacks_is_kept_for_the_caller_to_refuse() -> None:
    packet = EpAuthPacket()
    packet.parse(bytes([0b0000_0011]))
    assert packet.encryption_mode == 3
    assert not isinstance(packet.encryption_mode, EncryptionMode)


def test_the_method_carries_its_command_and_unknown_methods_survive() -> None:
    packet = EpAuthPacket()
    packet.parse(EpAuthPacket.compose_method(EpAuthPacketMethod.SESSION_ESTABLISHED))
    assert packet.command == EpAuthPacketCommand.ACKNOWLEDGE
    assert packet.method == EpAuthPacketMethod.SESSION_ESTABLISHED
    packet.parse(bytes([0x80 | 0x0F]))
    assert packet.command == EpAuthPacketCommand.ACTION and packet.method == 0x8F


def test_auth_headers_travel_as_a_typed_map() -> None:
    headers = TypedMap(
        t.u8,
        t.dynamic,
        {
            EpAuthPacketHeader.DOMAIN: "example.com",
            EpAuthPacketHeader.MAXIMUM_PACKET_SIZE: 1 << 20,
        },
    )
    wire = EpAuthPacket.compose_initialize(
        AuthenticationMode.NONE, EncryptionMode.NONE, compose(headers)
    )
    packet = EpAuthPacket()
    assert packet.parse(wire) == len(wire) and packet.has_tdu
    assert packet.tdu is not None
    assert parse(packet.tdu.tdu_bytes) == {1: "example.com", 18: 1 << 20}


def test_auth_compose_validates_every_field() -> None:
    with pytest.raises(ValueError, match="two bits"):
        EpAuthPacket.compose_initialize(4, 0)
    with pytest.raises(ValueError, match="two bits"):
        EpAuthPacket.compose_initialize(0, -1)
    with pytest.raises(ValueError, match="0x20"):
        EpAuthPacket.compose_method(0x20)
    with pytest.raises(ValueError, match="0x20"):
        EpAuthPacket.compose_method(256)
    with pytest.raises(ValueError, match="0x20"):
        EpAuthPacket.compose_method(-1)


def test_an_auth_packet_short_buffer_changes_nothing() -> None:
    wire = EpAuthPacket.compose_method(EpAuthPacketMethod.HANDSHAKE, compose("abc"))
    packet = EpAuthPacket()
    for cut in range(len(wire)):
        assert packet.parse(wire[:cut]) < 0
        assert packet == EpAuthPacket()
    assert packet.parse(wire) == len(wire)
