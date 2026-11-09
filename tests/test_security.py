"""The password protocol and the AES-GCM record cipher, without a network."""

from __future__ import annotations

import hashlib

import pytest

from esiur.security import (
    AesEncryptionProvider,
    AuthenticationContext,
    AuthenticationDirection,
    AuthenticationMode,
    AuthenticationResult,
    AuthenticationRuling,
    EncryptionContext,
    EncryptionMode,
    PasswordAuthenticationHandler,
    PasswordAuthenticationProvider,
    StaticPasswordProvider,
)
from esiur.security.encryption import hkdf_sha256
from esiur.security.password import sha3

# ---- primitives ------------------------------------------------------------------------------


def test_sha3_is_fips_202() -> None:
    assert sha3(b"").hex() == hashlib.sha3_256(b"").hexdigest()
    assert sha3(b"abc", 512) == hashlib.sha3_512(b"abc").digest()
    assert sha3(b"").hex().startswith("a7ffc6f8bf1ed766")  # the published SHA3-256 of nothing
    with pytest.raises(ValueError):
        sha3(b"", 100)


def test_hkdf_matches_rfc_5869_test_case_1() -> None:
    okm = hkdf_sha256(
        bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


# ---- the password exchange -------------------------------------------------------------------


def make_handlers(
    mode: AuthenticationMode,
    *,
    password: str = "wonderland",
    initiator: str | None = "alice",
    responder: str | None = "server",
    server_hosts: str = "alice",
    server_account_password: str = "srv-secret",
) -> tuple[PasswordAuthenticationHandler, PasswordAuthenticationHandler]:
    """The initiator proves ``alice`` (when the mode says so) and hosts the ``server`` account;
    the responder hosts ``alice`` and proves ``server``."""
    client = StaticPasswordProvider(
        accounts={"server": server_account_password},
        credentials={"alice": password},
        identity="alice"
    )
    server = StaticPasswordProvider(
        accounts={server_hosts: "wonderland"},
        credentials={"server": "srv-secret"},
        identity="server",
    )
    first = client.create_handler(
        AuthenticationContext(
            AuthenticationDirection.INITIATOR,
            mode,
            domain="test",
            initiator_identity=initiator if mode != AuthenticationMode.RESPONDER_IDENTITY else None,
        )
    )
    second = server.create_handler(
        AuthenticationContext(
            AuthenticationDirection.RESPONDER,
            mode,
            domain="test",
            responder_identity=responder if mode != AuthenticationMode.INITIALIZER_IDENTITY else None,
        )
    )
    assert isinstance(first, PasswordAuthenticationHandler)
    assert isinstance(second, PasswordAuthenticationHandler)
    return first, second


def exchange(
    initiator: PasswordAuthenticationHandler, responder: PasswordAuthenticationHandler
) -> tuple[AuthenticationResult, AuthenticationResult | None]:
    """Pass data between the two until one stops; returns each side's last result."""
    results: dict[bool, AuthenticationResult | None] = {True: initiator.process(None), False: None}
    speaker, listener, speaking = initiator, responder, True
    for _ in range(10):
        spoken = results[speaking]
        assert spoken is not None
        if spoken.ruling == AuthenticationRuling.FAILED:
            break
        answer = listener.process(spoken.authentication_data)
        results[not speaking] = answer
        if answer.ruling == AuthenticationRuling.FAILED or (
            answer.ruling == AuthenticationRuling.SUCCEEDED and answer.authentication_data is None
        ):
            break
        speaker, listener, speaking = listener, speaker, not speaking
    first = results[True]
    assert first is not None
    return first, results[False]


@pytest.mark.parametrize(
    "mode",
    [
        AuthenticationMode.INITIALIZER_IDENTITY,
        AuthenticationMode.RESPONDER_IDENTITY,
        AuthenticationMode.DUAL_IDENTITY,
    ],
)
def test_both_sides_derive_the_same_session_key(mode: AuthenticationMode) -> None:
    initiator, responder = exchange(*make_handlers(mode))
    assert responder is not None
    assert initiator.ruling == responder.ruling == AuthenticationRuling.SUCCEEDED
    assert initiator.session_key == responder.session_key
    assert initiator.session_key is not None and len(initiator.session_key) == 64


def test_the_initiator_proves_its_identity_and_the_responder_learns_it() -> None:
    initiator, responder = exchange(*make_handlers(AuthenticationMode.INITIALIZER_IDENTITY))
    assert responder is not None
    assert (initiator.local_identity, initiator.remote_identity) == ("alice", None)
    assert (responder.local_identity, responder.remote_identity) == (None, "alice")


def test_the_responder_proves_its_identity_to_the_initiator() -> None:
    initiator, responder = exchange(*make_handlers(AuthenticationMode.RESPONDER_IDENTITY))
    assert responder is not None
    assert initiator.remote_identity == "server" and responder.local_identity == "server"
    assert initiator.local_identity is None and responder.remote_identity is None


def test_in_dual_mode_each_side_learns_the_other() -> None:
    initiator, responder = exchange(*make_handlers(AuthenticationMode.DUAL_IDENTITY))
    assert responder is not None
    assert (initiator.local_identity, initiator.remote_identity) == ("alice", "server")
    assert (responder.local_identity, responder.remote_identity) == ("server", "alice")


@pytest.mark.parametrize(
    ("mode", "wrong"),
    [
        (AuthenticationMode.INITIALIZER_IDENTITY, {"password": "not the password"}),
        (AuthenticationMode.RESPONDER_IDENTITY, {"server_account_password": "not the password"}),
        (AuthenticationMode.DUAL_IDENTITY, {"password": "not the password"}),
        (AuthenticationMode.DUAL_IDENTITY, {"server_account_password": "not the password"}),
    ],
)
def test_a_wrong_password_fails_without_a_key(
    mode: AuthenticationMode, wrong: dict[str, str]
) -> None:
    initiator, responder = exchange(*make_handlers(mode, **wrong))
    results = [initiator, responder]
    assert any(r is not None and r.ruling == AuthenticationRuling.FAILED for r in results)
    assert all(r is None or r.session_key is None for r in results)


def test_an_unknown_account_fails() -> None:
    _, responder = exchange(
        *make_handlers(AuthenticationMode.INITIALIZER_IDENTITY, server_hosts="somebody-else")
    )
    assert responder is not None and responder.ruling == AuthenticationRuling.FAILED


def test_the_initiator_fails_when_it_has_no_password_to_prove() -> None:
    provider = StaticPasswordProvider()
    handler = provider.create_handler(
        AuthenticationContext(
            AuthenticationDirection.INITIATOR, AuthenticationMode.INITIALIZER_IDENTITY
        )
    )
    assert handler is not None
    assert handler.process(None).ruling == AuthenticationRuling.FAILED


def test_garbage_from_the_peer_fails_instead_of_raising() -> None:
    _, responder = make_handlers(AuthenticationMode.INITIALIZER_IDENTITY)
    for garbage in ("text", 5, [b"short", "alice"], [b"x" * 20], [None, None], {"a": 1}):
        _, fresh = make_handlers(AuthenticationMode.INITIALIZER_IDENTITY)
        assert fresh.process(garbage).ruling == AuthenticationRuling.FAILED
    assert responder.process([b"\x00" * 20, "alice"]).ruling == AuthenticationRuling.IN_PROGRESS


def test_a_reflected_nonce_is_refused() -> None:
    _, responder = make_handlers(AuthenticationMode.INITIALIZER_IDENTITY)
    # The peer echoes the responder's own nonce back: that is a reflection attack.
    assert responder._local_nonce
    result = responder.process([responder._local_nonce, "alice"])
    assert result.ruling == AuthenticationRuling.FAILED


def test_credentials_are_salted_hashes() -> None:
    first = PasswordAuthenticationProvider.create_credential("secret")
    second = PasswordAuthenticationProvider.create_credential(b"secret")
    assert first.salt != second.salt and first.hash != second.hash
    assert first.hash == sha3(b"secret" + (first.salt or b""))
    with pytest.raises(ValueError, match="empty"):
        PasswordAuthenticationProvider.create_credential("")


def test_a_static_provider_validates_its_identity() -> None:
    with pytest.raises(ValueError, match="No credential"):
        StaticPasswordProvider(credentials={"a": "x"}, identity="b")


# ---- the record cipher -----------------------------------------------------------------------


def contexts(**overrides: object) -> tuple[EncryptionContext, EncryptionContext]:
    shared = {
        "key": bytes(range(64)),
        "mode": EncryptionMode.ENCRYPT_WITH_SESSION_KEY,
        "protocol": "aes-gcm",
        "offered_protocols": ("aes-gcm",),
        "authentication_mode": AuthenticationMode.INITIALIZER_IDENTITY,
        "authentication_protocol": "password-sha3-v1",
        "domain": "test",
        "initiator_nonce": b"i" * 32,
        "responder_nonce": b"r" * 32,
    } | overrides
    return (
        EncryptionContext(direction=AuthenticationDirection.INITIATOR, **shared),  # type: ignore[arg-type]
        EncryptionContext(direction=AuthenticationDirection.RESPONDER, **shared),  # type: ignore[arg-type]
    )


def ciphers():  # type: ignore[no-untyped-def]
    pytest.importorskip("cryptography")
    initiator, responder = contexts()
    provider = AesEncryptionProvider()
    return provider.create_cipher(initiator), provider.create_cipher(responder)


def test_records_round_trip_in_both_directions() -> None:
    client, server = ciphers()
    for index in range(5):
        message = f"request {index}".encode() * (index + 1)
        assert server.decrypt(client.encrypt(message)) == message
        assert client.decrypt(server.encrypt(message[::-1])) == message[::-1]


def test_a_record_has_the_documented_layout() -> None:
    client, _ = ciphers()
    record = client.encrypt(b"hello")
    assert len(record) == 8 + 5 + 16  # sequence, ciphertext, tag
    assert record[:8] == (0).to_bytes(8, "big")
    assert client.encrypt(b"hello")[:8] == (1).to_bytes(8, "big")
    assert AesEncryptionProvider.maximum_record_overhead == 24


def test_a_tampered_record_is_refused() -> None:
    client, server = ciphers()
    record = bytearray(client.encrypt(b"transfer 100"))
    record[10] ^= 1
    with pytest.raises(ValueError, match="authentication failed"):
        server.decrypt(bytes(record))


def test_a_replayed_dropped_or_reordered_record_is_refused() -> None:
    client, server = ciphers()
    first, second, third = (client.encrypt(b"%d" % i) for i in range(3))
    with pytest.raises(ValueError, match="sequence"):
        server.decrypt(second)  # the first was dropped
    assert server.decrypt(first) == b"0"
    with pytest.raises(ValueError, match="sequence"):
        server.decrypt(first)  # replay
    assert server.decrypt(second) == b"1"
    assert server.decrypt(third) == b"2"
    with pytest.raises(ValueError, match="truncated"):
        server.decrypt(b"short")


def test_a_cipher_does_not_decrypt_its_own_direction() -> None:
    client, _ = ciphers()
    with pytest.raises(ValueError):
        client.decrypt(client.encrypt(b"loopback"))


def test_a_different_transcript_gives_unrelated_keys() -> None:
    pytest.importorskip("cryptography")
    provider = AesEncryptionProvider()
    initiator, _ = contexts()
    other_responder = contexts(responder_nonce=b"R" * 32)[1]
    with pytest.raises(ValueError):
        provider.create_cipher(other_responder).decrypt(
            provider.create_cipher(initiator).encrypt(b"x")
        )


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"key": b"short"}, "shared key"),
        ({"initiator_nonce": b"tiny"}, "initiator_nonce"),
        ({"responder_nonce": b"x" * 65}, "responder_nonce"),
        ({"mode": EncryptionMode.NONE}, "encrypted session mode"),
        ({"protocol": "other"}, "was not offered"),
        ({"offered_protocols": ()}, "offer is required"),
        ({"authentication_mode": AuthenticationMode.NONE}, "authenticated session"),
        ({"authentication_protocol": " "}, "authentication protocol"),
    ],
)
def test_an_invalid_context_is_refused(override: dict[str, object], message: str) -> None:
    pytest.importorskip("cryptography")
    initiator, _ = contexts(**override)
    with pytest.raises(ValueError, match=message):
        AesEncryptionProvider().create_cipher(initiator)


def test_address_bound_encryption_is_not_supported() -> None:
    pytest.importorskip("cryptography")
    initiator, _ = contexts(mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY_AND_ADDRESS)
    with pytest.raises(NotImplementedError):
        AesEncryptionProvider().create_cipher(initiator)
