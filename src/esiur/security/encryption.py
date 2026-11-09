"""Transport encryption (port of esiur-ts ``security/cryptography``).

Once the handshake has authenticated the peers and left them with a shared session key, the rest
of the connection travels as encrypted *records*: ``[4-byte big-endian length][protected record]``.
An :class:`EncryptionProvider` (registered under the name peers negotiate it by) turns the
handshake's result into a :class:`SymmetricCipher`.

The one cipher is ``aes-gcm`` (:class:`AesEncryptionProvider`), AES-256-GCM with per-direction
keys derived by HKDF-SHA256. It needs the ``cryptography`` package: ``pip install esiur[crypto]``.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from .authentication import AuthenticationDirection
from .modes import AuthenticationMode, EncryptionMode


@dataclass(frozen=True, slots=True)
class EncryptionContext:
    """What the handshake settled on, from which a cipher is created. Initiator and responder
    values keep their protocol roles whichever peer creates the cipher."""

    #: The shared secret the authentication protocol derived.
    key: bytes
    #: The role of the peer creating the cipher.
    direction: AuthenticationDirection
    mode: EncryptionMode
    #: The negotiated encryption protocol name.
    protocol: str
    #: The protocols the initiator offered, in wire order.
    offered_protocols: tuple[str, ...]
    authentication_mode: AuthenticationMode
    authentication_protocol: str
    domain: str | None
    initiator_nonce: bytes
    responder_nonce: bytes


class SymmetricCipher:
    """A per-session record cipher. It keeps the record sequence, so it protects exactly one
    connection and one direction pair."""

    identifier: int = 0

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, data: bytes) -> bytes:
        """Authenticate and decrypt a record; raises ``ValueError`` if it is invalid."""
        raise NotImplementedError


class EncryptionProvider:
    """Creates the cipher of a session."""

    #: The name peers negotiate the provider by.
    default_name: str = ""
    #: The most bytes :meth:`SymmetricCipher.encrypt` adds to one record.
    maximum_record_overhead: int = 0

    def create_cipher(self, context: EncryptionContext) -> SymmetricCipher:
        raise NotImplementedError


# ---- AES-256-GCM ---------------------------------------------------------------------------

_KEY_SIZE = 32
_NONCE_PREFIX_SIZE = 4
_SEQUENCE_SIZE = 8
_TAG_SIZE = 16
_RECORD_OVERHEAD = _SEQUENCE_SIZE + _TAG_SIZE
_MIN_SHARED_KEY = 16
_MAX_SHARED_KEY = 1024
_MIN_PEER_NONCE = 16
_MAX_PEER_NONCE = 64
_MAX_SEQUENCE = 0xFFFF_FFFF_FFFF_FFFF

_CONTEXT_LABEL = b"esiur/ep/aes-256-gcm/context/v3"
_I2R = "initiator-to-responder"
_R2I = "responder-to-initiator"


def _label(direction: str, purpose: str) -> bytes:
    return f"esiur/ep/aes-256-gcm/v1/{direction}/{purpose}".encode()


def hkdf_sha256(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) with SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF cannot produce that much output.")
    pseudo_random_key = hmac.new(salt, key, hashlib.sha256).digest()
    output, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.new(pseudo_random_key, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
    return output[:length]


class AesGcmCipher(SymmetricCipher):
    """AES-256-GCM records: ``[8-byte big-endian sequence][ciphertext][16-byte tag]``.

    The record length and the sequence are authenticated as associated data, and the sequence
    is both implicit state and an explicit field, so a replayed, dropped or reordered record
    fails closed. The key is immutable: reusing it would reuse the nonce sequence."""

    identifier = 0

    def __init__(self, context: EncryptionContext) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "AES-GCM encryption needs the 'cryptography' package: pip install esiur[crypto]"
            ) from None
        _validate(context)
        initiator = context.direction == AuthenticationDirection.INITIATOR
        send, receive = (_I2R, _R2I) if initiator else (_R2I, _I2R)
        salt = _context_salt(context)
        key = context.key
        self._send = AESGCM(hkdf_sha256(key, salt, _label(send, "key"), _KEY_SIZE))
        self._receive = AESGCM(hkdf_sha256(key, salt, _label(receive, "key"), _KEY_SIZE))
        self._send_prefix = hkdf_sha256(key, salt, _label(send, "nonce"), _NONCE_PREFIX_SIZE)
        self._receive_prefix = hkdf_sha256(key, salt, _label(receive, "nonce"), _NONCE_PREFIX_SIZE)
        self._send_sequence = 0
        self._receive_sequence = 0

    def encrypt(self, data: bytes) -> bytes:
        if self._send_sequence == _MAX_SEQUENCE:
            raise ValueError("The AES-GCM send sequence is exhausted.")
        sequence = self._send_sequence
        header = struct.pack(">Q", sequence)
        protected = self._send.encrypt(
            self._send_prefix + header, bytes(data), _aad(len(data) + _RECORD_OVERHEAD, sequence)
        )
        self._send_sequence += 1
        return header + protected

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < _RECORD_OVERHEAD:
            raise ValueError("The AES-GCM record is truncated.")
        (sequence,) = struct.unpack(">Q", data[:_SEQUENCE_SIZE])
        if sequence != self._receive_sequence:
            raise ValueError("The AES-GCM record sequence is invalid.")
        if self._receive_sequence == _MAX_SEQUENCE:
            raise ValueError("The AES-GCM receive sequence is exhausted.")
        try:
            plaintext = self._receive.decrypt(
                self._receive_prefix + data[:_SEQUENCE_SIZE],
                bytes(data[_SEQUENCE_SIZE:]),
                _aad(len(data), sequence),
            )
        except Exception as error:
            raise ValueError("AES-GCM record authentication failed.") from error
        self._receive_sequence += 1
        return plaintext


class AesEncryptionProvider(EncryptionProvider):
    """Creates AES-256-GCM record ciphers, negotiated as ``aes-gcm``."""

    NAME = "aes-gcm"
    default_name = NAME
    maximum_record_overhead = _RECORD_OVERHEAD

    def create_cipher(self, context: EncryptionContext) -> SymmetricCipher:
        return AesGcmCipher(context)


def _aad(record_length: int, sequence: int) -> bytes:
    return struct.pack(">IQ", record_length, sequence)


def _length_prefixed(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _context_salt(context: EncryptionContext) -> bytes:
    """SHA-256 over an ordered, length-prefixed transcript of every negotiated field."""
    parts = [
        _CONTEXT_LABEL,
        bytes([int(context.authentication_mode) & 0xFF]),
        _length_prefixed(context.authentication_protocol.encode()),
        _length_prefixed((context.domain or "").encode()),
        bytes([int(context.mode) & 0xFF]),
        struct.pack(">I", len(context.offered_protocols)),
        *(_length_prefixed(offered.encode()) for offered in context.offered_protocols),
        _length_prefixed(context.protocol.encode()),
        _length_prefixed(context.initiator_nonce),
        _length_prefixed(context.responder_nonce),
    ]
    return hashlib.sha256(b"".join(parts)).digest()


def _validate(context: EncryptionContext) -> None:
    if not _MIN_SHARED_KEY <= len(context.key) <= _MAX_SHARED_KEY:
        raise ValueError(
            f"The shared key must contain between {_MIN_SHARED_KEY} and {_MAX_SHARED_KEY} bytes."
        )
    for name, nonce in (
        ("initiator_nonce", context.initiator_nonce),
        ("responder_nonce", context.responder_nonce),
    ):
        if not _MIN_PEER_NONCE <= len(nonce) <= _MAX_PEER_NONCE:
            raise ValueError(
                f"{name} must contain between {_MIN_PEER_NONCE} and {_MAX_PEER_NONCE} bytes."
            )
    if context.mode == EncryptionMode.NONE:
        raise ValueError("AES-GCM requires an encrypted session mode.")
    if context.mode != EncryptionMode.ENCRYPT_WITH_SESSION_KEY:
        raise NotImplementedError("Address-bound encryption is not supported.")
    if not context.protocol.strip():
        raise ValueError("A negotiated encryption protocol is required.")
    if not context.offered_protocols or any(not p.strip() for p in context.offered_protocols):
        raise ValueError("The initiator's encryption offer is required.")
    if context.protocol not in context.offered_protocols:
        raise ValueError("The selected encryption protocol was not offered.")
    if context.authentication_mode == AuthenticationMode.NONE:
        raise ValueError("AES-GCM requires an authenticated session.")
    if not context.authentication_protocol.strip():
        raise ValueError("A negotiated authentication protocol is required.")


def available() -> bool:
    """Whether AES-GCM can be used (the ``cryptography`` package is installed)."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True

