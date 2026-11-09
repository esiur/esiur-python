"""The ``password-sha3-v1`` authentication protocol (port of esiur-ts
``security/providers/PasswordAuthentication*``).

A challenge-response exchange over SHA3: each side contributes a 20-byte nonce, the account's
salted password hash never travels, and both end up with the same 64-byte session key. The
hosting side keeps only salted hashes (see :meth:`PasswordAuthenticationProvider.create_credential`);
the proving side needs the raw password.

Subclass :class:`PasswordAuthenticationProvider` and override what your node plays:

* to *host accounts* (be the one a peer logs in to): :meth:`get_hosted_account_credential`;
* to *prove an identity* (log in to a peer, or prove the responder's own identity):
  :meth:`get_self_identity_and_credential` and :meth:`get_self_credential`.

:class:`StaticPasswordProvider` does both from dictionaries.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .authentication import (
    AuthenticationContext,
    AuthenticationDirection,
    AuthenticationHandler,
    AuthenticationProvider,
    AuthenticationResult,
    AuthenticationRuling,
)
from .modes import AuthenticationMode

PROTOCOL = "password-sha3-v1"
NONCE_LENGTH = 20
SALT_LENGTH = 32


def sha3(data: bytes, bit_length: int = 256) -> bytes:
    """SHA3 (FIPS 202), the same function as esiur-ts' ``sha3`` and .NET's SHA3."""
    if bit_length not in (224, 256, 384, 512):
        raise ValueError("SHA3 bit length must be 224, 256, 384, or 512.")
    return hashlib.new(f"sha3_{bit_length}", data).digest()


@dataclass(frozen=True, slots=True)
class PasswordHash:
    """A stored, salted password hash: ``hash = SHA3-256(password + salt)``."""

    hash: bytes | None = None
    salt: bytes | None = None


@dataclass(frozen=True, slots=True)
class IdentityPassword:
    """An identity and its raw password, as a node proves its own identity."""

    identity: str | None = None
    password: bytes | None = None


class PasswordAuthenticationProvider(AuthenticationProvider):
    """Base provider of the password protocol. Override the ``get_*`` methods for the roles
    this node plays; the defaults know no accounts."""

    default_name = PROTOCOL

    @staticmethod
    def create_credential(password: bytes | str) -> PasswordHash:
        """Derive a storable, salted hash from a password (a fresh random salt each time)."""
        raw = _password_bytes(password)
        if not raw:
            raise ValueError("A password cannot be empty.")
        salt = secrets.token_bytes(SALT_LENGTH)
        return PasswordHash(sha3(raw + salt), salt)

    def create_handler(self, context: AuthenticationContext) -> AuthenticationHandler:
        return PasswordAuthenticationHandler(
            context.mode,
            context.direction,
            context.initiator_identity,
            context.responder_identity,
            context.host_name,
            context.domain,
            self,
        )

    def get_hosted_account_credential(self, identity: str, domain: str | None) -> PasswordHash:
        """The stored hash and salt of the account ``identity`` this node hosts; an empty
        :class:`PasswordHash` if there is no such account."""
        return PasswordHash()

    def get_self_identity_and_credential(
        self, domain: str | None, host_name: str | None
    ) -> IdentityPassword:
        """The identity and password this node proves when none was named."""
        return IdentityPassword()

    def get_self_credential(
        self, identity: str, domain: str | None, host_name: str | None
    ) -> bytes | None:
        """The raw password with which this node proves ``identity``, if it knows it."""
        return None


class StaticPasswordProvider(PasswordAuthenticationProvider):
    """A provider backed by dictionaries.

    ``accounts`` maps identity to password for the accounts this node *hosts* (only salted
    hashes are kept). ``credentials`` maps identity to password for the identities this node
    can *prove*; ``identity`` names the one used when none was asked for.
    """

    def __init__(
        self,
        accounts: Mapping[str, bytes | str] | None = None,
        *,
        credentials: Mapping[str, bytes | str] | None = None,
        identity: str | None = None,
    ) -> None:
        self._hosted = {
            name: self.create_credential(password) for name, password in (accounts or {}).items()
        }
        self._credentials = {
            name: _password_bytes(password) for name, password in (credentials or {}).items()
        }
        self._identity = identity
        if identity is not None and identity not in self._credentials:
            raise ValueError(f"No credential is known for the identity '{identity}'.")

    def get_hosted_account_credential(self, identity: str, domain: str | None) -> PasswordHash:
        return self._hosted.get(identity, PasswordHash())

    def get_self_identity_and_credential(
        self, domain: str | None, host_name: str | None
    ) -> IdentityPassword:
        if self._identity is None:
            return IdentityPassword()
        return IdentityPassword(self._identity, self._credentials[self._identity])

    def get_self_credential(
        self, identity: str, domain: str | None, host_name: str | None
    ) -> bytes | None:
        return self._credentials.get(identity)


class PasswordAuthenticationHandler(AuthenticationHandler):
    """One connection's side of the password exchange.

    A successful result names the identities from this side's point of view: ``local_identity``
    is the one this side proved (``None`` if it proved none) and ``remote_identity`` the one the
    peer proved. (esiur-ts reports the initiator's identity as the responder's *local* one.)"""

    protocol = PROTOCOL

    def __init__(
        self,
        mode: AuthenticationMode,
        direction: AuthenticationDirection,
        initiator_identity: str | None,
        responder_identity: str | None,
        host_name: str | None,
        domain: str | None,
        provider: PasswordAuthenticationProvider,
    ) -> None:
        self.provider = provider
        self._mode = mode
        self._direction = direction
        self._initiator_identity = initiator_identity
        self._responder_identity = responder_identity
        self._host_name = host_name
        self._domain = domain
        self._local_nonce = secrets.token_bytes(NONCE_LENGTH)
        self._remote_nonce: bytes | None = None
        self._local_salt: bytes | None = None
        self._remote_salt: bytes | None = None
        self._initiator_password: bytes | None = None
        self._responder_password: bytes | None = None
        self._step = 0

    # ---- dispatch -------------------------------------------------------------------------

    def process(self, authentication_data: Any) -> AuthenticationResult:
        try:
            remote = _as_list(authentication_data)
            steps = _STEPS.get((self._direction, self._mode))
            if steps is None:
                return self._stop()
            return steps(self, remote)
        except Exception:  # noqa: BLE001 - whatever the peer sent, the answer is a failure
            self._step = -1
            return _FAILED

    def _stop(self) -> AuthenticationResult:
        self._step = -1
        return _FAILED

    # ---- initiator ------------------------------------------------------------------------

    def _initiator_initializer(self, remote: list[Any] | None) -> AuthenticationResult:
        if self._step == 0:
            if not self._load_initiator_self():
                return _FAILED
            self._step = 1
            return _in_progress([self._local_nonce, self._initiator_identity])
        if self._step != 1 or remote is None or len(remote) < 3:
            return _FAILED

        self._remote_nonce = _as_bytes(remote[0])
        self._remote_salt = _as_bytes(remote[1])
        remote_challenge = _as_bytes(remote[2])
        if not self._valid_remote_nonce() or not self._remote_salt or not remote_challenge:
            return self._stop()

        assert self._initiator_password is not None and self._remote_nonce is not None
        hashed = sha3(self._initiator_password + self._remote_salt)
        expected = sha3(self._remote_nonce + hashed + self._local_nonce)
        if not hmac.compare_digest(remote_challenge, expected):
            return self._stop()

        local_challenge = sha3(self._local_nonce + hashed + self._remote_nonce)
        assert self._initiator_identity is not None
        key = sha3(
            _utf8(self._initiator_identity) + hashed + self._local_nonce + self._remote_nonce, 512
        )
        self._step = -1
        return _succeeded([local_challenge], self._initiator_identity, None, key)

    def _initiator_responder(self, remote: list[Any] | None) -> AuthenticationResult:
        if self._step == 0:
            self._step = 1
            return _in_progress([self._local_nonce])
        if self._step == 1:
            if remote is None or len(remote) < 2:
                return _FAILED
            self._remote_nonce = _as_bytes(remote[0])
            self._responder_identity = _as_str(remote[1])
            if not self._valid_remote_nonce() or not self._responder_identity:
                return self._stop()
            credential = self.provider.get_hosted_account_credential(
                self._responder_identity, self._domain
            )
            self._local_salt, self._responder_password = credential.salt, credential.hash
            if not self._local_salt or not self._responder_password:
                return self._stop()
            assert self._remote_nonce is not None
            challenge = sha3(self._local_nonce + self._responder_password + self._remote_nonce)
            self._step = 2
            return _in_progress([self._local_salt, challenge])
        if self._step != 2 or remote is None or len(remote) < 1:
            return _FAILED

        remote_challenge = _as_bytes(remote[0])
        if not remote_challenge or not self._remote_nonce or not self._responder_password:
            return self._stop()
        expected = sha3(self._remote_nonce + self._responder_password + self._local_nonce)
        if not hmac.compare_digest(remote_challenge, expected):
            return self._stop()
        assert self._responder_identity is not None
        key = sha3(
            _utf8(self._responder_identity)
            + self._responder_password
            + self._local_nonce
            + self._remote_nonce,
            512,
        )
        self._step = -1
        return _succeeded(None, self._initiator_identity, self._responder_identity, key)

    def _initiator_dual(self, remote: list[Any] | None) -> AuthenticationResult:
        if self._step == 0:
            if not self._load_initiator_self():
                return _FAILED
            self._step = 1
            return _in_progress([self._local_nonce, self._initiator_identity])
        if self._step == 1:
            if remote is None or len(remote) < 3:
                return _FAILED
            self._remote_nonce = _as_bytes(remote[0])
            responder_identity, salt = _dual_responder_step(remote)
            self._responder_identity, self._remote_salt = responder_identity, salt
            if not self._valid_remote_nonce() or not responder_identity or not salt:
                return self._stop()
            credential = self.provider.get_hosted_account_credential(
                responder_identity, self._domain
            )
            self._local_salt, self._responder_password = credential.salt, credential.hash
            if not self._local_salt or not self._responder_password:
                return self._stop()
            assert self._initiator_password is not None and self._remote_nonce is not None
            hashed = sha3(self._initiator_password + salt)
            challenge = sha3(
                self._local_nonce + hashed + self._responder_password + self._remote_nonce
            )
            self._step = 2
            return _in_progress([self._local_salt, challenge])
        if self._step != 2 or remote is None or len(remote) < 1:
            return _FAILED

        remote_challenge = _as_bytes(remote[0])
        if (
            not remote_challenge
            or not self._remote_nonce
            or not self._remote_salt
            or not self._responder_password
            or self._initiator_password is None
        ):
            return self._stop()
        hashed = sha3(self._initiator_password + self._remote_salt)
        expected = sha3(self._remote_nonce + self._responder_password + hashed + self._local_nonce)
        if not hmac.compare_digest(remote_challenge, expected):
            return self._stop()
        assert self._initiator_identity is not None and self._responder_identity is not None
        key = sha3(
            _utf8(self._initiator_identity)
            + _utf8(self._responder_identity)
            + hashed
            + self._responder_password
            + self._local_nonce
            + self._remote_nonce,
            512,
        )
        self._step = -1
        return _succeeded(None, self._initiator_identity, self._responder_identity, key)

    # ---- responder ------------------------------------------------------------------------

    def _responder_initializer(self, remote: list[Any] | None) -> AuthenticationResult:
        if self._step == 0:
            if remote is None or len(remote) < 2:
                return _FAILED
            self._remote_nonce = _as_bytes(remote[0])
            self._initiator_identity = _as_str(remote[1])
            if not self._valid_remote_nonce() or not self._initiator_identity:
                return self._stop()
            credential = self.provider.get_hosted_account_credential(
                self._initiator_identity, self._domain
            )
            self._local_salt, self._initiator_password = credential.salt, credential.hash
            if not self._local_salt or not self._initiator_password:
                return _FAILED
            assert self._remote_nonce is not None
            challenge = sha3(self._local_nonce + self._initiator_password + self._remote_nonce)
            self._step = 1
            return _in_progress([self._local_nonce, self._local_salt, challenge])
        if self._step != 1 or remote is None or len(remote) < 1:
            return _FAILED

        remote_challenge = _as_bytes(remote[0])
        if not remote_challenge or not self._remote_nonce or not self._initiator_password:
            return self._stop()
        expected = sha3(self._remote_nonce + self._initiator_password + self._local_nonce)
        if not hmac.compare_digest(expected, remote_challenge):
            return self._stop()
        assert self._initiator_identity is not None
        key = sha3(
            _utf8(self._initiator_identity)
            + self._initiator_password
            + self._remote_nonce
            + self._local_nonce,
            512,
        )
        self._step = -1
        return _succeeded(None, self._responder_identity, self._initiator_identity, key)

    def _responder_responder(self, remote: list[Any] | None) -> AuthenticationResult:
        if self._step == 0:
            if remote is None or len(remote) < 1:
                return _FAILED
            self._remote_nonce = _as_bytes(remote[0])
            if not self._valid_remote_nonce():
                return self._stop()
            if not self._load_responder_self():
                return _FAILED
            self._step = 1
            return _in_progress([self._local_nonce, self._responder_identity])
        if self._step != 1 or remote is None or len(remote) < 2:
            return _FAILED

        self._remote_salt = _as_bytes(remote[0])
        remote_challenge = _as_bytes(remote[1])
        if (
            not self._remote_salt
            or not remote_challenge
            or not self._remote_nonce
            or not self._responder_password
        ):
            return self._stop()
        hashed = sha3(self._responder_password + self._remote_salt)
        expected = sha3(self._remote_nonce + hashed + self._local_nonce)
        if not hmac.compare_digest(expected, remote_challenge):
            return self._stop()
        local_challenge = sha3(self._local_nonce + hashed + self._remote_nonce)
        assert self._responder_identity is not None
        key = sha3(
            _utf8(self._responder_identity) + hashed + self._remote_nonce + self._local_nonce, 512
        )
        self._step = -1
        return _succeeded([local_challenge], self._responder_identity, None, key)

    def _responder_dual(self, remote: list[Any] | None) -> AuthenticationResult:
        if self._step == 0:
            if remote is None or len(remote) < 2:
                return _FAILED
            self._remote_nonce = _as_bytes(remote[0])
            self._initiator_identity = _as_str(remote[1])
            if not self._valid_remote_nonce() or not self._initiator_identity:
                return self._stop()
            if not self._load_responder_self():
                return _FAILED
            credential = self.provider.get_hosted_account_credential(
                self._initiator_identity, self._domain
            )
            self._local_salt, self._initiator_password = credential.salt, credential.hash
            if not self._local_salt or not self._initiator_password:
                return _FAILED
            self._step = 1
            return _in_progress([self._local_nonce, self._responder_identity, self._local_salt])
        if self._step != 1 or remote is None or len(remote) < 2:
            return _FAILED

        remote_salt = _as_bytes(remote[0])
        remote_challenge = _as_bytes(remote[1])
        if (
            not remote_salt
            or not remote_challenge
            or not self._remote_nonce
            or not self._initiator_password
            or self._responder_password is None
        ):
            return self._stop()
        hashed = sha3(self._responder_password + remote_salt)
        expected = sha3(self._remote_nonce + self._initiator_password + hashed + self._local_nonce)
        if not hmac.compare_digest(expected, remote_challenge):
            return self._stop()
        local_challenge = sha3(
            self._local_nonce + hashed + self._initiator_password + self._remote_nonce
        )
        assert self._initiator_identity is not None and self._responder_identity is not None
        key = sha3(
            _utf8(self._initiator_identity)
            + _utf8(self._responder_identity)
            + self._initiator_password
            + hashed
            + self._remote_nonce
            + self._local_nonce,
            512,
        )
        self._step = -1
        return _succeeded(
            [local_challenge], self._responder_identity, self._initiator_identity, key
        )

    # ---- helpers --------------------------------------------------------------------------

    def _load_initiator_self(self) -> bool:
        if self._initiator_identity is None:
            found = self.provider.get_self_identity_and_credential(self._domain, self._host_name)
            self._initiator_identity, self._initiator_password = found.identity, found.password
        else:
            self._initiator_password = self.provider.get_self_credential(
                self._initiator_identity, self._domain, self._host_name
            )
        return self._initiator_identity is not None and self._initiator_password is not None

    def _load_responder_self(self) -> bool:
        if self._responder_identity is None:
            found = self.provider.get_self_identity_and_credential(self._domain, self._host_name)
            self._responder_identity, self._responder_password = found.identity, found.password
        else:
            self._responder_password = self.provider.get_self_credential(
                self._responder_identity, self._domain, self._host_name
            )
        return self._responder_identity is not None and self._responder_password is not None

    def _valid_remote_nonce(self) -> bool:
        nonce = self._remote_nonce
        return (
            nonce is not None
            and len(nonce) == NONCE_LENGTH
            and not hmac.compare_digest(nonce, self._local_nonce)
        )


_STEPS = {
    (AuthenticationDirection.INITIATOR, AuthenticationMode.INITIALIZER_IDENTITY): (
        PasswordAuthenticationHandler._initiator_initializer
    ),
    (AuthenticationDirection.INITIATOR, AuthenticationMode.RESPONDER_IDENTITY): (
        PasswordAuthenticationHandler._initiator_responder
    ),
    (AuthenticationDirection.INITIATOR, AuthenticationMode.DUAL_IDENTITY): (
        PasswordAuthenticationHandler._initiator_dual
    ),
    (AuthenticationDirection.RESPONDER, AuthenticationMode.INITIALIZER_IDENTITY): (
        PasswordAuthenticationHandler._responder_initializer
    ),
    (AuthenticationDirection.RESPONDER, AuthenticationMode.RESPONDER_IDENTITY): (
        PasswordAuthenticationHandler._responder_responder
    ),
    (AuthenticationDirection.RESPONDER, AuthenticationMode.DUAL_IDENTITY): (
        PasswordAuthenticationHandler._responder_dual
    ),
}

_FAILED = AuthenticationResult(AuthenticationRuling.FAILED)


def _in_progress(data: list[Any]) -> AuthenticationResult:
    return AuthenticationResult(AuthenticationRuling.IN_PROGRESS, data)


def _succeeded(
    data: list[Any] | None,
    local_identity: str | None,
    remote_identity: str | None,
    session_key: bytes,
) -> AuthenticationResult:
    return AuthenticationResult(
        AuthenticationRuling.SUCCEEDED, data, local_identity, remote_identity, session_key
    )


def _as_list(value: Any) -> list[Any] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return value
    raise TypeError("Authentication data must be a list.")


def _as_bytes(value: Any) -> bytes | None:
    return bytes(value) if isinstance(value, bytes | bytearray) else None


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _password_bytes(password: bytes | str) -> bytes:
    return password.encode("utf-8") if isinstance(password, str) else bytes(password)


def _dual_responder_step(remote: list[Any]) -> tuple[str | None, bytes | None]:
    """The responder's step of the dual exchange: its identity and the salt, in either order
    (esiur-dotnet and esiur-ts differ in it)."""
    if isinstance(remote[1], str):
        return remote[1], _as_bytes(remote[2])
    if isinstance(remote[2], str):
        return remote[2], _as_bytes(remote[1])
    return None, None
