# Esiur for Python

Python implementation of Esiur v3, a distributed resource framework for real-time
properties, asynchronous function invocation and events over the Esiur EP protocol.
It is a port of [esiur-ts](https://github.com/esiur/esiur-ts) and must stay wire-compatible with
[esiur-dotnet](https://github.com/esiur/esiur-dotnet).

> **Status: alpha (0.1.0).** The wire data layer, the packet framing, an anonymous
> connection over WebSocket and TCP, **remote resources** (attach, read properties, call functions,
> write properties, events), **hosting resources** (`Resource`, `Warehouse`, `EpServer`), and
> **authentication and encryption** (password login, AES-GCM records) exist and interoperate with
> esiur-ts in both directions.
>
> **Compatibility:** interoperability is tested against a real esiur-ts client and server (the
> esiur-ts tests in `tests/test_interop_*.py` run when Node and an esiur-ts checkout are available).
> It has **not** yet been verified against esiur-dotnet, so treat that pairing as untested.

## Port status

| Layer | Status |
| --- | --- |
| TDU framing, limits (`esiur.data.tdu`, `guard`) | Done |
| Dynamic values: ints, floats, str, bytes, datetime, UUID, Decimal128, Int128/UInt128, list, map, `TypeContinuation` | Done, byte-identical to esiur-ts |
| Tru, Gvwie integer arrays, typed lists/maps/tuples (`TypedList`, `TypedMap`, `TypedTuple`, `t`) | Done, byte-identical to esiur-ts |
| TypeDefs: indexed structures, `TypeDefInfo` and member infos, signatures (`name64`), records, enums, `TypeRegistry` | Done, byte-identical to esiur-ts (resource-kind values and remote TypeDefs wait for the resource layer) |
| EP packets: `EpPacket`, `EpAuthPacket` and their enums (`esiur.net.packets`) | Done; parsing and composing match esiur-ts on every header byte and every truncation |
| `EpConnection` core: anonymous handshake (initiator and responder), request/reply correlation, progress/warning/chunk replies, notifications, limits exchange, close handling | Done, interoperates with esiur-ts over WebSocket; attach, subscribe, streaming, reconnect, keep-alive wait for the resource layer |
| Remote resources (client): `EpResource` proxies, `attach`/`get`, TypeDef fetching, property snapshots and notifications, calls, property writes, ref-counted event subscriptions, resource references (including cycles) | Done, tested against a real esiur-ts server. Not yet: streaming functions, historical event replay, reattach/reconnect, SyncTypeDefs, record/enum values from a peer's TypeDefs |
| Local resources: `Resource`, `Property`/`Event`/`@function` declarations, `Instance`, `Warehouse`, `MemoryStore`, TypeDefs built from classes, permissions managers | Done. Not yet: historical members and the journal, streaming functions, per-instance managers, rate-control and auditing managers, persistent stores, store children/parents |
| Server-side request handlers: attach, detach, link lookup, TypeDef by id / by resource, invoke, static call, set property, subscribe, unsubscribe | Done, a real esiur-ts client drives a Python server. Answered `NotImplemented`: reattach, SyncTypeDefs, TypeDefIdsByNames, query, link TypeDefs, create/delete/move resource, stream control, journal query |
| Transports: WebSocket (`pip install esiur[websockets]`) and TCP | Done, client and server. HTTP long-poll not started |
| Server: `EpServer` (WebSocket and TCP listeners) | Done. No connection-admission limits yet. `EpHttpHandler` (ASGI) not started |
| Authentication: `password-sha3-v1` in all three modes (initiator, responder, dual identity), providers, sessions seen by permissions managers | Done, both directions against esiur-ts. Only the password protocol exists; others plug in as `AuthenticationProvider`s |
| Encryption: `aes-gcm` (AES-256-GCM records, HKDF-SHA256 keys), negotiated in the handshake (`pip install esiur[crypto]`) | Done, both directions against esiur-ts. Not yet: address-bound mode (`EncryptWithSessionKeyAndAddress`; esiur-ts cannot run it either) |

The plan follows the order esiur-ts was built in, so each layer can be checked against
it before the next is added.

## Python mapping

| Python | Wire |
| --- | --- |
| `None`, `bool` | Null, True/False |
| `int` | narrowest of Int8/16/32/64 (UInt64 above 2**63) |
| `float` | Int8/16/32 when whole, else Float32 when exact, else Float64; NaN/inf is one token |
| `str`, `bytes` | String (UTF-8), RawData |
| `datetime` | DateTime (naive values are taken as UTC; 100 ns ticks round to microseconds) |
| `uuid.UUID`, `decimal.Decimal` | UUID, Decimal128 (96-bit mantissa, scale 0 to 28) |
| `list`/`tuple`, `dict` | List, Map |
| `Int8`, `UInt32`, `Float32`, `Int128`, ... | pin a specific width |
| `TypedList(t.i32, [...])`, `TypedMap(t.string, t.f64, {...})`, `TypedTuple([t.i32, t.string], (...))` | Typed list / map / tuple; decode back to `list` / `dict` / `tuple` |
| `t.list(t.i32)`, `t.nullable(t.string)`, ... (a `Tru`) | TRU value |
| `TypeDefInfo`, `PropertyDefInfo`, ... or any `IndexedStructure` dataclass | TypeDef (0x81) / sparse `TypedMap<UInt8, dynamic>`; decode back to the dataclass (`TypeDefInfo`) or a `dict` |
| dataclass registered with `TypeRegistry.register_record`, `Enum` registered with `register_enum` | Typed value with a `TruTypeDef`; pass `types=registry` to `compose` and `parse` |

## Development

```bash
python -m venv .venv
.venv/Scripts/python -m pip install pytest pytest-asyncio ruff mypy websockets cryptography   # Windows; use .venv/bin on Linux/macOS
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check src tests
.venv/Scripts/python -m mypy
```

`tests/fixtures/ts-vectors.json` holds bytes produced by the real esiur-ts encoder.
Regenerate it after building esiur-ts with `node tools/gen-ts-vectors.mjs ../esiur-ts`.
`tests/fixtures/ts-typedef-vectors.json` (TypeDefs, records, enums, signatures) is built from the esiur-ts
source instead, with `node tools/gen-typedef-vectors.mjs ../esiur-ts`.
`tests/fixtures/ts-packet-vectors.json` (packet composing, all 256 header bytes, every truncated prefix)
comes from the esiur-ts build, with `node tools/gen-packet-vectors.mjs ../esiur-ts`.

## Connecting

```python
from esiur.net import EpConnection
from esiur.net.packets import EpPacketRequest

async with await EpConnection.connect("ws://127.0.0.1:51018") as connection:
    resource_id = await connection.send_request(EpPacketRequest.GET_RESOURCE_ID_BY_LINK, "sys/greeter")
```

Or work with the resource itself:

```python
greeter = await connection.get("sys/greeter")        # attach: fetches the type and the values
print(greeter.visits)                                # cached, kept fresh by the peer's notifications
print(await greeter.greet("Ahmed"))                  # a remote call (`say_hi` finds `sayHi`)
await greeter.set("label", "hello")                  # a remote write
greeter.on_property("visits", print)                 # property listeners are synchronous
await greeter.on_event("ping", print)                # subscribes on the first listener
```

Resource references in results, properties and notifications become `EpResource` proxies; a
reference back to a resource being attached resolves to that proxy. Listeners may be plain functions
or coroutine functions, and one that raises is logged without affecting the others.

`send_request` sends at once and returns a future, so requests can be pipelined with `asyncio.gather`.
A failed request raises `esiur.core.AsyncException` (its `type` and `code` are what the peer sent).
`tcp://`, `ws://`, `wss://`, `ep://` and `eps://` endpoints are accepted; a missing port means 51018.

`tests/test_interop_ts.py` starts a real esiur-ts `EpServer` (`tools/ts-test-server.mjs`) and talks to it;
it is skipped without Node and an esiur-ts checkout (`ESIUR_TS_PATH`, default `../esiur-ts`).

## Hosting resources

```python
import asyncio
from esiur.data import t
from esiur.net import EpServer
from esiur.resource import Event, MemoryStore, Property, Resource, Warehouse, function
from esiur.security import AllowAll


class Greeter(Resource):
    visits = Property(t.i32, default=0)                 # peers are told when it changes
    serial = Property(t.string, default="S-1", read_only=True)
    ping = Event(t.string)                              # peers subscribe to it
    tick = Event(t.string, auto_delivered=True)         # pushed to every attached peer

    @function(t.string, [t.string])                     # a method (sync or async) peers can call
    def greet(self, name):
        self.visits += 1
        self.ping.emit(f"greeted {name}")
        return f"Hi {name}"


async def main():
    warehouse = Warehouse()
    warehouse.register_permissions(AllowAll())          # without a manager, peers cannot write
    await warehouse.put("sys", MemoryStore())           # a store, then resources into it
    await warehouse.put("sys/greeter", Greeter())
    await warehouse.open()
    server = await EpServer.listen(warehouse, port=51018)   # transport="tcp" for raw TCP
    await asyncio.Event().wait()

asyncio.run(main())
```

Members are indexed in declaration order (base classes first), and peers address them by index, so
reorder or remove them only together with their clients. Python names are exported as written
(`fire_ping`); `name="firePing"` on `Property`, `Event` or `@function` exports a different one. The
declared types describe the members to peers; values are written the way esiur-ts writes them
(integers in the narrowest width). A peer's call that raises answers with an `Exception` error
(`RuntimeError: boom`), and one the permissions managers deny with `AccessDenied`. By default a
peer may attach, read and call but not write; register a `PermissionsManager` (or `AllowAll`) to
decide otherwise.

## Authentication and encryption

By default a connection is anonymous. To log in, give the client a provider and the identity to
prove; to encrypt, add the mode (everything after the handshake then travels as AES-GCM records):

```python
from esiur.security import (AuthenticationMode, EncryptionMode, StaticPasswordProvider,
                            AesEncryptionProvider)

provider = StaticPasswordProvider(credentials={"alice": "wonderland"}, identity="alice")
connection = await EpConnection.connect(
    "ws://server:51018",
    authentication_mode=AuthenticationMode.INITIALIZER_IDENTITY,   # or RESPONDER_/DUAL_IDENTITY
    encryption_mode=EncryptionMode.ENCRYPT_WITH_SESSION_KEY,       # optional; needs esiur[crypto]
    authentication_provider=provider,
    identity="alice",
)
```

A server hosts accounts (only salted SHA3 hashes are kept) and decides who may connect:

```python
accounts = StaticPasswordProvider(
    accounts={"alice": "wonderland"},                              # who may log in
    credentials={"server": "srv-secret"}, identity="server",       # how it proves itself
)
server = await EpServer.listen(
    warehouse, port=51018,
    allow_unauthorized=False,                                      # refuse anonymous peers
    authentication_provider=accounts,
    encryption_providers=[AesEncryptionProvider()],
)
```

`RESPONDER_IDENTITY` makes the *server* prove its identity to the client (which needs the server's
account to check it), and `DUAL_IDENTITY` both. Subclass `PasswordAuthenticationProvider` to look
accounts up elsewhere (`get_hosted_account_credential`, `get_self_credential`,
`get_self_identity_and_credential`), and `AuthenticationProvider` for another protocol. A finished
session is `connection.session` (identities, key, the peer's headers); `local_identity`,
`remote_identity` and `session_key` are shortcuts, and permissions managers receive the session as
their second argument, so rules can depend on who is asking.

The session identities are from each side's own point of view: `remote_identity` is what the
*peer* proved. (esiur-ts reports the initiator's identity as the responder's `localIdentity`.)
Encryption needs a session key, so it requires authentication; a server rejects an offer it has no
matching provider for. Logging in over an unencrypted connection sends the nonces and challenges
in the clear, so use encryption (or `wss://`) on an untrusted network.

`tests/test_hosting_net.py` runs a Python client against a Python server, and
`tests/test_interop_ts_client.py` runs a real esiur-ts client (`tools/ts-test-client.mjs`) against one.
`tests/test_interop_security.py` repeats the authentication modes, with and without encryption, in both
directions against esiur-ts, and `tests/test_secure_sessions.py` checks with a recording relay that an
encrypted session shows nothing readable on the wire.
