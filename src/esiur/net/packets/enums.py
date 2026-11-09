"""Packet header fields of the EP protocol (ports of the esiur-ts ``net/packets`` enums).

Every enum is an ``IntEnum``, so a raw header value compares equal to its member and an action
this version does not know about can still be carried as a plain ``int``.
"""

from __future__ import annotations

import enum


class EpPacketMethod(enum.IntEnum):
    """Top two bits of an EP packet header."""

    NOTIFICATION = 0
    REQUEST = 1
    REPLY = 2
    EXTENSION = 3


class EpPacketRequest(enum.IntEnum):
    """Request actions, in the low five bits of the header."""

    # Invoke
    INVOKE_FUNCTION = 0x0
    SET_PROPERTY = 0x1
    SUBSCRIBE = 0x2
    UNSUBSCRIBE = 0x3
    QUERY_RESOURCE_JOURNAL = 0x4
    # Inquire
    TYPEDEF_IDS_BY_NAMES = 0x8  # request: list of names, reply: list of ids
    TYPEDEF_BY_ID = 0x9
    TYPEDEF_BY_RESOURCE_ID = 0xA
    QUERY = 0xB
    LINK_TYPEDEFS = 0xC
    TOKEN = 0xD
    GET_RESOURCE_ID_BY_LINK = 0xE
    SYNC_TYPEDEFS = 0xF  # validate cached TypeDefs by name and signature
    # Manage
    ATTACH_RESOURCE = 0x10
    REATTACH_RESOURCE = 0x11
    DETACH_RESOURCE = 0x12
    CREATE_RESOURCE = 0x13
    DELETE_RESOURCE = 0x14
    MOVE_RESOURCE = 0x15
    # Static
    KEEP_ALIVE = 0x18
    PROCEDURE_CALL = 0x19
    STATIC_CALL = 0x1A
    INDIRECT_CALL = 0x1B
    PULL_STREAM = 0x1C
    TERMINATE_EXECUTION = 0x1D
    HALT_EXECUTION = 0x1E
    RESUME_EXECUTION = 0x1F


class EpPacketReply(enum.IntEnum):
    """Reply actions, in the low five bits of the header."""

    # Success
    COMPLETED = 0x0
    PROPAGATED = 0x1
    STREAM = 0x2
    # Error
    PERMISSION_ERROR = 0x4
    EXECUTION_ERROR = 0x5
    # Partial
    PROGRESS = 0x8
    CHUNK = 0x9
    WARNING = 0xA


class EpPacketNotification(enum.IntEnum):
    """Notification actions, in the low five bits of the header."""

    # Invoke
    PROPERTY_MODIFIED = 0x0
    EVENT_OCCURRED = 0x1
    # Manage
    RESOURCE_DESTROYED = 0x8
    RESOURCE_REASSIGNED = 0x9
    RESOURCE_MOVED = 0xA
    SYSTEM_FAILURE = 0xB


class EpAuthPacketCommand(enum.IntEnum):
    """Top two bits of an authentication packet header."""

    INITIALIZE = 0x0
    ACKNOWLEDGE = 0x1
    ACTION = 0x2
    EVENT = 0x3


class EpAuthPacketMethod(enum.IntEnum):
    """Authentication packet methods. The top two bits repeat the
    :class:`EpAuthPacketCommand`; for example ``SESSION_ESTABLISHED`` (0x47) is an acknowledge."""

    # Initialize
    INITIALIZE = 0x00
    # Actions
    HANDSHAKE = 0x80
    FINAL_HANDSHAKE = 0x81
    # Acknowledgements
    DENIED = 0x40
    NOT_SUPPORTED = 0x41
    TRY_SUPPORTED = 0x42
    RETRY = 0x43
    PROCEED_TO_HANDSHAKE = 0x44
    PROCEED_TO_FINAL_HANDSHAKE = 0x45
    PROCEED_TO_ESTABLISH_SESSION = 0x46
    SESSION_ESTABLISHED = 0x47
    # Events
    ESTABLISHED = 0xC0
    ERROR_TERMINATE = 0xC1
    ERROR_MUST_ENCRYPT = 0xC2
    ERROR_RETRY = 0xC3
    INDICATION_ESTABLISHED = 0xC8
    IAUTH_PLAIN = 0xD0
    IAUTH_HASHED = 0xD1
    IAUTH_ENCRYPTED = 0xD2


class EpAuthPacketHeader(enum.IntEnum):
    """Keys of the ``TypedMap<UInt8, dynamic>`` an authentication packet carries."""

    VERSION = 0
    DOMAIN = 1
    SUPPORTED_AUTHENTICATIONS = 2
    SUPPORTED_HASH_ALGORITHMS = 3
    SUPPORTED_CIPHERS = 4
    SUPPORTED_COMPRESSION = 5
    SUPPORTED_MULTI_FACTOR_AUTHENTICATIONS = 6
    CIPHER_TYPE = 7
    CIPHER_KEY = 8
    SOFTWARE_IDENTITY = 9
    REFERRER = 10
    TIME = 11
    IP_ADDRESS = 12
    IDENTITY = 13
    AUTHENTICATION_PROTOCOL = 14
    AUTHENTICATION_DATA = 15
    ERROR_MESSAGE = 16
    #: Fresh public nonce used with the authenticated session key to derive unique
    #: per-connection encryption keys.
    CIPHER_NONCE = 17
    #: Maximum declared TDU payload accepted by this peer.
    MAXIMUM_PACKET_SIZE = 18
    #: Maximum allocation produced by one decoded value at this peer.
    MAXIMUM_ALLOCATION_SIZE = 19
    #: Maximum number of decoded values in one collection at this peer.
    MAXIMUM_COLLECTION_ITEMS = 20
    #: Maximum recursive TRU metadata depth accepted by this peer.
    MAXIMUM_TYPE_METADATA_DEPTH = 21
    #: Maximum protected encryption-record size accepted by this peer.
    MAXIMUM_ENCRYPTED_RECORD_SIZE = 22
