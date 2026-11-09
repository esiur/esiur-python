"""Differential test: Python must compose exactly the bytes esiur-ts composes.

Regenerate the fixture with ``node tools/gen-ts-vectors.mjs ../esiur-ts``.
The ``python`` field of each vector is a trusted, repository-owned expression.
"""

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from esiur.data import (
    Char16,
    Float32,
    Int8,
    Int16,
    TypedList,
    TypedMap,
    TypedTuple,
    UInt8,
    UInt32,
    UInt64,
    compose,
    parse,
    t,
)

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "ts-vectors.json").read_text("utf-8"))
NAMESPACE: dict[str, Any] = {
    "Char16": Char16, "Float32": Float32, "Int8": Int8, "Int16": Int16, "UInt8": UInt8,
    "UInt32": UInt32, "UInt64": UInt64, "Decimal": Decimal, "UUID": UUID,
    "datetime": datetime, "timezone": timezone,
    "TypedList": TypedList, "TypedMap": TypedMap, "TypedTuple": TypedTuple, "t": t,
}


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_compose_matches_esiur_ts(vector: dict[str, str]) -> None:
    value = eval(vector["python"], {"__builtins__": {"bytes": bytes, "range": range}}, NAMESPACE)
    assert compose(value).hex() == vector["hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_ts_bytes_decode_to_a_stable_value(vector: dict[str, str]) -> None:
    # Width wrappers narrow on the wire (UInt8(200) comes back as 200), so compare values,
    # not bytes: decoding what we would re-send must give the same value again.
    decoded = parse(bytes.fromhex(vector["hex"]))
    # A decoded typed tuple is a ``tuple`` but a bare tuple composes as a List, so compare
    # tuples and lists alike.
    assert _lists(parse(compose(decoded))) == _lists(decoded)


def _plain(value: Any) -> Any:
    """What a typed value should decode to."""
    if isinstance(value, TypedList):
        return [_plain(v) for v in value.values]
    if isinstance(value, TypedMap):
        return {_plain(k): _plain(v) for k, v in value.entries}
    if isinstance(value, TypedTuple):
        return [_plain(v) for v in value.values]
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


TYPED = [v for v in VECTORS if v["name"].startswith(("typed_", "tru_", "list_of_"))]


@pytest.mark.parametrize("vector", TYPED, ids=[v["name"] for v in TYPED])
def test_ts_typed_bytes_decode_to_the_declared_value(vector: dict[str, str]) -> None:
    expected = eval(vector["python"], {"__builtins__": {"bytes": bytes, "range": range}}, NAMESPACE)
    assert _lists(parse(bytes.fromhex(vector["hex"]))) == _lists(_plain(expected))


def _lists(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_lists(item) for item in value]
    if isinstance(value, dict):
        return {_lists(k): _lists(v) for k, v in value.items()}
    return value
