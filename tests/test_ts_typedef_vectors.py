"""Differential test of the TypeDef layer against the real esiur-ts encoder.

Regenerate the fixture with ``node tools/gen-typedef-vectors.mjs ../esiur-ts``. The ``python``
field of each vector is a trusted, repository-owned expression.
"""

import dataclasses
import enum
import json
from pathlib import Path
from typing import Any

import pytest

from esiur.data import (
    ArgumentDefInfo,
    ConstantDefInfo,
    EventDefInfo,
    FunctionDefInfo,
    PropertyDefInfo,
    TruTypeDef,
    TypeDefInfo,
    TypeDefKind,
    TypedList,
    TypeRegistry,
    compose,
    name64,
    parse,
    t,
)
from esiur.data.typedef_signature import typedef_signature

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "ts-typedef-vectors.json").read_text("utf-8"))


@dataclasses.dataclass
class Point:
    x: int = 0
    y: int = 0


@dataclasses.dataclass
class Path_:
    name: str = ""
    points: Any = None


@dataclasses.dataclass
class Mixed:
    label: Any = None
    extra: Any = None
    ratio: float = 0.0


class Color(enum.IntEnum):
    RED = 0
    GREEN = 1
    BLUE = 2


REGISTER = {
    "Point": lambda r: r.register_record(Point, [("x", t.i32), ("y", t.i32)]),
    "Path": lambda r: r.register_record(
        Path_, [("name", t.string), ("points", t.list(t.i32))], name="PathRecord"
    ),
    "Mixed": lambda r: r.register_record(
        Mixed, [("label", t.nullable(t.string)), ("extra", t.dynamic), ("ratio", t.f64)]
    ),
    "Color": lambda r: r.register_enum(Color),
}
NAMESPACE: dict[str, Any] = {
    "TypeDefInfo": TypeDefInfo, "PropertyDefInfo": PropertyDefInfo,
    "FunctionDefInfo": FunctionDefInfo, "EventDefInfo": EventDefInfo,
    "ConstantDefInfo": ConstantDefInfo, "ArgumentDefInfo": ArgumentDefInfo,
    "TypeDefKind": TypeDefKind, "TruTypeDef": TruTypeDef, "TypedList": TypedList, "t": t,
    "Point": Point, "Path": Path_, "Mixed": Mixed, "Color": Color,
}


def _evaluate(expression: str) -> Any:
    return eval(expression, {"__builtins__": {}}, NAMESPACE)


def _registry(names: list[str]) -> TypeRegistry:
    registry = TypeRegistry()
    for name in names:
        REGISTER[name](registry)
    return registry


def _norm(value: Any) -> Any:
    """Plain comparable form: dataclasses by field, typed lists and tuples as lists."""
    if isinstance(value, TypedList):
        return [_norm(v) for v in value.values]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {f.name: _norm(getattr(value, f.name)) for f in dataclasses.fields(value)}
        return (type(value).__name__, fields)
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in value.items()}
    return value


VECTORS = FIXTURE["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_compose_matches_esiur_ts(vector: dict[str, Any]) -> None:
    registry = _registry(vector.get("types", []))
    assert compose(_evaluate(vector["python"]), types=registry).hex() == vector["hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_ts_bytes_decode_to_the_composed_value(vector: dict[str, Any]) -> None:
    registry = _registry(vector.get("types", []))
    decoded = parse(bytes.fromhex(vector["hex"]), types=registry)
    assert _norm(decoded) == _norm(_evaluate(vector["python"]))


NAMES = {3: "Alpha", 300: "Beta", 70000: "Gamma", 2: "Base"}


@pytest.mark.parametrize("vector", FIXTURE["signatures"], ids=[v["name"] for v in FIXTURE["signatures"]])
def test_signature_matches_esiur_ts(vector: dict[str, Any]) -> None:
    assert str(typedef_signature(_evaluate(vector["python"]), NAMES.__getitem__)) == vector["signature"]


@pytest.mark.parametrize("entry", FIXTURE["names"], ids=lambda e: e["name"] or "empty")
def test_name64_matches_esiur_ts(entry: dict[str, str]) -> None:
    assert str(name64(entry["name"])) == entry["name64"]
