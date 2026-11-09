import dataclasses
import enum
from typing import Any

import pytest

from esiur.data import (
    IndexedStructure,
    ParserError,
    ParserLimitError,
    PropertyDefInfo,
    TduIdentifier,
    TruTypeDef,
    TypeDefConstant,
    TypeDefInfo,
    TypeDefinition,
    TypeDefKind,
    TypedMap,
    TypeRegistry,
    UInt128,
    compose,
    compose_tdu,
    parse,
    t,
    to_indexed_map,
)
from esiur.data.structure import indexed_members, member
from esiur.data.typedef_signature import typedef_signature

# ------------------------------------------------------------ indexed structures --


@dataclasses.dataclass(kw_only=True)
class Reading(IndexedStructure):
    value: int = member(0, 0, wire=t.i32, expect=int)
    label: str | None = member(1, expect=str)
    tags: list[str] | None = member(2, expect=list)


def test_structure_composes_sparsely_and_round_trips() -> None:
    sparse = Reading(value=5)
    map_ = to_indexed_map(sparse)
    assert [k for k, _ in map_.entries] == [0]  # None members are omitted
    assert parse(compose(sparse)) == {0: 5}
    full = Reading(value=-70_000, label="x", tags=["a", "b"])
    assert parse(compose(full)) == {0: -70_000, 1: "x", 2: ["a", "b"]}


def test_unknown_indices_are_ignored_and_missing_ones_default() -> None:
    from esiur.data.structure import from_indexed_map

    rebuilt = from_indexed_map(Reading, {0: 9, 200: "from a newer peer"})
    assert rebuilt == Reading(value=9)
    assert from_indexed_map(Reading, {}) == Reading()


def test_int32_member_narrows_like_any_dynamic_value() -> None:
    # The declared Int32 wrapper still narrows on the wire, as in esiur-ts.
    assert compose(Reading(value=5)) == compose(TypedMap(t.u8, t.dynamic, {0: 5}))
    assert compose(Reading(value=70_000)) != compose(Reading(value=5))


def test_structure_errors() -> None:
    @dataclasses.dataclass(kw_only=True)
    class Twice(IndexedStructure):
        a: int = member(1, 0)
        b: int = member(1, 0)

    with pytest.raises(ValueError, match="already used"):
        indexed_members(Twice)

    class NotADataclass(IndexedStructure):
        pass

    with pytest.raises(TypeError):
        indexed_members(NotADataclass)
    with pytest.raises(ValueError):
        member(256)
    with pytest.raises(TypeError):
        compose(Reading(value=True))  # type: ignore[arg-type]


def test_received_values_must_have_the_declared_python_type() -> None:
    from esiur.data.structure import from_indexed_map

    with pytest.raises(ParserError, match="Reading.label"):
        from_indexed_map(Reading, {1: 5})
    with pytest.raises(ParserError):
        from_indexed_map(Reading, {0: True})  # a bool is not an integer on the wire
    with pytest.raises(ParserError):
        from_indexed_map(Reading, [1, 2])


# ----------------------------------------------------------------- TypeDefInfo --


def _typedef_tdu(payload_map: dict[int, Any]) -> bytes:
    return compose_tdu(TduIdentifier.TYPEDEF, compose(TypedMap(t.u8, t.dynamic, payload_map)))


def test_typedef_info_round_trips() -> None:
    info = TypeDefInfo(
        id=7, name="T", kind=TypeDefKind.RECORD,
        properties=[PropertyDefInfo(index=0, name="p", value_type=t.nullable(t.i32))],
    )
    wire = compose(info)
    assert wire[0] & 0xC7 == TduIdentifier.TYPEDEF
    assert parse(wire) == info


def test_typedef_rejects_malformed_payloads() -> None:
    with pytest.raises(ParserError):
        parse(_typedef_tdu({2: 5}))  # name must be a string
    with pytest.raises(ParserError):
        parse(_typedef_tdu({6: [5]}))  # properties must be structures
    with pytest.raises(ParserError, match="64 bits"):
        parse(_typedef_tdu({1: UInt128(1 << 100)}))
    inner = compose(TypedMap(t.u8, t.dynamic, {2: "x"}))
    with pytest.raises(ParserError, match="trailing"):
        parse(compose_tdu(TduIdentifier.TYPEDEF, inner + b"\x00"))
    with pytest.raises(ParserError):
        parse(compose_tdu(TduIdentifier.TYPEDEF, inner[:-1]))


def test_typedef_keeps_members_it_does_not_know() -> None:
    wire = _typedef_tdu({1: 3, 2: "T", 0x7F: "future"})
    assert parse(wire) == TypeDefInfo(id=3, name="T")


def test_a_list_of_typedefs_uses_a_continuation() -> None:
    infos = [TypeDefInfo(id=i, name=f"T{i}") for i in range(1, 4)]
    assert parse(compose(infos)) == infos


# --------------------------------------------------------------------- registry --


@dataclasses.dataclass(frozen=True)
class FrozenPoint:
    x: int
    y: int


class Mode(enum.Enum):
    OFF = "off"
    ON = "on"


def test_ids_are_assigned_in_registration_order() -> None:
    registry = TypeRegistry()
    a = registry.register_record(FrozenPoint)
    b = registry.register_enum(Mode)
    assert (a.id, b.id) == (1, 2)
    assert registry.name_of(2) == "Mode" and len(registry) == 2
    assert registry.register_enum(enum.IntEnum("Big", {"A": 1}), id=40).id == 40
    assert registry.register_enum(enum.Enum("Next", {"A": 1})).id == 3


def test_registration_errors() -> None:
    registry = TypeRegistry()
    registry.register_record(FrozenPoint)
    with pytest.raises(ValueError, match="already registered"):
        registry.register_record(FrozenPoint)
    with pytest.raises(ValueError):
        registry.register_enum(Mode, id=1)
    with pytest.raises(ValueError):
        registry.register_enum(Mode, id=0)
    with pytest.raises(TypeError):
        registry.register_record(Mode)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="same name"):
        registry.register_record(dict, ["a", "a"])
    with pytest.raises(ValueError, match="256"):
        registry.register_enum(enum.Enum("Huge", {f"M{i}": i for i in range(257)}))
    with pytest.raises(KeyError):
        registry.name_of(99)


def test_frozen_dataclass_records_round_trip() -> None:
    registry = TypeRegistry()
    registry.register_record(FrozenPoint)
    value = FrozenPoint(3, -4)
    assert parse(compose(value, types=registry), types=registry) == value


def test_enum_members_round_trip_as_their_position() -> None:
    registry = TypeRegistry()
    registry.register_enum(Mode)
    wire = compose(Mode.ON, types=registry)
    assert wire.endswith(b"\x01")
    assert parse(wire, types=registry) is Mode.ON


def test_a_registered_value_needs_the_registry_on_both_sides() -> None:
    registry = TypeRegistry()
    registry.register_record(FrozenPoint)
    with pytest.raises(TypeError):
        compose(FrozenPoint(1, 2))
    wire = compose(FrozenPoint(1, 2), types=registry)
    with pytest.raises(ParserError, match="TypeRegistry"):
        parse(wire)
    with pytest.raises(ParserError, match="not registered"):
        parse(wire, types=TypeRegistry())


def test_hostile_record_and_enum_payloads() -> None:
    registry = TypeRegistry()
    registry.register_record(FrozenPoint)
    registry.register_enum(Mode)
    point_meta = TruTypeDef(1).compose()
    mode_meta = TruTypeDef(2).compose()

    def typed(meta: bytes, payload: bytes) -> bytes:
        return compose_tdu(0x80, meta + payload)

    one, two = compose(1), compose(2)
    assert parse(typed(point_meta, one + two), types=registry) == FrozenPoint(1, 2)
    with pytest.raises(ParserError):  # a property is missing
        parse(typed(point_meta, one), types=registry)
    with pytest.raises(ParserError, match="after its last"):
        parse(typed(point_meta, one + two + one), types=registry)
    with pytest.raises(ParserError, match="single constant index"):
        parse(typed(mode_meta, b"\x00\x00"), types=registry)
    with pytest.raises(ParserError, match="no constant at index 2"):
        parse(typed(mode_meta, b"\x02"), types=registry)
    with pytest.raises(ParserError, match="no declared type"):
        parse(typed(point_meta, compose_tdu(TduIdentifier.TYPE_OF_TARGET, b"\x00")), types=registry)
    remote = TruTypeDef(1, remote=True).compose()
    with pytest.raises(ParserError, match="connection"):
        parse(typed(remote, one + two), types=registry)
    with pytest.raises(ParserLimitError):
        parse(typed(point_meta, one + two), types=registry, maximum_collection_items=1)


def test_a_value_that_is_not_a_constant_composes_as_null() -> None:
    class Odd:
        pass

    registry = TypeRegistry()
    registry.add(
        TypeDefinition(
            5, TypeDefKind.ENUM, "Odd", constants=(TypeDefConstant("a", 1, 0),), python_type=Odd
        )
    )
    assert compose(Odd(), types=registry) == compose(None)  # like esiur-ts


# -------------------------------------------------------------------- signatures --


def _info(first_id: int, second_id: int, base_id: int, extra: str = "") -> TypeDefInfo:
    return TypeDefInfo(
        id=99, name="Holder", parent=base_id,
        properties=[
            PropertyDefInfo(index=0, name="a" + extra, value_type=TruTypeDef(first_id)),
            PropertyDefInfo(index=1, name="b", value_type=t.list(TruTypeDef(second_id))),
        ],
    )


def test_signature_does_not_depend_on_ids() -> None:
    left = {1: "A", 2: "B", 3: "Base"}
    right = {10: "A", 4000: "B", 70_000: "Base"}
    one = typedef_signature(_info(1, 2, 3), left.__getitem__)
    two = typedef_signature(_info(10, 4000, 70_000), right.__getitem__)
    assert one == two != 0


def test_signature_changes_with_the_contract() -> None:
    names = {1: "A", 2: "B", 3: "Base"}
    base = typedef_signature(_info(1, 2, 3), names.__getitem__)
    assert typedef_signature(_info(1, 2, 3, extra="2"), names.__getitem__) != base
    assert typedef_signature(_info(2, 1, 3), names.__getitem__) != base


def test_signature_ignores_a_recorded_signature_and_the_own_id() -> None:
    names = {1: "A", 2: "B", 3: "Base"}
    plain = _info(1, 2, 3)
    stamped = dataclasses.replace(plain, id=5, signature=1234)
    assert typedef_signature(stamped, names.__getitem__) == typedef_signature(
        plain, names.__getitem__
    )


def test_signature_mode_is_scoped_to_the_computation() -> None:
    names = {1: "A"}
    reference = TruTypeDef(1)
    before = reference.compose()
    typedef_signature(TypeDefInfo(properties=[PropertyDefInfo(value_type=reference)]), names.__getitem__)
    assert reference.compose() == before == bytes([0x40, 1])


def test_an_unnameable_reference_is_an_error() -> None:
    with pytest.raises(KeyError):
        typedef_signature(_info(1, 2, 3), {3: "Base"}.__getitem__)
