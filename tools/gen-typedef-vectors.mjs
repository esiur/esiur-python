// Regenerates tests/fixtures/ts-typedef-vectors.json from the esiur-ts SOURCE (the built dist does
// not export the member-info classes or the signature helpers, so this bundles src/ with esbuild).
// Usage: node tools/gen-typedef-vectors.mjs [path-to-esiur-ts]
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(process.argv[2] ?? "../esiur-ts").replaceAll("\\", "/");
const { build } = await import(pathToFileURL(resolve(root, "node_modules/esbuild/lib/main.js")).href);

// The entry runs inside the esiur-ts source tree, so it can use decorators and internals.
const entry = /* ts */ `
import { compose } from "${root}/src/data/Codec.ts";
import { t, typedList } from "${root}/src/data/descriptors.ts";
import { TruTypeDef } from "${root}/src/data/Tru.ts";
import { TypeDefInfo } from "${root}/src/data/types/TypeDefInfo.ts";
import { PropertyDefInfo } from "${root}/src/data/types/PropertyDefInfo.ts";
import { FunctionDefInfo } from "${root}/src/data/types/FunctionDefInfo.ts";
import { EventDefInfo } from "${root}/src/data/types/EventDefInfo.ts";
import { ConstantDefInfo } from "${root}/src/data/types/ConstantDefInfo.ts";
import { ArgumentDefInfo } from "${root}/src/data/types/ArgumentDefInfo.ts";
import { composeForSignature, name64, signatureOf } from "${root}/src/data/typeDefSignature.ts";
import { Warehouse } from "${root}/src/resource/Warehouse.ts";
import { Record } from "${root}/src/resource/records.ts";
import { defineEnum, enumValue } from "${root}/src/resource/enums.ts";
import { Export } from "${root}/src/resource/decorators.ts";

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const make = (Ctor, fields) => Object.assign(new Ctor(), fields);
const ref = (id, name) => new TruTypeDef(false, { id, name, kind: 1, properties: [], createInstance: () => ({}), setProperty() {} });

class PointRecord extends Record {
  @Export(t.i32) accessor x = 0;
  @Export(t.i32) accessor y = 0;
}
class PathRecord extends Record {
  @Export(t.string) accessor name = "";
  @Export(t.list(t.i32)) accessor points = [];
}
class MixedRecord extends Record {
  @Export(t.nullable(t.string)) accessor label = null;
  @Export(t.dynamic) accessor extra = null;
  @Export(t.f64) accessor ratio = 0;
}
const Color = defineEnum("Color", { Red: 0, Green: 1, Blue: 2 });

const out = [];
const add = (name, python, bytes, extra = {}) => out.push({ name, python, hex: hex(bytes), ...extra });

// ---- TypeDefInfo -------------------------------------------------------------------------
add("typedef_minimal",
  'TypeDefInfo(id=1, name="Point", kind=TypeDefKind.RECORD)',
  compose(make(TypeDefInfo, { id: 1n, name: "Point", kind: 1 })));

const wide = make(TypeDefInfo, {
  version: 3, id: 7n, name: "Sensor", namespace: "Acme.Devices", kind: 0, parent: 2n,
  signature: 0x1122334455667788n,
  usage: "u", description: "A sensor", example: [1, "x"], category: "iot", since: "3.2",
  annotations: new Map([["owner", "ops"], ["tier", "gold"]]),
  properties: [
    make(PropertyDefInfo, { index: 0, name: "temperature", flags: 0x04, valueType: t.f64,
      description: "deg C", unit: "C", minimum: -40, maximum: 125, effects: 0, orderingControl: 2, historyControl: 1,
      defaultValue: 20.5, tags: ["a", "b"], relatedMembers: [1, 2], annotations: new Map([["k", "v"]]) }),
    make(PropertyDefInfo, { index: 1, name: "label", flags: 0, valueType: t.nullable(t.string) }),
    make(PropertyDefInfo, { index: 2, name: "readings", flags: 0x22, valueType: t.list(t.map(t.string, t.i32)) }),
  ],
  functions: [
    make(FunctionDefInfo, { index: 0, name: "calibrate", flags: 0x14, returnType: t.bool, streamMode: 1,
      effects: 0x11, preconditions: ["idle"], warnings: ["slow"], deprecationMessage: "use x",
      arguments: [
        make(ArgumentDefInfo, { index: 0, name: "offset", flags: 0, valueType: t.f64 }),
        make(ArgumentDefInfo, { index: 1, name: "mode", flags: 3, valueType: t.string, defaultValue: "auto" }),
      ] }),
    make(FunctionDefInfo, { index: 1, name: "reset", flags: 0 }),
  ],
  events: [
    make(EventDefInfo, { index: 0, name: "changed", flags: 0x04, argumentType: t.f64, argumentName: "value", orderingControl: 1, historyControl: 2 }),
  ],
  constants: [
    make(ConstantDefInfo, { index: 0, name: "MaxRate", flags: 0, valueType: t.u16, value: 1000 }),
    make(ConstantDefInfo, { index: 1, name: "Unit", flags: 2, valueType: t.string, value: "C" }),
  ],
});
add("typedef_full_resource",
  'TypeDefInfo(version=3, id=7, name="Sensor", namespace="Acme.Devices", kind=TypeDefKind.RESOURCE, parent=2, '
  + 'signature=0x1122334455667788, usage="u", description="A sensor", example=[1, "x"], category="iot", since="3.2", '
  + 'annotations={"owner": "ops", "tier": "gold"}, properties=['
  + 'PropertyDefInfo(index=0, name="temperature", flags=0x04, value_type=t.f64, description="deg C", unit="C", minimum=-40, maximum=125, '
  + 'effects=0, ordering_control=2, history_control=1, default_value=20.5, tags=["a", "b"], related_members=[1, 2], annotations={"k": "v"}), '
  + 'PropertyDefInfo(index=1, name="label", flags=0, value_type=t.nullable(t.string)), '
  + 'PropertyDefInfo(index=2, name="readings", flags=0x22, value_type=t.list(t.map(t.string, t.i32)))], functions=['
  + 'FunctionDefInfo(index=0, name="calibrate", flags=0x14, return_type=t.bool, stream_mode=1, effects=0x11, preconditions=["idle"], '
  + 'warnings=["slow"], deprecation_message="use x", arguments=[ArgumentDefInfo(index=0, name="offset", flags=0, value_type=t.f64), '
  + 'ArgumentDefInfo(index=1, name="mode", flags=3, value_type=t.string, default_value="auto")]), '
  + 'FunctionDefInfo(index=1, name="reset", flags=0)], events=['
  + 'EventDefInfo(index=0, name="changed", flags=0x04, argument_type=t.f64, argument_name="value", ordering_control=1, history_control=2)], constants=['
  + 'ConstantDefInfo(index=0, name="MaxRate", flags=0, value_type=t.u16, value=1000), '
  + 'ConstantDefInfo(index=1, name="Unit", flags=2, value_type=t.string, value="C")])',
  compose(wide));

add("typedef_with_type_references",
  'TypeDefInfo(id=9, name="Holder", kind=TypeDefKind.RESOURCE, properties=[PropertyDefInfo(index=0, name="a", value_type=TruTypeDef(3)), '
  + 'PropertyDefInfo(index=1, name="b", value_type=t.nullable(TruTypeDef(300))), PropertyDefInfo(index=2, name="c", value_type=t.list(TruTypeDef(70000)))])',
  compose(make(TypeDefInfo, { id: 9n, name: "Holder", kind: 0, properties: [
    make(PropertyDefInfo, { index: 0, name: "a", valueType: ref(3n, "A") }),
    make(PropertyDefInfo, { index: 1, name: "b", valueType: ref(300n, "B").toNullable() }),
    make(PropertyDefInfo, { index: 2, name: "c", valueType: t.list(ref(70000n, "C")) }),
  ] })));

add("typedef_enum",
  'TypeDefInfo(id=2, name="Color", kind=TypeDefKind.ENUM, constants=[ConstantDefInfo(index=0, name="Red", value=0), '
  + 'ConstantDefInfo(index=1, name="Green", value=1), ConstantDefInfo(index=2, name="Blue", value=2)])',
  compose(make(TypeDefInfo, { id: 2n, name: "Color", kind: 2, constants: [
    make(ConstantDefInfo, { index: 0, name: "Red", value: 0 }),
    make(ConstantDefInfo, { index: 1, name: "Green", value: 1 }),
    make(ConstantDefInfo, { index: 2, name: "Blue", value: 2 }),
  ] })));

add("list_of_typedefs",
  '[TypeDefInfo(id=1, name="A", kind=TypeDefKind.RECORD), TypeDefInfo(id=2, name="B", kind=TypeDefKind.RECORD)]',
  compose([make(TypeDefInfo, { id: 1n, name: "A", kind: 1 }), make(TypeDefInfo, { id: 2n, name: "B", kind: 1 })]));

// ---- signatures --------------------------------------------------------------------------
// Mirrors computeTypeDefSignature() from protocol/typeDefSigning.ts (which needs a Warehouse of
// templates): zero the id, drop the signature, hash the parent's name, compose in signature mode.
const NAMES = { 3n: "Alpha", 300n: "Beta", 70000n: "Gamma", 2n: "Base" };
function signature(info) {
  info.id = 0n;
  info.signature = undefined;
  if (info.parent !== undefined) {
    const parentName = NAMES[info.parent];
    info.parent = parentName === undefined ? undefined : name64(parentName);
  }
  return signatureOf(composeForSignature(() => compose(info, null, null)));
}
const sigInfo = () => make(TypeDefInfo, { id: 9n, name: "Holder", kind: 0, parent: 2n, properties: [
  make(PropertyDefInfo, { index: 0, name: "a", valueType: ref(3n, "Alpha") }),
  make(PropertyDefInfo, { index: 1, name: "b", valueType: ref(300n, "Beta").toNullable() }),
  make(PropertyDefInfo, { index: 2, name: "c", valueType: t.list(ref(70000n, "Gamma")) }),
] });
const sigs = [];
sigs.push({ name: "signature_with_references", python:
  'TypeDefInfo(id=9, name="Holder", kind=TypeDefKind.RESOURCE, parent=2, properties=[PropertyDefInfo(index=0, name="a", value_type=TruTypeDef(3)), '
  + 'PropertyDefInfo(index=1, name="b", value_type=t.nullable(TruTypeDef(300))), PropertyDefInfo(index=2, name="c", value_type=t.list(TruTypeDef(70000)))])',
  signature: signature(sigInfo()).toString() });
sigs.push({ name: "signature_plain", python: 'TypeDefInfo(id=5, name="Plain", kind=TypeDefKind.RECORD, properties=[PropertyDefInfo(index=0, name="x", value_type=t.i32)])',
  signature: signature(make(TypeDefInfo, { id: 5n, name: "Plain", kind: 1, properties: [make(PropertyDefInfo, { index: 0, name: "x", valueType: t.i32 })] })).toString() });
sigs.push({ name: "signature_unknown_parent", python: 'TypeDefInfo(id=5, name="Orphan", kind=TypeDefKind.RESOURCE, parent=99)',
  signature: signature(make(TypeDefInfo, { id: 5n, name: "Orphan", kind: 0, parent: 99n })).toString() });
const names = [["Alpha", name64("Alpha")], ["", name64("")], ["héllo", name64("héllo")]].map(([n, v]) => ({ name: n, name64: v.toString() }));

// ---- records and enums ---------------------------------------------------------------------
function record(name, python, types, build) {
  const wh = new Warehouse();
  add(name, python, compose(build(), wh, null), { types });
}
const point = (x, y) => Object.assign(new PointRecord(), { x, y });
record("record_point", "Point(3, 4)", ["Point"], () => point(3, 4));
record("record_point_big_id_values", "Point(70000, -5)", ["Point"], () => point(70000, -5));
record("record_path_dynamic_list", 'Path("seg", [1, 2, 3])', ["Path"],
  () => Object.assign(new PathRecord(), { name: "seg", points: [1, 2, 3] }));
record("record_path_typed_list", 'Path("seg", TypedList(t.i32, [1, 2, 3]))', ["Path"],
  () => Object.assign(new PathRecord(), { name: "seg", points: typedList(t.i32, [1, 2, 3]) }));
record("record_mixed_nulls", "Mixed(None, None, 0.5)", ["Mixed"],
  () => Object.assign(new MixedRecord(), { label: null, extra: null, ratio: 0.5 }));
record("record_mixed_filled", 'Mixed("hi", {"a": [1, 2]}, 2.25)', ["Mixed"],
  () => Object.assign(new MixedRecord(), { label: "hi", extra: new Map([["a", [1, 2]]]), ratio: 2.25 }));
record("record_in_list_continuation", "[Point(1, 2), Point(3, 4), Point(5, 6)]", ["Point"],
  () => [point(1, 2), point(3, 4), point(5, 6)]);
record("record_nested_in_dynamic_property", 'Mixed("n", Point(7, 8), 1.5)', ["Mixed", "Point"],
  () => Object.assign(new MixedRecord(), { label: "n", extra: point(7, 8), ratio: 1.5 }));
record("enum_green", "Color.GREEN", ["Color"], () => enumValue(Color, 1));
record("enum_in_list", "[Color.RED, Color.BLUE, Color.BLUE]", ["Color"],
  () => [enumValue(Color, 0), enumValue(Color, 2), enumValue(Color, 2)]);
record("enum_and_record_ids", "[Point(1, 1), Color.RED]", ["Point", "Color"], () => [point(1, 1), enumValue(Color, 0)]);
record("enum_then_record_ids", "[Color.RED, Point(1, 1)]", ["Color", "Point"], () => [enumValue(Color, 0), point(1, 1)]);
record("map_of_records", '{"p": Point(2, 3)}', ["Point"], () => new Map([["p", point(2, 3)]]));

export default { vectors: out, signatures: sigs, names };
`;

const dir = mkdtempSync(join(tmpdir(), "esiur-typedef-"));
try {
  const result = await build({
    stdin: { contents: entry, resolveDir: root, loader: "ts", sourcefile: "gen.ts" },
    bundle: true, write: false, platform: "node", format: "esm", target: "es2022",
    tsconfigRaw: { compilerOptions: { target: "ES2022", useDefineForClassFields: true } },
    logLevel: "error",
  });
  const file = join(dir, "gen.mjs");
  writeFileSync(file, result.outputFiles[0].text);
  const generated = (await import(pathToFileURL(file).href)).default;
  const target = resolve(import.meta.dirname, "../tests/fixtures/ts-typedef-vectors.json");
  writeFileSync(target, JSON.stringify(generated, null, 2) + "\n");
  console.log(`wrote ${generated.vectors.length} vectors, ${generated.signatures.length} signatures to ${target}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
