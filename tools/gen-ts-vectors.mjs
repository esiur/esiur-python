// Regenerates tests/fixtures/ts-vectors.json from the esiur-ts build (npm run build there first).
// Usage: node tools/gen-ts-vectors.mjs [path-to-esiur-ts]
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const root = resolve(process.argv[2] ?? "../esiur-ts");
const esiur = await import(pathToFileURL(resolve(root, "dist/index.js")).href);
const compose = esiur.Codec.compose;
const { Decimal128, Uuid, u32, u64, i8, u8, i16, u16, f32, char16 } = esiur;
const { typedList, typedMap, typedTuple, t } = esiur;
const hex = (u8a) => Buffer.from(u8a).toString("hex");
const bytes = (...n) => Uint8Array.from(n);

// [name, tsValue, pythonExpression]
const cases = [
  ["null", null, "None"],
  ["true", true, "True"],
  ["int_300", 300, "300"],
  ["int_neg_70000", -70000, "-70000"],
  ["int_int32_max", 2147483647, "2147483647"],
  ["int_int32_over", 2147483648n, "2147483648"],
  ["int_i64_min", -(2n ** 63n), "-(2**63)"],
  ["double_integral_huge", 1e10, "1e10"],
  ["double_pi", Math.PI, "3.141592653589793"],
  ["double_f32_exact", 0.5, "0.5"],
  ["double_neg_zero", -0, "0.0"],
  ["string_unicode", "héllo ✓ 你好", '"héllo ✓ 你好"'],
  ["raw_300", new Uint8Array(300).fill(7), "bytes([7]) * 300"],
  ["list_mixed", [1, "a", null, true, 2.5], '[1, "a", None, True, 2.5]'],
  ["list_nested", [[1, 2], [3, [4, "x"]]], '[[1, 2], [3, [4, "x"]]]'],
  ["list_empty", [], "[]"],
  ["map_simple", new Map([["a", 1], ["b", [true]]]), '{"a": 1, "b": [True]}'],
  ["map_int_keys", new Map([[1, "x"], [2, "y"]]), '{1: "x", 2: "y"}'],
  ["u8_200", u8(200), "UInt8(200)"],
  ["u16_70000_is_u32", u32(70000), "UInt32(70000)"],
  ["u64_big", u64(2n ** 63n + 5n), "UInt64(2**63 + 5)"],
  ["i8_neg", i8(-3), "Int8(-3)"],
  ["i16_200", i16(200), "Int16(200)"],
  ["f32_1p1", f32(1.1), "Float32(1.1)"],
  ["char16_z", char16("z"), 'Char16.of("z")'],
  ["decimal_1p50", Decimal128.parse("1.50"), 'Decimal("1.50")'],
  ["decimal_neg", Decimal128.parse("-0.0000000000000000000000000001"), 'Decimal("-0.0000000000000000000000000001")'],
  ["decimal_whole", Decimal128.parse("42"), 'Decimal("42")'],
  ["datetime", new Date(Date.UTC(1999, 11, 31, 23, 59, 59, 123)), "datetime(1999, 12, 31, 23, 59, 59, 123000, tzinfo=timezone.utc)"],
  ["datetime_pre_1970", new Date(Date.UTC(1901, 0, 1)), "datetime(1901, 1, 1, tzinfo=timezone.utc)"],
  ["uuid", new Uuid(bytes(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)), "UUID(bytes=bytes(range(1, 17)))"],

  // Typed layer: Tru values, Gvwie arrays, typed lists / maps / tuples.
  ["tru_i32", t.i32, "t.i32"],
  ["tru_nullable_list", t.nullable(t.list(t.string)), "t.nullable(t.list(t.string))"],
  ["tru_map_of_nullable", t.map(t.string, t.nullable(t.i32)), "t.map(t.string, t.nullable(t.i32))"],
  ["tru_tuple3", t.tuple(t.u8, t.list(t.f64), t.bool), "t.tuple(t.u8, t.list(t.f64), t.bool)"],
  ["typed_list_i32", typedList(t.i32, [1, -2, 300, 70000, -5]), "TypedList(t.i32, [1, -2, 300, 70000, -5])"],
  ["typed_list_i16_zigzag", typedList(t.i16, [0, -1, 63, -64, 64, 32767, -32768]), "TypedList(t.i16, [0, -1, 63, -64, 64, 32767, -32768])"],
  ["typed_list_i16_long_run", typedList(t.i16, Array.from({ length: 100 }, (_, i) => i * 300 - 10000)), "TypedList(t.i16, [i * 300 - 10000 for i in range(100)])"],
  ["typed_list_u16_long_literals", typedList(t.u16, Array.from({ length: 300 }, (_, i) => i % 100)), "TypedList(t.u16, [i % 100 for i in range(300)])"],
  ["typed_list_u32", typedList(t.u32, [0, 255, 256, 65536, 4294967295]), "TypedList(t.u32, [0, 255, 256, 65536, 4294967295])"],
  ["typed_list_i64", typedList(t.i64, [1n, -(2n ** 40n), 2n ** 62n, -5n]), "TypedList(t.i64, [1, -(2**40), 2**62, -5])"],
  ["typed_list_u64", typedList(t.u64, [1n, 2n ** 40n, 2n ** 63n + 7n, 5n]), "TypedList(t.u64, [1, 2**40, 2**63 + 7, 5])"],
  ["typed_list_u64_huge_run", typedList(t.u64, Array.from({ length: 20 }, (_, i) => 2n ** 40n + BigInt(i))), "TypedList(t.u64, [2**40 + i for i in range(20)])"],
  ["typed_list_empty", typedList(t.i32, []), "TypedList(t.i32, [])"],
  ["typed_list_u8", typedList(t.u8, [1, 2, 200]), "TypedList(t.u8, [1, 2, 200])"],
  ["typed_list_i8", typedList(t.i8, [-1, 2, -128]), "TypedList(t.i8, [-1, 2, -128])"],
  ["typed_list_char", typedList(t.char, [97, 98, 0x4e2d]), "TypedList(t.char, [97, 98, 0x4e2d])"],
  ["typed_list_string", typedList(t.string, ["a", "bb", ""]), 'TypedList(t.string, ["a", "bb", ""])'],
  ["typed_list_dynamic", typedList(t.dynamic, [1, "x", null, [2]]), 'TypedList(t.dynamic, [1, "x", None, [2]])'],
  ["typed_list_f64", typedList(t.f64, [1.5, 2, 3.25]), "TypedList(t.f64, [1.5, 2, 3.25])"],
  ["typed_list_of_typed_lists", typedList(t.list(t.i32), [typedList(t.i32, [1, 2]), typedList(t.i32, [3])]), "TypedList(t.list(t.i32), [TypedList(t.i32, [1, 2]), TypedList(t.i32, [3])])"],
  ["typed_map_string_i32", typedMap(t.string, t.i32, new Map([["a", 1], ["b", 300]])), 'TypedMap(t.string, t.i32, {"a": 1, "b": 300})'],
  ["typed_map_u8_dynamic", typedMap(t.u8, t.dynamic, new Map([[1, "x"], [2, [1, 2]]])), 'TypedMap(t.u8, t.dynamic, {1: "x", 2: [1, 2]})'],
  ["typed_map_empty", typedMap(t.string, t.string, new Map()), "TypedMap(t.string, t.string, {})"],
  ["typed_tuple2", typedTuple([t.i32, t.string], [1, "a"]), 'TypedTuple([t.i32, t.string], (1, "a"))'],
  ["typed_tuple3_nested", typedTuple([t.list(t.i32), t.bool, t.f64], [typedList(t.i32, [1]), true, 2.5]), "TypedTuple([t.list(t.i32), t.bool, t.f64], (TypedList(t.i32, [1]), True, 2.5))"],
  ["list_of_same_typed_lists", [typedList(t.i32, [1]), typedList(t.i32, [2, 3]), typedList(t.i32, [])], "[TypedList(t.i32, [1]), TypedList(t.i32, [2, 3]), TypedList(t.i32, [])]"],
  ["list_of_mixed_typed_lists", [typedList(t.i32, [1]), typedList(t.string, ["a"]), typedList(t.string, ["b"])], '[TypedList(t.i32, [1]), TypedList(t.string, ["a"]), TypedList(t.string, ["b"])]'],
];

const out = cases.map(([name, value, py]) => ({ name, python: py, hex: hex(compose(value)) }));
const target = resolve(import.meta.dirname, "../tests/fixtures/ts-vectors.json");
writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${out.length} vectors to ${target}`);
