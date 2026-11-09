// Regenerates tests/fixtures/ts-packet-vectors.json from the esiur-ts build (npm run build there first).
// Usage: node tools/gen-packet-vectors.mjs [path-to-esiur-ts]
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const root = resolve(process.argv[2] ?? "../esiur-ts");
const esiur = await import(pathToFileURL(resolve(root, "dist/index.js")).href);
const { Codec, EpPacket, EpAuthPacket, EpPacketMethod, typedList, typedMap, t, u8 } = esiur;
const compose = Codec.compose;
const hex = (u8a) => Buffer.from(u8a).toString("hex");
const fromHex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const cat = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));

// The TDUs the packets carry, as the connection layer would compose them.
const tdus = {
  hi: compose("hi"),
  null: compose(null),
  int: compose(300),
  list: compose([1, "a", null]),
  typed: compose(typedList(t.i32, [1, 2, 3])),
  headers: compose(typedMap(t.u8, t.dynamic, [[u8(0), 1], [u8(1), "example.com"], [u8(15), new Uint8Array([1, 2, 3])]])),
  big: compose(new Uint8Array(300).fill(9)), // a two-byte length
};
const huge = compose(new Uint8Array(70_000).fill(9)); // a three-byte length (not stored)

// What the parser makes of a PlainTdu, in the same terms the Python port exposes.
const tduInfo = (tdu, base) =>
  tdu === null
    ? null
    : {
        identifier: tdu.identifier,
        index: tdu.index,
        tduClass: tdu.tduClass,
        offset: tdu.tduOffset - base,
        payloadOffset: tdu.payloadOffset - base,
        payloadLength: tdu.payloadLength,
        totalLength: tdu.totalLength,
      };

function parsePacket(bytes, offset = 0) {
  const p = new EpPacket();
  try {
    const ret = p.parse(bytes, offset, bytes.length);
    if (ret < 0) return { ret };
    return {
      ret,
      method: p.method,
      action: p.action,
      callbackId: p.callbackId,
      hasTdu: p.hasTdu,
      tdu: tduInfo(p.tdu, offset),
    };
  } catch (e) {
    return { error: e.constructor.name };
  }
}

function parseAuth(bytes, offset = 0) {
  const p = new EpAuthPacket();
  try {
    const ret = p.parse(bytes, offset, bytes.length);
    if (ret < 0) return { ret };
    return {
      ret,
      command: p.command,
      hasTdu: p.hasTdu,
      tdu: tduInfo(p.tdu, offset),
      ...(p.command === 0
        ? { authMode: p.authMode, encryptionMode: p.encryptionMode }
        : { method: p.method }),
    };
  } catch (e) {
    return { error: e.constructor.name };
  }
}

// ---- compose --------------------------------------------------------------------------

const composeCases = [];
const add = (name, kind, args, bytes) => composeCases.push({ name, kind, args, hex: hex(bytes) });

for (const [action, name] of [[0, "invoke"], [0x13, "create"], [0x18, "keepalive"], [0x1f, "max"]]) {
  add(`request_${name}_no_tdu`, "request", { action, callbackId: 7 }, EpPacket.composeRequest(action, 7));
  add(`request_${name}_tdu`, "request", { action, callbackId: 0xdeadbeef, tdu: hex(tdus.list) },
    EpPacket.composeRequest(action, 0xdeadbeef, tdus.list));
}
for (const [action, name] of [[0, "completed"], [5, "execution_error"], [0xa, "warning"]]) {
  add(`reply_${name}_no_tdu`, "reply", { action, callbackId: 0 }, EpPacket.composeReply(action, 0));
  add(`reply_${name}_tdu`, "reply", { action, callbackId: 0xffffffff, tdu: hex(tdus.typed) },
    EpPacket.composeReply(action, 0xffffffff, tdus.typed));
}
for (const [action, name] of [[0, "property"], [1, "event"], [0xb, "failure"]]) {
  add(`notification_${name}_no_tdu`, "notification", { action }, EpPacket.composeNotification(action));
  add(`notification_${name}_tdu`, "notification", { action, tdu: hex(tdus.int) },
    EpPacket.composeNotification(action, tdus.int));
}
add("request_big_tdu", "request", { action: 0, callbackId: 1, tdu: hex(tdus.big) },
  EpPacket.composeRequest(0, 1, tdus.big));

for (let auth = 0; auth < 4; auth++) {
  for (let enc = 0; enc < 3; enc++) {
    add(`auth_init_${auth}_${enc}`, "auth_initialize", { authMode: auth, encryptionMode: enc },
      EpAuthPacket.composeInitialize(auth, enc));
    add(`auth_init_${auth}_${enc}_headers`, "auth_initialize",
      { authMode: auth, encryptionMode: enc, tdu: hex(tdus.headers) },
      EpAuthPacket.composeInitialize(auth, enc, tdus.headers));
  }
}
for (const method of [0x00, 0x80, 0x81, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xc0, 0xc1, 0xc2, 0xc3, 0xc8, 0xd0, 0xd1, 0xd2]) {
  add(`auth_method_${method.toString(16)}`, "auth_method", { method }, EpAuthPacket.composeMethod(method));
  add(`auth_method_${method.toString(16)}_headers`, "auth_method", { method, tdu: hex(tdus.headers) },
    EpAuthPacket.composeMethod(method, tdus.headers));
}

// ---- parse: every header byte ---------------------------------------------------------

const callback = Uint8Array.of(0x78, 0x56, 0x34, 0x12);
const packetSweep = [];
const authSweep = [];
for (let b = 0; b < 256; b++) {
  const method = b >> 6;
  const body = cat(
    method === EpPacketMethod.Request || method === EpPacketMethod.Reply ? callback : [],
    b & 0x20 ? tdus.hi : [],
  );
  const bytes = cat([b], body);
  packetSweep.push({ hex: hex(bytes), expect: parsePacket(bytes) });
  const authBytes = cat([b], b & 0x20 ? tdus.headers : []);
  authSweep.push({ hex: hex(authBytes), expect: parseAuth(authBytes) });
}

// ---- parse: every prefix of a few whole packets --------------------------------------

const prefixSources = {
  request_tdu: EpPacket.composeRequest(0x10, 99, tdus.list),
  reply_typed: EpPacket.composeReply(0, 99, tdus.typed),
  notification: EpPacket.composeNotification(1, tdus.int),
  request_big: EpPacket.composeRequest(0, 1, huge).slice(0, 20), // length known, body cut short
};
const authPrefixSources = {
  init_headers: EpAuthPacket.composeInitialize(3, 2, tdus.headers),
  method_headers: EpAuthPacket.composeMethod(0x80, tdus.headers),
};
const prefixes = [];
for (const [name, bytes] of Object.entries(prefixSources)) {
  for (let n = 0; n <= bytes.length; n++) {
    prefixes.push({ name, kind: "packet", hex: hex(bytes.slice(0, n)), expect: parsePacket(bytes.slice(0, n)) });
  }
}
for (const [name, bytes] of Object.entries(authPrefixSources)) {
  for (let n = 0; n <= bytes.length; n++) {
    prefixes.push({ name, kind: "auth", hex: hex(bytes.slice(0, n)), expect: parseAuth(bytes.slice(0, n)) });
  }
}

// ---- parse: edge cases ----------------------------------------------------------------

const edges = [];
const edge = (name, kind, bytes, offset = 0) =>
  edges.push({
    name,
    kind,
    hex: hex(bytes),
    offset,
    expect: kind === "packet" ? parsePacket(bytes, offset) : parseAuth(bytes, offset),
  });

const keepAlive = EpPacket.composeRequest(0x18, 5);
edge("trailing_bytes", "packet", cat(keepAlive, [0xaa, 0xbb]));
edge("junk_before_offset", "packet", cat([1, 2, 3], keepAlive, [9]), 3);
edge("typed_tdu_not_decoded", "packet", EpPacket.composeNotification(0, tdus.typed));
edge("oversized_declaration", "packet", cat([0x20], [0x58, 0xff, 0xff, 0xff, 0xff, 0xff]));
edge("extension_method_with_tdu", "packet", cat([0xe0 | 3], tdus.hi));
edge("extension_method_no_tdu", "packet", Uint8Array.of(0xc7));
edge("auth_trailing_bytes", "auth", cat(EpAuthPacket.composeMethod(0x47), [0xaa]));
edge("auth_initialize_reserved_bit", "auth", Uint8Array.of(0x10 | 0x0b));
edge("auth_oversized_declaration", "auth", cat([0x20], [0x58, 0xff, 0xff, 0xff, 0xff, 0xff]));
edge("auth_junk_before_offset", "auth", cat([7, 7], EpAuthPacket.composeMethod(0xc0, tdus.headers)), 2);

const out = {
  tdus: Object.fromEntries(Object.entries(tdus).map(([k, v]) => [k, hex(v)])),
  compose: composeCases,
  packetSweep,
  authSweep,
  prefixes,
  edges,
};
writeFileSync(
  new URL("../tests/fixtures/ts-packet-vectors.json", import.meta.url),
  JSON.stringify(out) + "\n",
);
console.log(
  `${composeCases.length} compose, ${packetSweep.length + authSweep.length} sweep, ` +
    `${prefixes.length} prefix, ${edges.length} edge cases`,
);
