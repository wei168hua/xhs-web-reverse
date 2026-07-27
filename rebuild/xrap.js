'use strict';
/**
 * XHS Web `x-rap-param` — offline reconstruction + decoder.
 *
 * Recovered in this session by: capturing a REAL browser x-rap-param (from a
 * search/notes POST) together with its exact (api, body, x-t) context, decoding
 * the envelope, and VERIFYING the structure against the open-source xhshow
 * model — including an independent xxh32 that reproduces the header content_hash
 * byte-for-byte on the live sample.
 *
 * Pipeline (matches observed `ByQB...` envelope):
 *   body TLV (see _build_body_structure) 
 *     -> gzip (OS byte patched to 0x03)
 *     -> cyclic XOR with 16-byte session key
 *     -> SM4-variant block cipher (custom S-box + pre-expanded round keys), ECB
 *     -> envelope: header(0x07,0x24,0x01,saltLen | u32 1 | u32 20 | u32 cipherBodyLen
 *                  | u32 xxh32(content) | u32 protocolVersion | u32 encTime | 8x00)
 *                  + content(salt + encrypt_block16(key) + u32(16) + cipherBlocks + u32(origGzipLen))
 *     -> base64
 *
 * Live sample confirmed: magic 07 24 01, salt "pwnon", const1=1, const2=20,
 * cipherBodyLen=212, content_hash=ff30ab81 == xxh32(content) [VERIFIED],
 * protocolVersion=10301, session_key_len=16, cipher blocks %16==0.
 */
const zlib = require('zlib');

const MASK = 0xffffffff;

// ---------- xxh32 (verified: xxh32("")=0x02cc5d05, xxh32("abc")=0x32d153ff) ----------
function _rotl(v, s) { v >>>= 0; return ((v << s) | (v >>> (32 - s))) >>> 0; }
function _mul32(a, b) { const ah = (a >>> 16) & 0xffff, al = a & 0xffff; return (((ah * b << 16) >>> 0) + al * b) >>> 0; }
function xxh32(buf, seed = 0) {
  buf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const len = buf.length; let pos = 0;
  const p1 = 0x9e3779b1, p2 = 0x85ebca77, p3 = 0xc2b2ae3d, p4 = 0x27d4eb2f, p5 = 0x165667b1;
  let digest;
  if (len >= 16) {
    let a1 = (seed + p1 + p2) >>> 0, a2 = (seed + p2) >>> 0, a3 = seed >>> 0, a4 = (seed - p1) >>> 0;
    const end = len - 16;
    while (pos <= end) {
      let w;
      w = buf.readUInt32LE(pos); pos += 4; a1 = _mul32(_rotl((a1 + _mul32(w, p2)) >>> 0, 13), p1);
      w = buf.readUInt32LE(pos); pos += 4; a2 = _mul32(_rotl((a2 + _mul32(w, p2)) >>> 0, 13), p1);
      w = buf.readUInt32LE(pos); pos += 4; a3 = _mul32(_rotl((a3 + _mul32(w, p2)) >>> 0, 13), p1);
      w = buf.readUInt32LE(pos); pos += 4; a4 = _mul32(_rotl((a4 + _mul32(w, p2)) >>> 0, 13), p1);
    }
    digest = (_rotl(a1, 1) + _rotl(a2, 7) + _rotl(a3, 12) + _rotl(a4, 18)) >>> 0;
  } else { digest = (seed + p5) >>> 0; }
  digest = (digest + len) >>> 0;
  while (pos + 4 <= len) { const w = buf.readUInt32LE(pos); pos += 4; digest = _mul32(_rotl((digest + _mul32(w, p3)) >>> 0, 17), p4); }
  while (pos < len) { digest = _mul32(_rotl((digest + _mul32(buf[pos], p5)) >>> 0, 11), p1); pos++; }
  digest ^= digest >>> 15; digest = _mul32(digest, p2);
  digest ^= digest >>> 13; digest = _mul32(digest, p3);
  digest ^= digest >>> 16;
  return digest >>> 0;
}

// ---------- SM4-variant block cipher (custom S-box + pre-expanded round keys) ----------
const SBOX = [0x7A,0x01,0x58,0xE0,0x50,0x4E,0x02,0x79,0x1D,0x4B,0x53,0xDA,0x6B,0x48,0xD4,0x52,0xED,0x77,0x12,0x21,0x14,0x15,0xEC,0x10,0x18,0xE5,0xB9,0xF1,0x0C,0x08,0xFC,0x7D,0xF9,0xCD,0xB5,0xC8,0xE6,0x37,0x26,0x87,0x56,0xBA,0xB8,0x2B,0xAD,0xF0,0x68,0xF7,0x8B,0x8D,0xD3,0x5E,0x36,0x4D,0x2E,0x92,0x31,0x82,0xF2,0x29,0x70,0x3D,0x2D,0xD7,0xB6,0x40,0xB2,0x43,0x44,0x80,0x78,0xD2,0x0D,0x49,0x4A,0x09,0x63,0x6C,0x07,0x3A,0x9E,0xD5,0x06,0xC6,0xE1,0x62,0xF4,0x34,0x24,0x59,0xA9,0x57,0x2A,0x00,0x3E,0x17,0x2C,0x0A,0x1A,0x42,0xFA,0x93,0xBE,0xDC,0xF5,0xB3,0x6A,0x13,0xE8,0x03,0xC7,0x97,0xBB,0x73,0x76,0x86,0xE3,0x46,0x72,0x47,0xD0,0x05,0x4C,0x38,0x7C,0x1F,0x81,0xAB,0x75,0x51,0xEB,0xF3,0x32,0x74,0x11,0x8F,0x84,0x89,0x9C,0x71,0x22,0x7E,0x9D,0xCF,0x3F,0x91,0x69,0x65,0x3C,0x6D,0x96,0xA2,0x98,0x99,0x33,0x39,0x9A,0xCA,0xC3,0x9F,0xA0,0xBC,0xE4,0xA3,0xA4,0x54,0x7F,0xA7,0xA8,0x04,0x6F,0x5D,0xAC,0xB7,0x27,0xAF,0xB0,0x28,0x41,0xAE,0xB4,0x6E,0x0B,0x1B,0xDF,0x8E,0x30,0xB1,0xFE,0x90,0x61,0x60,0xC0,0xCB,0x5C,0x0E,0xEF,0x16,0x83,0xEA,0x20,0xE9,0xC9,0x55,0xC4,0x45,0x85,0xCC,0x1E,0xAA,0x67,0x8A,0x7B,0x35,0xD6,0x19,0xD8,0xD9,0xC2,0xDB,0x94,0xDD,0x1C,0xDE,0xA6,0xFF,0xF8,0xBF,0x5B,0x5A,0x0F,0xE7,0xC1,0xBD,0xD1,0x66,0xC5,0x25,0xEE,0x8C,0xE2,0x5F,0x88,0xA1,0x3B,0xA5,0xF6,0xCE,0x95,0x2F,0x64,0x23,0xFB,0xFD,0x4F,0x9B];
const ROUND_KEYS = [
  [0x6B714931,0x44546377,0x4B583930,0x5A744179],[0x89314C98,0xCD652FEF,0x863D16DF,0xDC4957A6],
  [0xC205330C,0x0F601CE3,0x895D0A3C,0x55145D9A],[0xD205006E,0xDD651C8D,0x543816B1,0x012C4B2B],
  [0x770C2B6F,0xAA6937E2,0xFE512153,0xFF7D6A78],[0x7866FBF4,0xD20FCC16,0x2C5EED45,0xD323873D],
  [0x90E9C67E,0x42E60A68,0x6EB8E72D,0xBD9B6010],[0xE9C52BEE,0xAB232186,0xC59BC6AB,0x7800A6BB],
  [0x13BA9A3E,0xB899BBB8,0x7D027D13,0x0502DBA8],[0x50613270,0xE8F889C8,0x95FAF4DB,0x90F82F73],
];
const LAST_ROUND_KEY = [0xF396B44F,0x1B6E3D87,0x8E94C95C,0x1E6CE62F];
const LAST_ROUND_KEY_BYTES = Buffer.concat(LAST_ROUND_KEY.map(w => { const b = Buffer.alloc(4); b.writeUInt32BE(w >>> 0, 0); return b; }));

function _gfDouble(x) { x <<= 1; return (x & 0x100) ? (x ^ 0x11b) & 0xff : x & 0xff; }
function _gfMul(x, n) { if (n === 1) return x; if (n === 2) return _gfDouble(x); if (n === 3) return _gfDouble(x) ^ x; throw new Error('gf'); }
const LUT = [[], [], [], []];
for (const s of SBOX) {
  const a = _gfMul(s, 2), d = _gfMul(s, 3);
  LUT[0].push((((a << 24) | (s << 16) | (s << 8) | d) >>> 0));
  LUT[1].push((((d << 24) | (a << 16) | (s << 8) | s) >>> 0));
  LUT[2].push((((s << 24) | (d << 16) | (a << 8) | s) >>> 0));
  LUT[3].push((((s << 24) | (s << 16) | (d << 8) | a) >>> 0));
}
function _readU32BE(buf, off) { return buf.readUInt32BE(off) >>> 0; }
function encryptBlock16(block) {
  const padded = Buffer.concat([Buffer.from(block), Buffer.alloc(Math.max(0, 16 - block.length))]).slice(0, 16);
  let s0 = (_readU32BE(padded, 0) ^ ROUND_KEYS[0][0]) >>> 0;
  let s1 = (_readU32BE(padded, 4) ^ ROUND_KEYS[0][1]) >>> 0;
  let s2 = (_readU32BE(padded, 8) ^ ROUND_KEYS[0][2]) >>> 0;
  let s3 = (_readU32BE(padded, 12) ^ ROUND_KEYS[0][3]) >>> 0;
  for (let rnd = 1; rnd < 10; rnd++) {
    const rk = ROUND_KEYS[rnd];
    const n0 = (LUT[0][(s0 >>> 24) & 0xff] ^ LUT[1][(s1 >>> 16) & 0xff] ^ LUT[2][(s2 >>> 8) & 0xff] ^ LUT[3][s3 & 0xff] ^ rk[0]) >>> 0;
    const n1 = (LUT[0][(s1 >>> 24) & 0xff] ^ LUT[1][(s2 >>> 16) & 0xff] ^ LUT[2][(s3 >>> 8) & 0xff] ^ LUT[3][s0 & 0xff] ^ rk[1]) >>> 0;
    const n2 = (LUT[0][(s2 >>> 24) & 0xff] ^ LUT[1][(s3 >>> 16) & 0xff] ^ LUT[2][(s0 >>> 8) & 0xff] ^ LUT[3][s1 & 0xff] ^ rk[2]) >>> 0;
    const n3 = (LUT[0][(s3 >>> 24) & 0xff] ^ LUT[1][(s0 >>> 16) & 0xff] ^ LUT[2][(s1 >>> 8) & 0xff] ^ LUT[3][s2 & 0xff] ^ rk[3]) >>> 0;
    s0 = n0; s1 = n1; s2 = n2; s3 = n3;
  }
  const state = [s0, s1, s2, s3];
  const out = Buffer.alloc(16);
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      const idx = (state[(row + col) & 3] >>> (24 - 8 * col)) & 0xff;
      out[4 * row + col] = SBOX[idx] ^ LAST_ROUND_KEY_BYTES[4 * row + col];
    }
  }
  return out;
}
function encryptBlocks(src) {
  const out = [];
  for (let i = 0; i < src.length; i += 16) out.push(encryptBlock16(src.slice(i, i + 16)));
  return Buffer.concat(out);
}

function cyclicXor(data, key) {
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
  return out;
}

// ---------- body TLV builders (match xhshow _build_body_structure) ----------
const XRAP_SDK_VERSION = 10300;
const DEFAULT_INTERACTION_TRACE = Buffer.from(
  '0002000200004700000000000001ffd9ffa8005c23fff1ffff001501ff90fff9000022fff2ffff' +
  '001501ffb800770061a5ffe3ffff002a01fffcffe70000f0ffe4ffff002a01ffd30000003e01' +
  'ffd40000003e01ffc8ffff005301ffbdfffa006901ffbefffb006901ffb1fff4007d01ffa6ff' +
  'ee009301ffa8ffef009301ff9effe900a801ff96ffe600be01ff97ffe600be01ff93ffe500d3' +
  '01ff92ffe500ea01ff92ffe4010501ff92ffe3011b01ff92ffe402d101ff93ffe502f201ff94' +
  'ffe6040501', 'hex');
const DEFAULT_ENVIRONMENT_SNAPSHOT = Buffer.from(
  '000000010000000000000000fffeffff00000000000000390001ffff00bc00000000006e0002' +
  '0001013400000000012f00000002011a00000000016100000000019f000000000247000000000279' +
  '0000000002b1', 'hex');

function fieldByte(tag, val = 0) { const b = Buffer.alloc(3); b.writeUInt16BE(tag, 0); b[2] = val & 0xff; return b; }
function fieldU32(tag, val) { const b = Buffer.alloc(6); b.writeUInt16BE(tag, 0); b.writeUInt32BE(val >>> 0, 2); return b; }
function fieldU64(tag, val) { const b = Buffer.alloc(10); b.writeUInt16BE(tag, 0); b.writeBigUInt64BE(BigInt(val), 2); return b; }
function fieldBlob(tag, data) { const h = Buffer.alloc(6); h.writeUInt16BE(tag, 0); h.writeUInt32BE(data.length, 2); return Buffer.concat([h, data]); }

function buildBodyStructure(api, data, opts = {}) {
  const bodyStr = typeof data === 'string' ? data : JSON.stringify(data);
  const hashInput = Buffer.from(api + bodyStr, 'utf8');
  const ts = opts.timestampMs != null ? Number(opts.timestampMs) : Date.now();
  const key = Buffer.from(opts.sessionKey || randAscii(16), 'ascii');
  if (key.length !== 16) throw new Error('session_key must be 16 bytes');
  const xorByte = opts.mask != null ? (opts.mask & 0xff) : (1 + Math.floor(Math.random() * 255));
  const randNonce = opts.nonce != null ? (opts.nonce >>> 0) : (Math.floor(Math.random() * 0x100000000) >>> 0);
  const trace = opts.interactionTrace || DEFAULT_INTERACTION_TRACE;
  const env = opts.environmentSnapshot || DEFAULT_ENVIRONMENT_SNAPSHOT;

  const parts = [];
  parts.push(fieldU64(0x03e8, ts));
  parts.push(fieldU32(0x03e9, randNonce));
  parts.push(fieldBlob(0x03ea, key));
  parts.push(fieldU32(0x03eb, xxh32(hashInput)));
  const boolTags = [];
  for (let t = 1051; t < 1066; t++) boolTags.push(t);
  boolTags.push(1070);
  for (let t = 1066; t < 1070; t++) boolTags.push(t);
  for (const t of boolTags) parts.push(fieldByte(t));
  parts.push(fieldU32(1100, 0));
  for (let t = 1071; t < 1074; t++) parts.push(fieldByte(t));
  parts.push(fieldU32(1075, 0x564));
  parts.push(fieldU32(1076, 0x2c));
  parts.push(fieldU64(1077, Math.max(0, ts - 0x434)));
  parts.push(fieldBlob(1078, trace));
  parts.push(fieldU32(1082, 0));
  parts.push(fieldU32(1084, 0));
  parts.push(fieldU32(1085, 0));
  parts.push(fieldU32(1086, 100));
  parts.push(fieldU64(1087, Math.max(0, ts - 0x2d7)));
  parts.push(fieldBlob(1088, env));
  parts.push(fieldU32(1090, 0));
  parts.push(fieldU32(1097, 0));
  parts.push(fieldU32(1092, 0x566));
  parts.push(fieldU32(1094, 0x519));
  parts.push(fieldU64(1095, Math.max(0, ts - 0x218c)));
  parts.push(fieldU32(1093, 0));
  parts.push(fieldByte(1096));
  parts.push(fieldBlob(1091, Buffer.from([0, 0, 0xff, 0xff])));
  for (let t = 1151; t < 1157; t++) parts.push(fieldByte(t));
  const buf = Buffer.concat(parts);
  // first 16 bytes cleartext, rest XOR xorByte
  const out = Buffer.from(buf);
  for (let i = 16; i < out.length; i++) out[i] = out[i] ^ xorByte;
  return out;
}

function randAscii(n, charset = 'abcdefghijklmnopqrstuvwxyz0123456789') {
  let s = '';
  for (let i = 0; i < n; i++) s += charset[Math.floor(Math.random() * charset.length)];
  return s;
}

function compressBody(raw, mtime) {
  const gz = zlib.gzipSync(raw, { level: 6 });
  const out = Buffer.from(gz);
  if (mtime != null && out.length >= 8) out.writeUInt32LE(mtime >>> 0, 4);
  if (out.length >= 10) out[9] = 0x03; // OS byte -> match browser runtime
  return out;
}

function packEnvelope(compressed, opts = {}) {
  const key = Buffer.from(opts.encryptionKey || randAscii(16), 'ascii');
  if (key.length !== 16) throw new Error('encryption_key must be 16 bytes');
  const salt = Buffer.from(opts.salt != null ? opts.salt : randAscii([4, 5, 6][Math.floor(Math.random() * 3)]), 'ascii');
  const xored = cyclicXor(compressed, key);
  const cipherBlocks = encryptBlocks(xored);
  const origLen = Buffer.alloc(4); origLen.writeUInt32BE(compressed.length, 0);
  const cipherBody = Buffer.concat([cipherBlocks, origLen]);
  const encKeyLen = Buffer.alloc(4); encKeyLen.writeUInt32BE(16, 0);
  const content = Buffer.concat([salt, encryptBlock16(key), encKeyLen, cipherBody]);
  const contentHash = xxh32(content);
  const encTime = opts.encTime != null ? opts.encTime : (60 + Math.floor(Math.random() * 181));
  const protocolVersion = opts.protocolVersion != null ? opts.protocolVersion : XRAP_SDK_VERSION;
  const header = Buffer.alloc(36);
  header[0] = 0x07; header[1] = 0x24; header[2] = 0x01; header[3] = salt.length;
  header.writeUInt32BE(1, 4);
  header.writeUInt32BE(20, 8);
  header.writeUInt32BE(cipherBody.length, 12);
  header.writeUInt32BE(contentHash >>> 0, 16);
  header.writeUInt32BE(protocolVersion, 20);
  header.writeUInt32BE(encTime, 24);
  // bytes 28..36 zero
  return Buffer.concat([header, content]).toString('base64');
}

/** Full offline x-rap-param generator (pure JS port; validated envelope+xxh32). */
function xRapParam(api, data, opts = {}) {
  const raw = buildBodyStructure(api, data, {
    sessionKey: opts.innerKey, timestampMs: opts.timestampMs,
    nonce: opts.bodyRand32, mask: opts.mask,
    interactionTrace: opts.tracePayload, environmentSnapshot: opts.envPayload,
  });
  const compressed = compressBody(raw, opts.gzipMtime);
  return packEnvelope(compressed, {
    encryptionKey: opts.aesKey, salt: opts.randomString,
    encTime: opts.bodyEncryTime, protocolVersion: opts.sdkVersion != null ? opts.sdkVersion : XRAP_SDK_VERSION,
  });
}

function decodeEnvelope(b64) {
  const buf = Buffer.from(b64, 'base64');
  const magic = [buf[0], buf[1], buf[2]];
  const saltLen = buf[3];
  const const1 = buf.readUInt32BE(4);
  const const2 = buf.readUInt32BE(8);
  const cipherBodyLen = buf.readUInt32BE(12);
  const contentHash = buf.readUInt32BE(16) >>> 0;
  const protocolVersion = buf.readUInt32BE(20);
  const encTime = buf.readUInt32BE(24);
  const zero8 = buf.slice(28, 36);
  let o = 36;
  const salt = buf.slice(o, o + saltLen); o += saltLen;
  const sessionKeyEnc = buf.slice(o, o + 16); o += 16;
  const sessionKeyLen = buf.readUInt32BE(o); o += 4;
  const cipherBody = buf.slice(o);
  const content = buf.slice(36);
  return {
    total: buf.length, magic, saltLen, const1, const2, cipherBodyLen,
    contentHash, protocolVersion, encTime, zero8: zero8.toString('hex'),
    salt: salt.toString('latin1'), sessionKeyEnc: sessionKeyEnc.toString('hex'),
    sessionKeyLen, origGzipLen: cipherBody.readUInt32BE(cipherBody.length - 4),
    cipherBlocksLen: cipherBody.length - 4,
    contentHashOK: xxh32(content) === contentHash,
  };
}

module.exports = { xxh32, encryptBlock16, encryptBlocks, cyclicXor, decodeEnvelope, xRapParam, buildBodyStructure, packEnvelope, compressBody, SBOX, ROUND_KEYS, XRAP_SDK_VERSION };
