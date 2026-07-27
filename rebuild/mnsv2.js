'use strict';
/**
 * XHS Web `x-s` core (window.mnsv2 / "mns0301_") — full offline reconstruction.
 *
 * This is the "last mile" the earlier session could not reach. It was recovered
 * in this session by Live differential analysis of window.mnsv2 in an ATTACHED
 * (TCP 9222) browser, cross-referenced against the open-source `xhshow` model,
 * and then VERIFIED byte-for-byte by decoding real browser mnsv2 outputs.
 *
 * KEY CORRECTION vs the prior report: the core is NOT AES. The `mns0301_`
 * payload is a fixed 144-byte structured buffer XORed with a hard-coded
 * 144-byte key (HEX_KEY) and then custom-base64 encoded (X3 alphabet). The
 * per-call non-determinism comes from an internal seed + timestamp + sequence
 * + a `custom_hash_v2` over (timestamp_bytes ++ md5_path_bytes), NOT from a
 * block cipher. There is no avalanche, which is why single-byte input changes
 * only move a few output bytes.
 *
 * Layout of the 144-byte plaintext (little-endian ints), all VERIFIED against
 * live browser output for c="/api/sns/web/v1/test":
 *   [0:4]    VERSION_BYTES = [121,104,96,41]
 *   [4:8]    seed (random u32); seedByte = seed & 0xFF
 *   [8:16]   timestamp_ms (Date.now(), LE 8 bytes)
 *   [16:24]  page_load_ts / effective_ts (LE 8 bytes; == `loadts` cookie)
 *   [24:28]  sequence (LE u32, small monotonic-ish)
 *   [28:32]  window_props_length (LE u32)
 *   [32:36]  uri_length = len(utf8(content_string)) (LE u32)
 *   [36:44]  MD5(content)[0:8] XOR seedByte      <-- the only input-derived field
 *   [44]     a1_len (=52)
 *   [45:97]  a1 cookie bytes (padded/truncated to 52)
 *   [97]     app_len (=10)
 *   [98:108] app_id "xhs-pc-web"
 *   [108:124] part11 = [1, seedByte^ENV_TABLE[0], ENV_TABLE[i]^ENV_CHECKS[i] (i=1..14)]
 *   [124:128] A3_PREFIX = [2,97,51,16]
 *   [128:144] custom_hash_v2(ts_bytes ++ md5_path_bytes) XOR seedByte
 * Then: XOR whole buffer with HEX_KEY (144B) -> base64 (X3 alphabet) -> "mns0301_"+that.
 * X-s = "XYS_" + customB64(JSON({x0,x1,x2,x3:"mns0301_"+...,x4})).
 */
const crypto = require('crypto');

const STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const X3_B64  = 'MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G';
const XS_B64  = 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5'; // x-s / x-s-common alphabet

const HEX_KEY = '71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277516db7116035439730fa61e9822a0eca7bff72d8';
const KEY = Buffer.from(HEX_KEY, 'hex');

const VERSION_BYTES = [121, 104, 96, 41];
const A3_PREFIX = [2, 97, 51, 16];
const ENV_TABLE = [115, 248, 83, 102, 103, 201, 181, 131, 99, 94, 4, 68, 250, 132, 21];
// Environment-detection vector. xhshow ships [0,1,18,1,0,0,0,0,0,0,3,0,0,0,0].
// The live 6.34.4 browser in this session reported idx5=1, idx7=2 (runtime env
// flags). Using the browser-observed vector makes the forward rebuild
// byte-identical to window.mnsv2. These flags encode environment signals and
// legitimately vary per browser/session.
const ENV_CHECKS_DEFAULT = [0, 1, 18, 1, 0, 1, 0, 2, 0, 0, 3, 0, 0, 0, 0];
const HASH_IV = [1831565813, 461845907, 2246822507, 3266489909];
const A1_LENGTH = 52;
const APP_ID_LENGTH = 10;
const PAYLOAD_LENGTH = 144;

function transAlpha(str, from, to) {
  const m = {};
  for (let i = 0; i < from.length; i++) m[from[i]] = to[i];
  let out = '';
  for (const ch of str) out += m[ch] !== undefined ? m[ch] : ch;
  return out;
}
function b64EncodeAlpha(buf, alpha) {
  return transAlpha(Buffer.from(buf).toString('base64'), STD_B64, alpha);
}
function b64DecodeAlpha(str, alpha) {
  return Buffer.from(transAlpha(str, alpha, STD_B64), 'base64');
}

function md5hex(str) { return crypto.createHash('md5').update(str, 'utf8').digest('hex'); }
function md5bytes(str) { return crypto.createHash('md5').update(str, 'utf8').digest(); }

function leBytes(val, len) {
  // val may exceed 32 bits (timestamps); use BigInt for safety.
  const out = [];
  let v = BigInt(val);
  for (let i = 0; i < len; i++) { out.push(Number(v & 0xffn)); v >>= 8n; }
  return out;
}

function rotl(v, n) { return (((v << n) | (v >>> (32 - n))) >>> 0); }

function customHashV2(inputBytes) {
  let [s0, s1, s2, s3] = HASH_IV;
  const L = inputBytes.length;
  s0 = (s0 ^ L) >>> 0;
  s1 = (s1 ^ (L << 8)) >>> 0;
  s2 = (s2 ^ (L << 16)) >>> 0;
  s3 = (s3 ^ (L << 24)) >>> 0;
  const buf = Buffer.from(inputBytes);
  for (let i = 0; i < Math.floor(L / 8); i++) {
    const v0 = buf.readUInt32LE(i * 8);
    const v1 = buf.readUInt32LE(i * 8 + 4);
    s0 = rotl(((((s0 + v0) >>> 0) ^ s2) >>> 0), 7);
    s1 = rotl(((((v0 ^ s1) >>> 0) + s3) >>> 0), 11);
    s2 = rotl(((((s2 + v1) >>> 0) ^ s0) >>> 0), 13);
    s3 = rotl(((((s3 ^ v1) >>> 0) + s1) >>> 0), 17);
  }
  const t0 = (s0 ^ L) >>> 0;
  const t1 = (s1 ^ t0) >>> 0;
  const t2 = (s2 + t1) >>> 0;
  const t3 = (s3 ^ t2) >>> 0;
  const r0 = rotl(t0, 9), r1 = rotl(t1, 13), r2 = rotl(t2, 17), r3 = rotl(t3, 19);
  s0 = (r0 + r2) >>> 0;
  s1 = (r1 ^ r3) >>> 0;
  s2 = (r2 + s0) >>> 0;
  s3 = (r3 ^ s1) >>> 0;
  const out = [];
  for (let s of [s0, s1, s2, s3]) { for (let k = 0; k < 4; k++) { out.push(s & 0xff); s = s >>> 8; } }
  return out;
}

/**
 * Build the 144-byte plaintext payload (before XOR key).
 * opts: { content, md5Path, a1, appId, timestampMs, pageLoadTs, seed, sequence, windowPropsLength }
 */
function buildPayload(opts) {
  const content = opts.content || '';
  const appId = opts.appId || 'xhs-pc-web';
  const a1 = opts.a1 || '';
  const timestampMs = opts.timestampMs != null ? opts.timestampMs : Date.now();
  const pageLoadTs = opts.pageLoadTs != null ? opts.pageLoadTs : (timestampMs - 20000);
  const seed = opts.seed != null ? opts.seed : (Math.floor(Math.random() * 0xffffffff) >>> 0);
  const seedByte = seed & 0xff;
  const sequence = opts.sequence != null ? opts.sequence : (15 + Math.floor(Math.random() * 35));
  const windowPropsLength = opts.windowPropsLength != null ? opts.windowPropsLength : (1000 + Math.floor(Math.random() * 200));
  const dValue = opts.dValue || md5hex(content);      // MD5(content) hex
  const md5Path = opts.md5Path || dValue;             // GET: == dValue

  const payload = [];
  payload.push(...VERSION_BYTES);                     // [0:4]
  payload.push(...leBytes(seed, 4));                  // [4:8]
  const tsBytes = leBytes(timestampMs, 8);
  payload.push(...tsBytes);                           // [8:16]
  payload.push(...leBytes(pageLoadTs, 8));            // [16:24]
  payload.push(...leBytes(sequence, 4));              // [24:28]
  payload.push(...leBytes(windowPropsLength, 4));     // [28:32]
  payload.push(...leBytes(Buffer.byteLength(content, 'utf8'), 4)); // [32:36]

  const dBytes = Buffer.from(dValue, 'hex');
  for (let i = 0; i < 8; i++) payload.push(dBytes[i] ^ seedByte); // [36:44]

  let a1Bytes = Buffer.from(a1, 'utf8').slice(0, A1_LENGTH);
  a1Bytes = Buffer.concat([a1Bytes, Buffer.alloc(A1_LENGTH - a1Bytes.length)]);
  payload.push(a1Bytes.length);                       // [44]
  payload.push(...a1Bytes);                           // [45:97]

  let appBytes = Buffer.from(appId, 'utf8').slice(0, APP_ID_LENGTH);
  appBytes = Buffer.concat([appBytes, Buffer.alloc(APP_ID_LENGTH - appBytes.length)]);
  payload.push(appBytes.length);                      // [97]
  payload.push(...appBytes);                          // [98:108]

  const part11 = [1, seedByte ^ ENV_TABLE[0]];
  for (let i = 1; i < 15; i++) part11.push(ENV_TABLE[i] ^ ENV_CHECKS_DEFAULT[i]);
  payload.push(...part11);                            // [108:124]

  const md5PathBytes = [];
  for (let i = 0; i < 32; i += 2) md5PathBytes.push(parseInt(md5Path.substr(i, 2), 16));
  const a3 = customHashV2(tsBytes.concat(md5PathBytes));
  payload.push(...A3_PREFIX);                         // [124:128]
  for (let i = 0; i < 16; i++) payload.push(a3[i] ^ seedByte); // [128:144]

  return payload;
}

function xorKey(bytes) {
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = (bytes[i] ^ (i < KEY.length ? KEY[i] : 0)) & 0xff;
  return out;
}

/** Produce the "mns0301_..." x3 value (equivalent to window.mnsv2 output). */
function mnsv2(content, opts = {}) {
  const payload = buildPayload(Object.assign({ content }, opts));
  const xored = xorKey(payload).slice(0, PAYLOAD_LENGTH);
  return 'mns0301_' + b64EncodeAlpha(xored, X3_B64);
}

/** Reverse a "mns0301_..." value back to the 144-byte plaintext + parsed fields. */
function decodeMnsv2(x3) {
  const body = x3.startsWith('mns0301_') ? x3.slice(8) : x3;
  const raw = b64DecodeAlpha(body, X3_B64);
  const p = xorKey(raw); // XOR is its own inverse
  const seed = p.readUInt32LE(4);
  const seedByte = seed & 0xff;
  const md5xor = [];
  for (let i = 0; i < 8; i++) md5xor.push(p[36 + i] ^ seedByte);
  const a1 = p.slice(45, 45 + p[44]).toString('latin1').replace(/\x00+$/, '');
  return {
    version: [...p.slice(0, 4)],
    seed, seedByte,
    timestampMs: Number(p.readBigUInt64LE(8)),
    pageLoadTs: Number(p.readBigUInt64LE(16)),
    sequence: p.readUInt32LE(24),
    windowPropsLength: p.readUInt32LE(28),
    uriLength: p.readUInt32LE(32),
    md5Head: Buffer.from(md5xor).toString('hex'),
    a1Len: p[44],
    a1,
    appId: p.slice(98, 108).toString('latin1'),
    part11: [...p.slice(108, 124)],
    a3Prefix: [...p.slice(124, 128)],
    a3Tail: p.slice(128, 144).toString('hex'),
    plaintextHex: p.toString('hex'),
  };
}

/** Full X-s builder: "XYS_" + custom-b64(JSON({x0,x1,x2,x3,x4})). */
function buildXS(content, opts = {}) {
  const x3 = mnsv2(content, opts);
  const S = {
    x0: opts.x0 || '4.3.7',
    x1: 'xhs-pc-web',
    x2: opts.platform || 'PC',
    x3,
    x4: opts.x4 != null ? opts.x4 : 'object',
  };
  return 'XYS_' + b64EncodeAlpha(Buffer.from(JSON.stringify(S), 'utf8'), XS_B64);
}

module.exports = {
  mnsv2, decodeMnsv2, buildXS, buildPayload, xorKey, customHashV2,
  b64EncodeAlpha, b64DecodeAlpha, md5hex, md5bytes,
  STD_B64, X3_B64, XS_B64, HEX_KEY, VERSION_BYTES, A3_PREFIX, ENV_TABLE, ENV_CHECKS_DEFAULT,
};
