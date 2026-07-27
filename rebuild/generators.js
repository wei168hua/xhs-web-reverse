'use strict';
/**
 * XHS Web — auxiliary generators (a1 / web_id / search ids / trace ids /
 * xy-direction sharding / URL helpers).
 *
 * JS port of the pieces that the earlier rebuild left out, matching the
 * open-source `xhshow` (github Cloxl/xhshow) reference. These are the
 * "account/search parameter" + "trace id" + "xy-direction" utilities that
 * accompany the signature headers. Pure functions, no network.
 *
 * NOTE ON RANDOMNESS: XHS uses these as cosmetic/telemetry values (trace ids,
 * sharding). They do NOT feed the x-s / x-rap-param signature, so exact
 * reproduction is not required for server acceptance — only well-formedness.
 */
const crypto = require('crypto');

const HEX_CHARS = 'abcdef0123456789';
const A1_CHARSET = 'abcdefghijklmnopqrstuvwxyz1234567890';
const BASE36 = '0123456789abcdefghijklmnopqrstuvwxyz';
const MASK32 = 0xffffffff;

function md5hex(s) { return crypto.createHash('md5').update(s, 'utf8').digest('hex'); }
function randInt(min, max) { return min + Math.floor(Math.random() * (max - min + 1)); }
function randChoice(str) { return str[Math.floor(Math.random() * str.length)]; }

// ---- CRC32 (standard reflected poly 0xEDB88320), JS `>>>0` unsigned ----
const CRC_TABLE = (() => {
  const a = 0xedb88320, t = [];
  for (let u = 0; u < 256; u++) { let r = u; for (let c = 8; c--;) r = 1 & r ? (r >>> 1) ^ a : r >>> 1; t[u] = r >>> 0; }
  return t;
})();
function crc32(str) {
  let c = -1;
  for (let i = 0; i < str.length; i++) c = CRC_TABLE[(255 & c) ^ str.charCodeAt(i)] ^ (c >>> 8);
  return (-1 ^ c) >>> 0;
}

// ---- a1 cookie (52 chars): tsHex + 30 rand + "5"+"0"+"000" + crc32 ----
function generateA1() {
  const tsHex = Date.now().toString(16);
  let randomStr = '';
  for (let i = 0; i < 30; i++) randomStr += randChoice(A1_CHARSET);
  const aPart = tsHex + randomStr + '5' + '0' + '000';
  const crc = crc32(aPart) >>> 0;
  return (aPart + String(crc)).slice(0, 52);
}

// ---- web_id = md5(a1) ----
function generateWebId(a1) { return md5hex(a1); }

// ---- b3 trace id: 16 random hex chars ----
function getB3TraceId() {
  let s = '';
  for (let i = 0; i < 16; i++) s += randChoice(HEX_CHARS);
  return s;
}

// ---- xray trace id: 16 (timestamp<<23 | seq) hex + 16 random hex ----
function getXrayTraceId(timestampMs, seq) {
  if (timestampMs == null) timestampMs = Date.now();
  if (seq == null) seq = randInt(0, 8388607); // 2^23-1
  // (ts << 23) | seq  — use BigInt to avoid 32-bit overflow, pad to 16 hex
  const part1 = ((BigInt(timestampMs) << 23n) | BigInt(seq)).toString(16).padStart(16, '0');
  let part2 = '';
  for (let i = 0; i < 16; i++) part2 += randChoice(HEX_CHARS);
  return part1 + part2;
}

// ---- search_id: base36( (tsMs << 64) + rand ) ----
function intToBase36(bi) {
  if (bi === 0n) return '0';
  let s = '';
  while (bi > 0n) { s = BASE36[Number(bi % 36n)] + s; bi /= 36n; }
  return s;
}
function getSearchId() {
  const tsMs = BigInt(Date.now());
  const randPart = BigInt(Math.ceil(0x7ffffffe * Math.random()));
  return intToBase36((tsMs << 64n) + randPart);
}

// ---- search request_id: "{rand}-{tsMs}" ----
function getSearchRequestId() {
  const tsMs = Date.now();
  const randPart = Math.ceil(0x7ffffffe * Math.random());
  return randPart + '-' + tsMs;
}

// ---- xy-direction sharding key: MurmurHash3-x86-32 variant (%100 + 1) ----
const _C1 = 0xcc9e2d51, _C2 = 0x1b873593;
function _imul(a, b) { return Math.imul(a >>> 0, b >>> 0) | 0; }
function _rotl32(x, r) { x >>>= 0; return ((x << r) | (x >>> (32 - r))) >>> 0; }
function getShardingKey(userId) {
  if (userId == null) return randInt(10, 100);
  const data = Buffer.from(userId, 'utf8');
  const length = data.length;
  let r = 151488;
  const blocks = Math.floor(length / 4);
  for (let o = 0; o < blocks; o++) {
    const i = 4 * o;
    let u = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) >>> 0;
    u = _imul(u, _C1); u = _rotl32(u, 15); u = _imul(u, _C2);
    r = (r ^ u) | 0;
    r = _rotl32(r, 13);
    r = (_imul(r, 5) + 0xe6546b64) | 0;
  }
  const s = 4 * blocks;
  let c = 0;
  const rem = length % 4;
  if (rem >= 3) c ^= data[s + 2] << 16;
  if (rem >= 2) c ^= data[s + 1] << 8;
  if (rem >= 1) { c ^= data[s]; c = _imul(c, _C1); c = _rotl32(c, 15); c = _imul(c, _C2); r = (r ^ c) | 0; }
  r = (r ^ length) >>> 0;
  r ^= r >>> 16; r >>>= 0;
  r = _imul(r, 0x85ebca6b) >>> 0;
  r ^= r >>> 13; r >>>= 0;
  r = _imul(r, 0xc2b2ae35) >>> 0;
  r ^= r >>> 16; r >>>= 0;
  return (r % 100) + 1;
}

// ---- URL helpers (XHS-specific: only '=' -> %3D) ----
function extractUri(url) {
  if (!url) throw new Error('URL must be non-empty');
  url = url.trim();
  let path = url;
  try {
    if (/^https?:/.test(url)) path = new URL(url).pathname;
    else { const q = url.indexOf('?'); path = q >= 0 ? url.slice(0, q) : url; }
  } catch (_) {}
  if (!path || path === '/') throw new Error('Cannot extract URI path: ' + url);
  return path;
}
function buildUrl(baseUrl, params) {
  if (!baseUrl) throw new Error('base_url must be non-empty');
  if (!params || Object.keys(params).length === 0) return baseUrl;
  const parts = [];
  for (const [k, v] of Object.entries(params)) {
    let val;
    if (Array.isArray(v)) val = v.map(String).join(',');
    else if (v != null) val = String(v);
    else val = '';
    parts.push(k + '=' + val.replace(/=/g, '%3D'));
  }
  const qs = parts.join('&');
  const sep = !baseUrl.includes('?') ? '?' : (baseUrl.endsWith('?') || baseUrl.endsWith('&') ? '' : '&');
  return baseUrl + sep + qs;
}

module.exports = {
  crc32, md5hex,
  generateA1, generateWebId,
  getB3TraceId, getXrayTraceId,
  getSearchId, getSearchRequestId,
  getShardingKey,
  extractUri, buildUrl,
};
