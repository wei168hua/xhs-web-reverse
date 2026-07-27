'use strict';
/**
 * Verification for the reversed X-s core (window.mnsv2 / mns0301_).
 *
 * NOTE ON DATA: this public version uses SYNTHETIC placeholder inputs (a fake
 * a1, a round timestamp, and arbitrary content). The original research validated
 * the reconstruction against REAL browser mnsv2 outputs and proved byte-identical
 * equivalence in both directions; that alignment is documented in report.md §9.
 * Here we prove the same properties self-consistently:
 *   - encode -> decode round-trips every structured field exactly, and
 *   - decode -> re-encode reproduces the byte-identical mns0301_ string.
 * This demonstrates the algorithm is correct and fully invertible without
 * embedding any device-specific data.
 */
const M = require('./mnsv2.js');

let pass = true;
function check(name, cond, extra) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : ''));
  if (!cond) pass = false;
}

// Synthetic, fully-pinned inputs (no real device data).
const A1 = 'demo00000000000000000000000000000000000000000000a1xx'; // 52 chars, clearly fake
const LOADTS = 1700000000000;
const crypto = require('crypto');
const md5hex = (s) => crypto.createHash('md5').update(s, 'utf8').digest('hex');

const cases = [
  { label: 'A', content: '/api/sns/web/v1/test', seed: 0x11223344, ts: 1700000005000, seq: 20, win: 1100 },
  { label: 'B', content: '/api/sns/web/v2/example_endpoint', seed: 0xdeadbeef, ts: 1700000009000, seq: 37, win: 1200 },
];

console.log('=== ENCODE -> DECODE round-trip (byte-exact fields) ===');
for (const c of cases) {
  const u = md5hex(c.content); // GET: md5Path == dValue == MD5(content)
  const x3 = M.mnsv2(c.content, {
    dValue: u, md5Path: u, a1: A1, appId: 'xhs-pc-web',
    seed: c.seed, timestampMs: c.ts, pageLoadTs: LOADTS,
    sequence: c.seq, windowPropsLength: c.win,
  });
  check(`[${c.label}] output has mns0301_ prefix`, x3.startsWith('mns0301_'));
  const d = M.decodeMnsv2(x3);
  check(`[${c.label}] version == 121,104,96,41`, d.version.join(',') === '121,104,96,41');
  check(`[${c.label}] uri_length == byteLen(content)`, d.uriLength === Buffer.byteLength(c.content), `(${d.uriLength})`);
  check(`[${c.label}] md5Head == MD5(content)[0:8]`, d.md5Head === u.slice(0, 16), `(${d.md5Head})`);
  check(`[${c.label}] a1 round-trips`, d.a1 === A1);
  check(`[${c.label}] appId == xhs-pc-web`, d.appId === 'xhs-pc-web');
  check(`[${c.label}] pageLoadTs round-trips`, d.pageLoadTs === LOADTS, `(${d.pageLoadTs})`);
  check(`[${c.label}] sequence round-trips`, d.sequence === c.seq);
  check(`[${c.label}] a3Prefix == 2,97,51,16`, d.a3Prefix.join(',') === '2,97,51,16');

  // recompute custom_hash_v2 from decoded fields -> must match a3 tail
  const tsBytes = []; let t = BigInt(d.timestampMs); for (let i = 0; i < 8; i++) { tsBytes.push(Number(t & 0xffn)); t >>= 8n; }
  const md5pb = []; for (let i = 0; i < 32; i += 2) md5pb.push(parseInt(u.substr(i, 2), 16));
  const a3 = M.customHashV2(tsBytes.concat(md5pb)).map(b => b ^ d.seedByte);
  check(`[${c.label}] custom_hash_v2 reproduces a3 tail`, Buffer.from(a3).toString('hex') === d.a3Tail);
}

console.log('\n=== DECODE -> RE-ENCODE (byte-identical string) ===');
for (const c of cases) {
  const u = md5hex(c.content);
  const x3 = M.mnsv2(c.content, { dValue: u, md5Path: u, a1: A1, appId: 'xhs-pc-web', seed: c.seed, timestampMs: c.ts, pageLoadTs: LOADTS, sequence: c.seq, windowPropsLength: c.win });
  const d = M.decodeMnsv2(x3);
  const reenc = M.mnsv2(c.content, { dValue: u, md5Path: u, a1: d.a1, appId: 'xhs-pc-web', seed: d.seed, timestampMs: d.timestampMs, pageLoadTs: d.pageLoadTs, sequence: d.sequence, windowPropsLength: d.windowPropsLength });
  check(`[${c.label}] re-encode == original`, reenc === x3);
}

console.log('\n=== Primitive sanity ===');
const h = M.customHashV2([0, 0, 0, 0, 0, 0, 0, 0]);
check('custom_hash_v2 outputs 16 bytes', h.length === 16);
check('HEX_KEY is 144 bytes', Buffer.from(M.HEX_KEY, 'hex').length === 144);
const rt = M.xorKey(M.xorKey(Buffer.from('deadbeef'.repeat(36), 'hex')));
check('xorKey involutive', rt.toString('hex') === 'deadbeef'.repeat(36));
const xs = M.buildXS('/api/sns/web/v1/homefeed', { a1: A1, x4: 'object' });
check('buildXS starts with XYS_', xs.startsWith('XYS_'));
check('buildXS embeds mns0301_ x3', Buffer.from(M.b64DecodeAlpha(xs.slice(4), M.XS_B64)).toString('utf8').includes('mns0301_'));

console.log('\n' + (pass ? 'ALL CHECKS PASSED — offline mnsv2 encode/decode fully consistent & invertible.' : 'SOME CHECKS FAILED.'));
process.exit(pass ? 0 : 1);
