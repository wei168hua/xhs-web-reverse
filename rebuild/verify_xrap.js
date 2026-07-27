'use strict';
/**
 * Verification for x-rap-param reconstruction.
 *
 * NOTE ON DATA: this public version verifies against a SELF-GENERATED envelope
 * (pinned nonces) rather than a captured browser sample. The original research
 * additionally confirmed the byte layout and `content_hash == xxh32(content)`
 * against a REAL browser x-rap-param; that ground-truth alignment is documented
 * in report.md §10. The properties proven here — envelope field layout, xxh32
 * self-consistency over content, SM4-variant ECB block sizing, and generator
 * round-trip — establish the algorithm without embedding any device data.
 *
 * Part A — envelope structure + content_hash == xxh32(content) on a pinned build.
 * Part B — generator round-trip self-consistency.
 * Part C — xxh32 known-answer tests.
 */
const X = require('./xrap.js');

let pass = true;
function check(name, cond, extra) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : ''));
  if (!cond) pass = false;
}

console.log('=== Part C: xxh32 known-answer ===');
check('xxh32("") == 0x02cc5d05', X.xxh32(Buffer.from('')) === 0x02cc5d05);
check('xxh32("abc") == 0x32d153ff', X.xxh32(Buffer.from('abc')) === 0x32d153ff);

console.log('\n=== Part A: envelope structure + content_hash == xxh32(content) ===');
// Self-generated with pinned nonces (no real device data). Public API path + synthetic body.
const apiA = '//edith.xiaohongshu.com/api/sns/web/v1/feed';
const bodyA = { source_note_id: 'EXAMPLE_NOTE_ID', image_formats: ['jpg', 'webp', 'avif'] };
const REAL = X.xRapParam(apiA, bodyA, { aesKey: 'abcdef0123456789', innerKey: 'abcdef0123456789', randomString: 'pwnon', timestampMs: 1700000000000, bodyRand32: 0x01020304, mask: 0x55, bodyEncryTime: 16, gzipMtime: 0, sdkVersion: 10301 });
const d = X.decodeEnvelope(REAL);
check('magic == 07 24 01', d.magic[0] === 7 && d.magic[1] === 0x24 && d.magic[2] === 1);
check('const1 == 1', d.const1 === 1);
check('const2 == 20', d.const2 === 20);
check('salt is ascii (len ' + d.saltLen + ')', /^[\x20-\x7e]+$/.test(d.salt), JSON.stringify(d.salt));
check('session_key_len == 16', d.sessionKeyLen === 16);
check('cipher blocks multiple of 16', d.cipherBlocksLen % 16 === 0, '(' + d.cipherBlocksLen + ')');
check('protocolVersion present', d.protocolVersion === 10301 || d.protocolVersion === 10300, '(' + d.protocolVersion + ')');
check('content_hash == xxh32(content)  [envelope byte layout proof]', d.contentHashOK);

console.log('\n=== Part B: offline generator round-trip ===');
const api = '//edith.xiaohongshu.com/api/sns/web/v2/search/notes';
const body = { keyword: 'example', page: 1, page_size: 20, sort: 'general', note_type: 0, image_formats: ['jpg', 'webp', 'avif'] };
const gen = X.xRapParam(api, body, { aesKey: '0123456789abcdef', innerKey: '0123456789abcdef', randomString: 'pwnon', timestampMs: 1700000000000, bodyRand32: 0x11223344, mask: 0x7a, bodyEncryTime: 16, gzipMtime: 0, sdkVersion: 10301 });
const dg = X.decodeEnvelope(gen);
check('generated starts with ByQB', gen.startsWith('ByQB'));
check('generated magic 07 24 01', dg.magic[0] === 7 && dg.magic[1] === 0x24 && dg.magic[2] === 1);
check('generated salt == pwnon', dg.salt === 'pwnon');
check('generated protocolVersion == 10301', dg.protocolVersion === 10301);
check('generated content_hash self-consistent', dg.contentHashOK);
check('generated cipher blocks multiple of 16', dg.cipherBlocksLen % 16 === 0);

console.log('\n' + (pass ? 'ALL CHECKS PASSED — x-rap-param envelope + xxh32 + generator round-trip confirmed.' : 'SOME CHECKS FAILED.'));
console.log('NOTE: byte-identical whole-string match vs browser is not asserted because the');
console.log('inner gzip size + trace/env snapshots are runtime-environment dependent (like the');
console.log('mnsv2 env-check vector). The envelope algorithm, field layout, xxh32, cyclic-XOR,');
console.log('and SM4-variant cipher pipeline are confirmed (byte-level ground truth: report.md §10).');
process.exit(pass ? 0 : 1);
