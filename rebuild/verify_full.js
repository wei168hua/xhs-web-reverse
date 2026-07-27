'use strict';
/**
 * Verification for the auxiliary generator suite + full header assembly.
 *
 * Covers the pieces added to close the gap vs xhshow's public API:
 *   - generators.js : a1 / web_id / trace ids / xy-direction / url helpers
 *   - session.js    : SessionManager stateful counters
 *   - entry.signHeaders : full browser-equivalent header set
 *
 * These are pure/local; no network. xy-direction & trace ids are cosmetic
 * (not part of the x-s/x-rap signature), so we assert well-formedness and
 * determinism-of-hash rather than server acceptance.
 */
const gen = require('./generators');
const { SessionManager } = require('./session');
const { signHeaders } = require('./entry');
const M = require('./mnsv2');

let pass = true;
function check(name, cond, extra) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : ''));
  if (!cond) pass = false;
}

console.log('=== generators ===');
// crc32 KAT (used by a1 + x-s-common x9)
check('crc32("123456789")==0xCBF43926', gen.crc32('123456789') === 0xcbf43926);
const a1 = gen.generateA1();
check('a1 length == 52', a1.length === 52, a1);
check('a1 charset ok', /^[0-9a-z]+$/.test(a1));
const webId = gen.generateWebId(a1);
check('web_id == md5(a1) (32 hex)', /^[0-9a-f]{32}$/.test(webId) && webId === gen.md5hex(a1));
check('b3 trace id 16 hex', /^[0-9a-f]{16}$/.test(gen.getB3TraceId()));
const xray = gen.getXrayTraceId(1700000000000, 12345);
check('xray trace id 32 hex', /^[0-9a-f]{32}$/.test(xray), xray);
check('xray deterministic head for fixed ts+seq', gen.getXrayTraceId(1700000000000, 12345).slice(0, 16) === xray.slice(0, 16));
check('search_id is base36', /^[0-9a-z]+$/.test(gen.getSearchId()));
check('search request_id "{n}-{ts}"', /^\d+-\d{13}$/.test(gen.getSearchRequestId()));

// xy-direction sharding: deterministic per user_id, in [1,100]
const sk1 = gen.getShardingKey('628e47470000000021029eef');
const sk2 = gen.getShardingKey('628e47470000000021029eef');
check('sharding key deterministic per user_id', sk1 === sk2, String(sk1));
check('sharding key in [1,100]', sk1 >= 1 && sk1 <= 100);

// url helpers
check('extractUri strips host+query', gen.extractUri('https://edith.xiaohongshu.com/api/x?y=1') === '/api/x');
check('buildUrl only encodes = as %3D', gen.buildUrl('/api/p', { k: 'v=1', t: ['a', 'b'] }) === '/api/p?k=v%3D1&t=a,b');

console.log('\n=== SessionManager ===');
const s = new SessionManager({ pageLoadTimestamp: 1700000000000, sequenceValue: 15, windowPropsLength: 1000 });
const st1 = s.getCurrentState('/api/sns/web/v1/homefeed{"num":18}');
const st2 = s.getCurrentState('/api/sns/web/v1/homefeed{"num":18}');
check('pageLoadTs fixed across calls', st1.pageLoadTs === 1700000000000 && st2.pageLoadTs === 1700000000000);
check('sequence monotonic non-decreasing', st2.sequence >= st1.sequence && st2.sequence >= 15);
check('window_props monotonic increasing', st2.windowPropsLength > st1.windowPropsLength);
check('uri_length = byteLen(content)', st1.uriLength === Buffer.byteLength('/api/sns/web/v1/homefeed{"num":18}'));

console.log('\n=== full header set (signHeaders) ===');
const session = new SessionManager({ pageLoadTimestamp: 1700000000000 });
const h = signHeaders({
  url: '/api/sns/web/v1/homefeed', method: 'POST', data: { num: 18 }, session, xRap: true, userId: '628e47470000000021029eef',
  ctx: { a1: 'demo00000000000000000000000000000000000000000000a1xx', b1: 'FP', dsl: 'DSL' },
});
check('has x-s (XYS_)', h['x-s'].startsWith('XYS_'));
check('has x-t (13-digit)', /^\d{13}$/.test(h['x-t']));
check('has x-s-common', typeof h['x-s-common'] === 'string' && h['x-s-common'].length > 0);
check('has x-b3-traceid (16 hex)', /^[0-9a-f]{16}$/.test(h['x-b3-traceid']));
check('has x-xray-traceid (32 hex)', /^[0-9a-f]{32}$/.test(h['x-xray-traceid']));
check('x-mns == unload (default, matches live)', h['x-mns'] === 'unload');
check('xy-direction numeric [1..100]', /^\d+$/.test(h['xy-direction']) && +h['xy-direction'] >= 1 && +h['xy-direction'] <= 100);
check('has x-rap-param (ByQB)', h['x-rap-param'] && h['x-rap-param'].startsWith('ByQB'));

// The embedded mnsv2 x3 must decode to the session-driven fields
const inner = JSON.parse(Buffer.from(M.b64DecodeAlpha(h['x-s'].slice(4), M.XS_B64)).toString('utf8'));
const dec = M.decodeMnsv2(inner.x3);
check('x-s embeds mns0301_ x3', inner.x3.startsWith('mns0301_'));
check('x3 pageLoadTs == session pageLoadTs', dec.pageLoadTs === 1700000000000, String(dec.pageLoadTs));
check('x3 a1 == ctx a1', dec.a1 === 'demo00000000000000000000000000000000000000000000a1xx');

console.log('\n' + (pass ? 'ALL CHECKS PASSED — generator suite + session + full header set complete.' : 'SOME CHECKS FAILED.'));
process.exit(pass ? 0 : 1);
