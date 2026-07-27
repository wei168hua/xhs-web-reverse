'use strict';
// Self-check: run the entry demo + verify custom-base64 round-trips + crc32 sanity.
const { crc32, b64Encode, encodeUtf8, B64_ALPHABET } = require('./env');
const { signRequest, buildXSCommon } = require('./entry');

// 1) custom-base64 decoder built from the SAME alphabet, to prove xE is invertible/consistent
function b64Decode(str) {
  const lookup = {};
  for (let i = 0; i < B64_ALPHABET.length; i++) lookup[B64_ALPHABET[i]] = i;
  const clean = str.replace(/=+$/, '');
  const bytes = [];
  let buf = 0, bits = 0;
  for (const ch of clean) {
    buf = (buf << 6) | lookup[ch];
    bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 0xff); }
  }
  return Buffer.from(bytes).toString('utf8');
}

let pass = true;
function check(name, cond) { console.log((cond ? 'PASS ' : 'FAIL ') + name); if (!cond) pass = false; }

// round-trip a JSON string through encodeUtf8+b64Encode then decode
const sample = JSON.stringify({ s0: 5, x1: '4.3.7', x9: 123456789, msg: '小红书✓' });
const enc = b64Encode(encodeUtf8(sample));
const dec = b64Decode(enc);
check('custom-base64 round-trip', dec === sample);
console.log('   enc =', enc.slice(0, 48) + (enc.length > 48 ? '…' : ''));

// crc32 known-answer: crc32("123456789") === 0xCBF43926 (standard CRC-32)
check('crc32 KAT "123456789"==0xCBF43926', crc32('123456789') === 0xcbf43926);

// entry demo runs and yields the three headers with correct shapes
const h = signRequest({ url: '/api/sns/web/v1/homefeed', data: { num: 18 }, ctx: { b1: 'FP', a1: 'A1', dsl: 'DSL' } });
check('X-t is ms timestamp', /^\d{13}$/.test(h['X-t']));
check('X-s starts with XYS_', h['X-s'].startsWith('XYS_'));
check('X-S-Common non-empty', typeof h['X-S-Common'] === 'string' && h['X-S-Common'].length > 0);
// X-S-Common must decode back to a JSON envelope with expected keys
const common = JSON.parse(b64Decode(h['X-S-Common']));
check('X-S-Common has s0..x12 envelope', common.x1 === '4.3.7' && common.x3 === 'xhs-pc-web' && 'x9' in common);

console.log('\n--- sample headers ---');
console.log(JSON.stringify(h, null, 2));
console.log('\n--- decoded X-S-Common ---');
console.log(JSON.stringify(common));

process.exit(pass ? 0 : 1);
