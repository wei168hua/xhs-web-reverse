'use strict';
/**
 * XHS Web signing – deterministic primitives, verbatim-faithful reconstruction.
 * Source: fe-static.xhscdn.com/formula-static/xhs-pc-web/.../vendor-dynamic.ae665ebb.js
 * Extracted 2026-07-25. For personal research / understanding only.
 *
 * These three functions ARE the exact algorithms shipped by XHS (module exports
 * tb=crc32, lz=encodeUtf8, xE=b64Encode). The custom base64 alphabet is copied
 * byte-for-byte from the bundle.
 */

// ---- CRC32 (export `tb` / internal `w`) : standard reflected poly 0xEDB88320 ----
const CRC_TABLE = (function () {
  const a = 0xedb88320;
  const p = [];
  for (let u = 0; u < 256; u++) {
    let r = u;
    for (let c = 8; c--; ) r = 1 & r ? (r >>> 1) ^ a : r >>> 1;
    p[u] = r >>> 0;
  }
  return p;
})();

function crc32(e) {
  // Accepts a string or a byte array, exactly like the bundle's `w`.
  let c = -1;
  if (typeof e === 'string') {
    for (let r = 0; r < e.length; ++r)
      c = CRC_TABLE[(255 & c) ^ e.charCodeAt(r)] ^ (c >>> 8);
  } else {
    for (let r = 0; r < e.length; ++r)
      c = CRC_TABLE[(255 & c) ^ e[r]] ^ (c >>> 8);
  }
  return (-1 ^ c) >>> 0;
}

// ---- encodeUtf8 (export `lz`) : string -> array of UTF-8 byte values ----
function encodeUtf8(e) {
  const a = encodeURIComponent(e);
  const r = [];
  for (let c = 0; c < a.length; c++) {
    const u = a.charAt(c);
    if ('%' === u) {
      const p = parseInt(a.charAt(c + 1) + a.charAt(c + 2), 16);
      r.push(p);
      c += 2;
    } else {
      r.push(u.charCodeAt(0));
    }
  }
  return r;
}

// ---- b64Encode (export `xE`) : base64 over a byte array, CUSTOM alphabet ----
const B64_ALPHABET = 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5';
const B64 = B64_ALPHABET.split('');

function tripletToBase64(e) {
  return (
    B64[(e >> 18) & 63] + B64[(e >> 12) & 63] + B64[(e >> 6) & 63] + B64[63 & e]
  );
}
function encodeChunk(e, a, r) {
  const u = [];
  for (let p = a; p < r; p += 3) {
    const c =
      ((e[p] << 16) & 0xff0000) + ((e[p + 1] << 8) & 65280) + (255 & e[p + 2]);
    u.push(tripletToBase64(c));
  }
  return u.join('');
}
function b64Encode(e) {
  const r = e.length;
  const u = r % 3;
  const p = [];
  const v = 16383;
  const S = r - u;
  for (let w = 0; w < S; w += v) p.push(encodeChunk(e, w, w + v > S ? S : w + v));
  if (1 === u) {
    const a = e[r - 1];
    p.push(B64[a >> 2] + B64[(a << 4) & 63] + '==');
  } else if (2 === u) {
    const a = (e[r - 2] << 8) + e[r - 1];
    p.push(B64[a >> 10] + B64[(a >> 4) & 63] + B64[(a << 2) & 63] + '=');
  }
  return p.join('');
}

// Convenience: the bundle always calls xE(lz(str)) to encode a string.
function encodeXsCommon(str) {
  return b64Encode(encodeUtf8(str));
}

module.exports = { crc32, encodeUtf8, b64Encode, encodeXsCommon, B64_ALPHABET };
