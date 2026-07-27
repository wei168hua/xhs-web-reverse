'use strict';
/**
 * XHS Web signing – orchestration reconstruction (entry).
 *
 * Faithfully mirrors, from vendor-dynamic.ae665ebb.js:
 *   - xhsSign()          -> sets X-s, X-t
 *   - xsCommon()         -> sets X-S-Common
 *   - seccore_signv2()   -> the X-s value ("XYS_" + custom-b64(JSON))
 *
 * KNOWN LIMITATION (see report.md §"已知限制"):
 *   X-s ultimately depends on `window.mnsv2(c,u,p)` (and the legacy
 *   `window.sign`/`window._webmsxyw`). Those are NOT in the static bundles;
 *   they are installed at runtime by the obfuscated risk-control VM loaded
 *   from as.xiaohongshu.com + fe-static.../as/v1/3e44/public/*.js.
 *   So X-s CANNOT be produced fully offline without either (a) porting that VM
 *   or (b) calling into a browser/JS-VM that has mnsv2 installed.
 *   The X-S-Common envelope and X-t are fully deterministic and reproduced here.
 */
const crypto = require('crypto');
const { crc32, encodeXsCommon } = require('./env');
const mns = require('./mnsv2'); // reconstructed X-s core (was the black box in the prior session)
const xrap = require('./xrap'); // x-rap-param generator
const gen = require('./generators'); // a1 / trace ids / xy-direction / url helpers
const { SessionManager } = require('./session'); // stateful signing for mnsv2

// MD5 stands in for the bundle's `W.Pu` (a bundled MD5 -> hex).
function md5hex(str) {
  return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

// getRealUrl: origin-stripped path+query, with ' -> %27  (buildURL omitted here;
// pass an already-serialized "/api/...?a=1&b=2" path or a full https URL).
function getRealUrl(u) {
  let p = u;
  try {
    if (/^https?:/.test(u)) {
      const url = new URL(u);
      p = url.href.replace(url.origin, '');
    }
  } catch (_) {}
  return p.replace(/'/g, '%27');
}

/**
 * X-S-Common envelope. Field names/order copied from xsCommon().
 * Runtime-sourced values (fingerprint b1, dsl, sc count, cookie a1...) are passed
 * in via `ctx`; defaults illustrate structure. R and I are "" in the shipped code,
 * so x6=x7="" and x9=crc32(fingerprint).
 */
function buildXSCommon(ctx = {}) {
  const platform = ctx.platform || 'PC';
  const R = '';
  const I = '';
  const fingerprint = ctx.b1 || ''; // localStorage[q2] === "b1"
  const en = {
    s0: ctx.s0 != null ? ctx.s0 : 5, // getPlatformCode(platform): Windows0 iOS1 Android2 MacOs3 Linux4 other5
    s1: '',
    x0: ctx.x0 != null ? ctx.x0 : '1', // localStorage[z7]||fI("1")
    x1: ctx.x1 || '4.3.7', // i8 (appId/version constant from bundle)
    x2: platform,
    x3: 'xhs-pc-web',
    x4: '6.34.4', // client version string in bundle
    x5: ctx.a1 || '', // cookie a1 (o4)
    x6: R,
    x7: I,
    x8: fingerprint, // localStorage[q2] === b1
    x9: crc32('' + R + I + fingerprint), // tb(R+I+G)
    x10: ctx.x10 != null ? ctx.x10 : 1,
    x11: 'normal',
    x12: (ctx.br || '') + ';' + (ctx.dsl || ''), // localStorage[br("dsllt")] + ';' + window._dsl
  };
  return encodeXsCommon(JSON.stringify(en));
}

/**
 * seccore_signv2 – produces the X-s value.
 * `mnsv2` is now reconstructed offline (see mnsv2.js). If a caller passes a
 * custom `mnsv2` fn (e.g. a live browser bridge) it is used instead; otherwise
 * the offline reconstruction produces a byte-identical `mns0301_` x3.
 * `ctx` supplies runtime fields the core reads: a1 cookie, loadts (pageLoadTs),
 * seed/timestamp/sequence (randomized when omitted).
 */
function seccoreSignV2(realUrl, data, mnsv2, ctx = {}) {
  let c = realUrl;
  if (data && (typeof data === 'object')) c += JSON.stringify(data);
  else if (typeof data === 'string') c += data;

  const u = md5hex(c);     // W.Pu([c].join(""))
  const p = md5hex(realUrl); // W.Pu(e)

  let v;
  if (typeof mnsv2 === 'function') {
    v = mnsv2(c, u, p); // external bridge (browser/VM)
  } else {
    // offline reconstruction of window.mnsv2
    v = mns.mnsv2(c, {
      dValue: u,
      md5Path: p,
      a1: ctx.a1 || '',
      appId: 'xhs-pc-web',
      pageLoadTs: ctx.loadts,
      timestampMs: ctx.timestampMs,
      seed: ctx.seed,
      sequence: ctx.sequence,
      windowPropsLength: ctx.windowPropsLength,
    });
  }

  const S = {
    x0: '4.3.7', // w.i8
    x1: 'xhs-pc-web',
    x2: typeof globalThis !== 'undefined' && globalThis.__xhs_platform__ ? globalThis.__xhs_platform__ : 'PC',
    x3: v, // <-- reconstructed core output ("mns0301_"...)
    x4: data ? (typeof data) : '',
  };
  return 'XYS_' + encodeXsCommon(JSON.stringify(S));
}

/**
 * Full header set for one request (mirrors xhsSign + xsCommon).
 * `mnsv2` optional external bridge; if omitted, the offline core is used.
 */
function signRequest({ url, data, ctx = {}, mnsv2 } = {}) {
  const realUrl = getRealUrl(url);
  return {
    'X-s': seccoreSignV2(realUrl, data, mnsv2, ctx),
    'X-t': String(Date.now()),
    'X-S-Common': buildXSCommon(ctx),
  };
}

/**
 * Complete browser-equivalent header set (mirrors xhshow sign_headers).
 * Emits: x-s, x-s-common, x-t, x-b3-traceid, x-xray-traceid, x-mns, xy-direction,
 * and optionally x-rap-param.
 *
 * opts:
 *   url            request URL or URI
 *   method         'GET' | 'POST' (affects x-rap api path only; x-s signs URL+body regardless)
 *   data           params/body object (or string)
 *   ctx            runtime ctx for x-s / x-s-common (a1, loadts, b1, dsl, ...)
 *   session        optional SessionManager (stateful sequence/timestamp for mnsv2)
 *   userId         optional user id for xy-direction sharding (else random)
 *   xRap           boolean — include x-rap-param
 *   xMns           value for x-mns header (default 'unload', matching live browser when SDK unloaded)
 *   mnsv2          optional external mnsv2 bridge
 */
function signHeaders(opts = {}) {
  const { url, method = 'GET', data, ctx = {}, session, userId, xRap = false, xMns = 'unload', mnsv2 } = opts;
  const realUrl = getRealUrl(url);

  // If a session is supplied, derive the mnsv2 dynamic fields from it.
  let signCtx = ctx;
  if (session) {
    let content = realUrl;
    if (data && typeof data === 'object') content += JSON.stringify(data);
    else if (typeof data === 'string') content += data;
    const st = session.getCurrentState(content);
    signCtx = Object.assign({}, ctx, {
      loadts: st.pageLoadTs,
      sequence: st.sequence,
      windowPropsLength: st.windowPropsLength,
    });
  }

  const headers = {
    'x-s': seccoreSignV2(realUrl, data, mnsv2, signCtx),
    'x-t': String(Date.now()),
    'x-s-common': buildXSCommon(signCtx),
    'x-b3-traceid': gen.getB3TraceId(),
    'x-xray-traceid': gen.getXrayTraceId(Date.now()),
    'x-mns': xMns,
    'xy-direction': String(gen.getShardingKey(userId)),
  };

  if (xRap) {
    const rapApi = '//edith.xiaohongshu.com' + gen.extractUri(url);
    headers['x-rap-param'] = xrap.xRapParam(rapApi, data || {});
  }
  return headers;
}

module.exports = {
  md5hex,
  getRealUrl,
  buildXSCommon,
  seccoreSignV2,
  signRequest,
  signHeaders,
  SessionManager,
  gen,
};

if (require.main === module) {
  // demo / self-check
  const demoUrl = '/api/sns/web/v1/homefeed';
  const demoData = { cursor_score: '', num: 18, refresh_type: 1 };
  const session = new SessionManager({ pageLoadTimestamp: 1700000000000 });
  console.log(JSON.stringify(signHeaders({
    url: demoUrl, method: 'POST', data: demoData, session, xRap: true,
    ctx: { b1: 'DEMOFINGERPRINT', a1: 'demo00000000000000000000000000000000000000000000a1xx', dsl: 'demodsl' },
  }), null, 2));
}
