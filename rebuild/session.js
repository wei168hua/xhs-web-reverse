'use strict';
/**
 * SessionManager / SignState — stateful signing for the X-s core (mnsv2).
 *
 * Mirrors xhshow's session.py. The mnsv2 plaintext contains three fields that,
 * on a real browser, evolve across a single page session rather than being
 * fully random each call:
 *   - page_load_timestamp : fixed at page load (== `loadts` cookie)
 *   - sequence_value      : monotonically increasing per signed request
 *   - window_props_length : slowly increasing counter
 * Using a session (instead of fresh randoms) produces signatures whose dynamic
 * fields move the way a genuine browser's do — matching what we observed live
 * in the mnsv2 differential analysis (bytes [16:24], [24:28], [28:32]).
 *
 * These feed mnsv2.buildPayload() via opts {pageLoadTs, sequence, windowPropsLength}.
 */

// Config ranges copied from xhshow CryptoConfig.
const SEQUENCE_INIT_MIN = 15, SEQUENCE_INIT_MAX = 17;
const SEQUENCE_STEP_MIN = 0, SEQUENCE_STEP_MAX = 1;
const WINDOW_PROPS_INIT_MIN = 1000, WINDOW_PROPS_INIT_MAX = 2000;
const WINDOW_PROPS_STEP_MIN = 1, WINDOW_PROPS_STEP_MAX = 10;

function randInt(min, max) { return min + Math.floor(Math.random() * (max - min + 1)); }

class SessionManager {
  constructor(opts = {}) {
    this.pageLoadTimestamp = opts.pageLoadTimestamp != null ? opts.pageLoadTimestamp : Date.now();
    this.sequenceValue = opts.sequenceValue != null ? opts.sequenceValue : randInt(SEQUENCE_INIT_MIN, SEQUENCE_INIT_MAX);
    this.windowPropsLength = opts.windowPropsLength != null ? opts.windowPropsLength : randInt(WINDOW_PROPS_INIT_MIN, WINDOW_PROPS_INIT_MAX);
  }

  /** Advance counters to simulate activity between requests. */
  updateState() {
    this.sequenceValue += randInt(SEQUENCE_STEP_MIN, SEQUENCE_STEP_MAX);
    this.windowPropsLength += randInt(WINDOW_PROPS_STEP_MIN, WINDOW_PROPS_STEP_MAX);
  }

  /**
   * Get the current SignState for a request (advances counters first).
   * `content` is the string used for uri_length (== realUrl [+ body]).
   * Returns fields consumed by mnsv2.buildPayload / seccoreSignV2 via ctx.
   */
  getCurrentState(content) {
    this.updateState();
    return {
      pageLoadTs: this.pageLoadTimestamp,
      sequence: this.sequenceValue,
      windowPropsLength: this.windowPropsLength,
      uriLength: Buffer.byteLength(content || '', 'utf8'),
    };
  }
}

module.exports = { SessionManager };
