'use strict';
/**
 * DemiPass browser fill — the part shared by every browser path (Chromium over CDP, Lightpanda's MCP wrapper).
 *
 *   origin rules       the same as the server (dustforge browser_fill.js): exact origin, https, http only on localhost
 *   approval flow      fill/request → fill/redeem, with 428 polling for a person's (carbon) approval
 *   FillError          every failure carries a fixed code and a message built from non-secret parts only
 *   Redactor           best-effort: strips a filled value (and the encodings pages echo it in) out of what we return
 *
 * The secret value exists only inside obtainFill()'s return and the call that puts it into the page. Nothing
 * here logs. Contract: docs/browser-fill-api.md (dustforge branch feat/browser-fill).
 */

const REDACTED = '[demipass:redacted]';
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);
const POLL_MS = 2000;

class FillError extends Error {
  constructor(code, message, extra) {
    super(message);
    this.name = 'FillError';
    this.code = code;
    if (extra) this.extra = extra;
  }
  toJSON() { return { filled: false, error: this.code, message: this.message, ...(this.extra || {}) }; }
}

// `https://host[:port]`, or null. Mirrors the server so the client refuses what the server would refuse.
function normalizeOrigin(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
  let u;
  try { u = new URL(raw.trim()); } catch (_) { return null; }
  if (u.username || u.password) return null;
  if (u.protocol === 'https:') return u.origin;
  if (u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname)) return u.origin;
  return null;
}

// A server error string is display data, but cap it and strip control characters before it reaches a model.
function serverMessage(data, fallback) {
  const m = data && typeof data.error === 'string' ? data.error : fallback;
  return String(m).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200);
}

/**
 * Ask the server for a fill and collect the value. Resolves { value, username, origin, name, ref, request_id };
 * throws FillError otherwise. `api` = { fillRequest, fillRedeem } with the SDK's {status, data} shape.
 *
 *   waitSeconds   how long to poll 428 approval_pending (a carbon request waits for the phone; a silicon one
 *                 comes back approved). On timeout the request_id is returned in the error so the caller can resume.
 *   requestId     resume an earlier request instead of making a new one.
 */
async function obtainFill(api, { ref, origin, clientLabel, waitSeconds = 0, requestId, token, sleep = defaultSleep }) {
  if (!ref && !requestId) throw new FillError('bad_args', 'ref is required');
  const want = normalizeOrigin(origin);
  if (!want) throw new FillError('origin_not_fillable', 'the page origin is not fillable (https only; http only on localhost)', { origin: String(origin || '').slice(0, 200) });

  let id = requestId;
  if (!id) {
    let r;
    try { r = await api.fillRequest({ ref, origin: want, client_label: clientLabel, token }); }
    catch (e) { throw new FillError('network', `fill request failed: ${String(e && e.message || e).slice(0, 160)}`); }
    const { status, data } = r;
    if (status === 403) {
      const bound = data && Array.isArray(data.bound_origins);
      throw new FillError(bound ? 'origin_not_bound' : 'not_granted', serverMessage(data, 'forbidden'),
        bound ? { origin: want, bound_origins: data.bound_origins.slice(0, 10) } : { origin: want });
    }
    if (status === 401) throw new FillError('unauthorized', serverMessage(data, 'not signed in to DemiPass'));
    if (status === 404) throw new FillError('not_found', serverMessage(data, 'secret not found'));
    if (status === 423) throw new FillError('frozen', serverMessage(data, 'secret is frozen'));
    if (status !== 201 && status !== 200) throw new FillError('request_failed', serverMessage(data, `HTTP ${status}`), { http_status: status });
    if (!data || typeof data.request_id !== 'string') throw new FillError('request_failed', 'server returned no request_id');
    id = data.request_id;
  }

  const deadline = Date.now() + Math.max(0, Math.min(Number(waitSeconds) || 0, 120)) * 1000;
  for (;;) {
    let r;
    try { r = await api.fillRedeem({ request_id: id, token }); }
    catch (e) { throw new FillError('network', `fill redeem failed: ${String(e && e.message || e).slice(0, 160)}`, { request_id: id }); }
    const { status, data } = r;
    if (status === 200) {
      if (!data || typeof data.value !== 'string') throw new FillError('redeem_failed', 'server returned no value');
      const got = normalizeOrigin(data.origin);
      // The server says which origin it approved. It must be the page we are about to fill, exactly.
      if (got !== want) throw new FillError('origin_mismatch', `the server approved ${String(data.origin).slice(0, 200)}, the page is ${want}`, { origin: want });
      return { value: data.value, username: typeof data.username === 'string' ? data.username : '', origin: got,
               name: data.name, ref: data.ref || ref, request_id: id };
    }
    if (status === 428) {
      if (Date.now() + POLL_MS > deadline) {
        throw new FillError('approval_pending', 'waiting for approval in the DemiPass wallet — call again with this request_id (it expires 120 s after the request)', { request_id: id });
      }
      await sleep(POLL_MS);
      continue;
    }
    if (status === 403) throw new FillError(data && data.error === 'denied' ? 'denied' : 'not_granted', serverMessage(data, 'denied'), { request_id: id });
    if (status === 410) throw new FillError(data && data.error === 'already_redeemed' ? 'already_redeemed' : 'expired', serverMessage(data, 'expired'), { request_id: id });
    if (status === 404) throw new FillError('not_found', serverMessage(data, 'fill request not found'), { request_id: id });
    if (status === 423) throw new FillError('frozen', serverMessage(data, 'secret is frozen'), { request_id: id });
    if (status === 401) throw new FillError('unauthorized', serverMessage(data, 'not signed in to DemiPass'), { request_id: id });
    throw new FillError('redeem_failed', serverMessage(data, `HTTP ${status}`), { request_id: id, http_status: status });
  }
}

function defaultSleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

/** Candidates for an origin (never values). */
async function listCandidates(api, { origin, token }) {
  const want = normalizeOrigin(origin);
  if (!want) throw new FillError('origin_not_fillable', 'the origin is not fillable (https only; http only on localhost)', { origin: String(origin || '').slice(0, 200) });
  let r;
  try { r = await api.fillCandidates({ origin: want, token }); }
  catch (e) { throw new FillError('network', `candidates failed: ${String(e && e.message || e).slice(0, 160)}`); }
  if (r.status !== 200) throw new FillError(r.status === 401 ? 'unauthorized' : 'candidates_failed', serverMessage(r.data, `HTTP ${r.status}`));
  const list = (r.data && Array.isArray(r.data.candidates)) ? r.data.candidates : [];
  return { origin: want, candidates: list.map((c) => ({ ref: c.ref, name: c.name, username: c.username || '', secret_type: c.secret_type })) };
}

/**
 * Best-effort scrubbing of known values out of strings and JSON-shaped objects. It replaces a value the page or
 * browser echoes back verbatim or in one of the encodings below; it cannot catch a value that was transformed in
 * any other way (base64, slicing, char codes, an encoding not listed). A value shorter than MIN_LEN is not scrubbed
 * (it would shred unrelated output); such a password is not worth protecting this way anyway.
 *
 * Encodings, each one seen in real Lightpanda 1.0.1 output or a common page echo:
 *   raw; JSON string body; encodeURIComponent (+ spaces as '+'); WHATWG URL serialization of an encoded query
 *   ("'" → %27, `!*()~` left raw — links / interactiveElements / extract hrefs); strict RFC 3986; form
 *   (URLSearchParams); decodeURIComponent of a form query (spaces left as '+'); the raw value as a URL parser
 *   serializes it in a query; HTML escapes (&<>"' / &<>" / &<> — text nodes leave quotes raw); markdown
 *   backslash escapes (\`*_{}[]()#+-!|); lowercase-hex forms of every percent encoding; and the JSON string body of
 *   each of those.
 */
const MIN_LEN = 4;
const MD_SPECIAL = /[\\`*_{}[\]()#+\-!|]/g;

function encodingVariants(value) {
  const base = new Set([value]);
  const tryAdd = (f) => { try { const v = f(); if (typeof v === 'string') base.add(v); } catch (_) { /* lone surrogate */ } };
  const pct = [];
  const tryPct = (f) => { try { const v = f(); if (typeof v === 'string') { base.add(v); pct.push(v); } } catch (_) {} };
  tryPct(() => encodeURIComponent(value));
  tryPct(() => encodeURIComponent(value).replace(/%20/g, '+'));
  tryPct(() => encodeURIComponent(value).replace(/'/g, '%27'));
  tryPct(() => encodeURIComponent(value).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()));
  tryPct(() => new URLSearchParams({ v: value }).toString().slice(2));
  // A raw value placed in a query and serialized by a URL parser (special-scheme query percent-encode set).
  if (!value.includes('#')) tryPct(() => new URL('http://x/?' + value).search.slice(1));
  // decodeURIComponent(location.search) of a form-encoded value: everything decoded except '+' for spaces.
  tryAdd(() => value.replace(/ /g, '+'));
  const amp = value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  base.add(amp);
  base.add(amp.replace(/"/g, '&quot;'));
  base.add(amp.replace(/"/g, '&quot;').replace(/'/g, '&#39;'));
  base.add(amp.replace(/"/g, '&quot;').replace(/'/g, '&#x27;'));
  base.add(amp.replace(/"/g, '&#34;').replace(/'/g, '&#39;'));
  base.add(value.replace(MD_SPECIAL, (c) => '\\' + c));
  for (const v of pct) base.add(v.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  const out = new Set(base);
  for (const v of base) out.add(JSON.stringify(v).slice(1, -1));
  return [...out].filter((v) => v.length >= MIN_LEN);
}

class Redactor {
  // `max` fills are remembered; past that the oldest fill's needles are dropped together (never a raw value while
  // one of its encodings stays, and never a newer fill's needles).
  constructor({ max = 64 } = {}) { this.groups = []; this.needles = []; this.max = max; }
  add(value) {
    if (typeof value !== 'string' || value.length < MIN_LEN) return;
    const variants = encodingVariants(value);
    this.groups = this.groups.filter((g) => g[0] !== value); // a refill of the same value counts as the newest
    this.groups.push(variants);
    while (this.groups.length > this.max) this.groups.shift();
    // Longest first, so a raw value inside its own encoding is not half-replaced.
    this.needles = [...new Set(this.groups.flat())].sort((a, b) => b.length - a.length);
  }
  get size() { return this.needles.length; }
  get fills() { return this.groups.length; }
  scrub(str) {
    if (typeof str !== 'string' || this.needles.length === 0) return str;
    let out = str;
    for (const n of this.needles) if (out.includes(n)) out = out.split(n).join(REDACTED);
    return out;
  }
  scrubDeep(obj) {
    if (this.needles.length === 0) return obj;
    if (typeof obj === 'string') return this.scrub(obj);
    if (Array.isArray(obj)) return obj.map((x) => this.scrubDeep(x));
    if (obj && typeof obj === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(obj)) out[this.scrub(k)] = this.scrubDeep(v);
      return out;
    }
    return obj;
  }
}

/** Turn anything thrown inside a fill into a value-free result object. */
function failureResult(err, redactor) {
  const base = err instanceof FillError ? err.toJSON() : { filled: false, error: 'internal', message: 'browser fill failed' };
  return redactor ? redactor.scrubDeep(base) : base;
}

/**
 * The fill identity, read fresh on every call (the fleet provisions the token file after the wrapper starts).
 *
 *   DEMIPASS_FILL_TOKEN set            → that token; blank → FillError('no_fill_identity')
 *   else DEMIPASS_FILL_TOKEN_FILE set  → its first line; missing, unreadable or empty → FillError('no_fill_identity')
 *   neither set                        → undefined: the caller uses the SDK's usual bearer
 *
 * A configured-but-unusable fill identity never falls back to the operator's bearer: that would run an agent's fill
 * under the operator's (carbon) identity instead of the silicon grant the operator set up for it.
 */
function resolveFillToken(env = process.env) {
  if (env.DEMIPASS_FILL_TOKEN !== undefined) {
    const t = String(env.DEMIPASS_FILL_TOKEN).trim();
    if (!t) throw new FillError('no_fill_identity', 'no fill identity provisioned: DEMIPASS_FILL_TOKEN is set but blank');
    return t;
  }
  if (env.DEMIPASS_FILL_TOKEN_FILE !== undefined) {
    const f = String(env.DEMIPASS_FILL_TOKEN_FILE);
    let t = '';
    try { t = require('fs').readFileSync(f, 'utf8').split('\n')[0].trim(); } catch (_) { t = ''; }
    if (!t) throw new FillError('no_fill_identity', `no fill identity provisioned: the token file DEMIPASS_FILL_TOKEN_FILE names (${f.slice(0, 200)}) is missing, unreadable or empty`);
    return t;
  }
  return undefined;
}
/** True when a fill identity is configured (usable or not) — the SDK bearer is then never used for fills. */
function fillIdentityConfigured(env = process.env) {
  return env.DEMIPASS_FILL_TOKEN !== undefined || env.DEMIPASS_FILL_TOKEN_FILE !== undefined;
}

module.exports = { resolveFillToken, fillIdentityConfigured, encodingVariants, REDACTED, FillError, normalizeOrigin, obtainFill, listCandidates, Redactor, failureResult };
