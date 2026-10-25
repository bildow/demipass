'use strict';
/**
 * DemiPass browser fill — the part shared by every browser path (Chromium over CDP, Lightpanda's MCP wrapper).
 *
 *   origin rules       the same as the server (dustforge browser_fill.js): exact origin, https, http only on localhost
 *   approval flow      fill/request → fill/redeem, with 428 polling for a person's (carbon) approval
 *   FillError          every failure carries a fixed code and a message built from non-secret parts only
 *   Redactor           strips a filled value (and its URL / form / HTML encodings) out of anything we return
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
 * Strips known values out of strings and JSON-shaped objects. A value shorter than MIN_LEN is not scrubbed
 * (it would shred unrelated output); such a password is not worth protecting this way anyway.
 */
const MIN_LEN = 4;
class Redactor {
  constructor({ max = 64 } = {}) { this.needles = []; this.max = max; }
  add(value) {
    if (typeof value !== 'string' || value.length < MIN_LEN) return;
    const variants = new Set([value]);
    try { variants.add(encodeURIComponent(value)); } catch (_) { /* lone surrogate */ }
    try { variants.add(encodeURIComponent(value).replace(/%20/g, '+')); } catch (_) {}
    try { variants.add(new URLSearchParams({ v: value }).toString().slice(2)); } catch (_) {}
    variants.add(value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'));
    variants.add(value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
    variants.add(JSON.stringify(value).slice(1, -1));
    for (const v of variants) if (v.length >= MIN_LEN && !this.needles.includes(v)) this.needles.push(v);
    // Longest first, so a raw value inside its own encoding is not half-replaced.
    this.needles.sort((a, b) => b.length - a.length);
    while (this.needles.length > this.max * 7) this.needles.pop();
  }
  get size() { return this.needles.length; }
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
 * The agent's fill token: DEMIPASS_FILL_TOKEN, or the first line of the file DEMIPASS_FILL_TOKEN_FILE names (keeps
 * the token out of an MCP client's config file, e.g. goose's config.yaml). undefined → use the SDK's bearer.
 */
function fillTokenFromEnv(env = process.env) {
  if (env.DEMIPASS_FILL_TOKEN) return env.DEMIPASS_FILL_TOKEN.trim();
  if (env.DEMIPASS_FILL_TOKEN_FILE) {
    try { return require('fs').readFileSync(env.DEMIPASS_FILL_TOKEN_FILE, 'utf8').split('\n')[0].trim() || undefined; }
    catch (_) { return undefined; }
  }
  return undefined;
}

module.exports = { fillTokenFromEnv, REDACTED, FillError, normalizeOrigin, obtainFill, listCandidates, Redactor, failureResult };
