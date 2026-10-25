'use strict';
/**
 * DemiPass browser fill over the Chrome DevTools Protocol.
 *
 *   fillViaCdp({ cdpUrl, ref, ... })   attach to a browser the agent drives (Chromium with --remote-debugging-port,
 *                                      Playwright/puppeteer launched browsers), find the page, fill it, detach.
 *   fillOnSession(send, { ref, ... })  the same fill on a CDP session the caller already holds. Needed where a
 *                                      second CDP connection cannot see the agent's page — Lightpanda `serve` gives
 *                                      every connection its own browser — so the fill must ride the driver's own
 *                                      connection (puppeteer: `page.createCDPSession()`, `(m, p) => s.send(m, p)`).
 *
 * The page's origin comes from the browser (Page.getFrameTree of the main frame), never from page script, and the
 * in-page step re-checks location.origin in the same task that sets the value, so a navigation between approval and
 * fill fails closed. The value travels only in the Runtime.callFunctionOn arguments; results carry a length.
 *
 * Node >= 22 (global WebSocket and fetch). No dependencies.
 */

const crypto = require('crypto');
const { FillError, normalizeOrigin, obtainFill, listCandidates, Redactor, failureResult } = require('./fill-core');
const { PAGE_FUNCTION } = require('./page-script');

const DEFAULT_TIMEOUT_MS = 15000;

// ── a minimal CDP client ──────────────────────────────────────────────────────────────────────────────────────

async function resolveWsUrl(cdpUrl) {
  if (typeof cdpUrl !== 'string' || !cdpUrl) throw new FillError('bad_args', 'cdp_url is required (http://127.0.0.1:9222 or a ws:// URL)');
  let u;
  try { u = new URL(cdpUrl); } catch (_) { throw new FillError('bad_args', 'cdp_url is not a URL'); }
  if (u.protocol === 'ws:' || u.protocol === 'wss:') return cdpUrl;
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new FillError('bad_args', 'cdp_url must be http(s):// or ws(s)://');
  let res;
  try { res = await fetch(new URL('/json/version', u), { signal: AbortSignal.timeout(5000) }); }
  catch (e) { throw new FillError('cdp_unreachable', `no DevTools endpoint at ${u.origin}`); }
  if (!res.ok) throw new FillError('cdp_unreachable', `DevTools endpoint at ${u.origin} answered HTTP ${res.status}`);
  let info;
  try { info = await res.json(); } catch (_) { throw new FillError('cdp_unreachable', 'DevTools /json/version is not JSON'); }
  if (!info || typeof info.webSocketDebuggerUrl !== 'string') throw new FillError('cdp_unreachable', 'DevTools endpoint advertises no webSocketDebuggerUrl');
  return info.webSocketDebuggerUrl;
}

async function connect(cdpUrl, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof WebSocket !== 'function') throw new FillError('runtime', 'this Node has no global WebSocket (need Node >= 22)');
  const wsUrl = await resolveWsUrl(cdpUrl);
  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new FillError('cdp_unreachable', 'DevTools WebSocket did not open')), 5000);
    ws.onopen = () => { clearTimeout(t); resolve(); };
    ws.onerror = () => { clearTimeout(t); reject(new FillError('cdp_unreachable', 'DevTools WebSocket failed to open')); };
  });
  let nextId = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    let m;
    try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString()); } catch (_) { return; }
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); clearTimeout(p.timer); p.resolve(m); }
  };
  ws.onclose = () => { for (const p of pending.values()) { clearTimeout(p.timer); p.resolve({ error: { message: 'connection closed' } }); } pending.clear(); };
  // Resolves the raw message; a CDP error becomes FillError('cdp_error') with the method name only (the protocol
  // error text can echo arguments, and the fill's arguments carry the value).
  function send(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => { pending.delete(id); reject(new FillError('cdp_timeout', `${method} timed out`)); }, timeoutMs);
      pending.set(id, { timer, resolve: (m) => (m.error ? reject(new FillError('cdp_error', `${method} failed`)) : resolve(m.result || {})) });
      try { ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); }
      catch (_) { clearTimeout(timer); pending.delete(id); reject(new FillError('cdp_error', `${method} could not be sent`)); }
    });
  }
  return { send, close: () => { try { ws.close(); } catch (_) {} } };
}

// ── page lookup ───────────────────────────────────────────────────────────────────────────────────────────────

function pageSummary(t) {
  return { target_id: t.targetId, origin: normalizeOrigin(t.url) || safeOrigin(t.url), title: String(t.title || '').slice(0, 120) };
}
function safeOrigin(url) { try { return new URL(url).origin; } catch (_) { return null; } }

async function listPages(conn) {
  const { targetInfos = [] } = await conn.send('Target.getTargets');
  return targetInfos.filter((t) => t.type === 'page');
}

function choosePage(pages, targetId) {
  if (targetId) {
    const t = pages.find((p) => p.targetId === targetId);
    if (!t) throw new FillError('target_not_found', 'no page with that target_id', { pages: pages.map(pageSummary) });
    return t;
  }
  if (pages.length === 1) return pages[0];
  if (pages.length === 0) throw new FillError('no_page', 'the browser has no open page');
  throw new FillError('ambiguous_page', 'several pages are open — pass target_id', { pages: pages.map(pageSummary) });
}

// The main frame's origin as the browser reports it. securityOrigin, when present, must agree with the URL.
async function mainFrame(send) {
  const { frameTree } = await send('Page.getFrameTree');
  const frame = frameTree && frameTree.frame;
  if (!frame) throw new FillError('no_frame', 'the page has no main frame');
  const origin = normalizeOrigin(frame.url);
  if (!origin) throw new FillError('origin_not_fillable', 'the page origin is not fillable (https only; http only on localhost)', { origin: safeOrigin(frame.url) });
  if (frame.securityOrigin && frame.securityOrigin !== origin) throw new FillError('origin_unclear', 'the browser reports a different security origin for this page', { origin });
  return { id: frame.id, origin };
}

async function runInIsolatedWorld(send, frameId, args) {
  const { executionContextId } = await send('Page.createIsolatedWorld', { frameId, worldName: 'demipass-fill', grantUniveralAccess: false });
  if (!executionContextId) throw new FillError('cdp_error', 'could not create an isolated world');
  const r = await send('Runtime.callFunctionOn', {
    functionDeclaration: PAGE_FUNCTION,
    executionContextId,
    arguments: [{ value: args }],
    returnByValue: true,
    awaitPromise: false,
    userGesture: true,
  });
  if (r.exceptionDetails) throw new FillError('page_script_failed', 'the fill script raised an exception in the page');
  const v = r.result && r.result.value;
  if (!v || typeof v !== 'object') throw new FillError('page_script_failed', 'the fill script returned nothing');
  return v;
}

function pageFailure(v, origin) {
  const msgs = {
    origin_changed: 'the page navigated away from the approved origin before the fill — nothing was filled',
    no_password_field: 'no visible password field on this page — pass password_selector',
    ambiguous_password_field: 'several password fields on this page — pass password_selector',
    selector_not_found: `no element matches the ${v.field}_selector`,
    bad_selector: `the ${v.field}_selector is not valid CSS`,
    field_not_usable: `the ${v.field} field is hidden, disabled or read-only`,
    value_not_accepted: 'the password field did not accept the value (maxlength or a page script?)',
  };
  return new FillError(v.code || 'page_script_failed', msgs[v.code] || 'the fill could not be completed in the page', { origin, ...(v.count ? { count: v.count } : {}) });
}

// ── the fill ──────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Fill on a CDP session the caller holds. `send(method, params)` must already be bound to the page session.
 * Resolves the value-free result; throws FillError (value-free).
 */
async function fillOnSession(send, opts) {
  const { ref, usernameSelector, passwordSelector, submit = false, api, token, clientLabel, waitSeconds, requestId } = opts;
  try { await send('Page.enable'); } catch (_) { /* Page.getFrameTree works without it on Chromium */ }
  const frame = await mainFrame(send);
  const selectors = { usernameSelector: usernameSelector || null, passwordSelector: passwordSelector || null };

  // Locate the fields before asking for the value, so a page with nothing to fill never spends a request.
  const found = await runInIsolatedWorld(send, frame.id, { mode: 'find', expectedOrigin: frame.origin, ...selectors });
  if (!found.ok) throw pageFailure(found, frame.origin);

  let secret = await obtainFill(api, { ref, origin: frame.origin, clientLabel, waitSeconds, requestId, token });
  try {
    const now = await mainFrame(send);
    if (now.origin !== secret.origin || now.id !== frame.id) throw new FillError('origin_changed', 'the page navigated away before the fill — nothing was filled', { origin: now.origin });
    const v = await runInIsolatedWorld(send, frame.id, {
      mode: 'fill', expectedOrigin: secret.origin, ...selectors,
      username: secret.username, password: secret.value, submit: Boolean(submit),
    });
    if (!v.ok) throw pageFailure(v, secret.origin);
    return {
      filled: true, chars: v.chars, origin: secret.origin, ref: secret.ref,
      username_filled: v.username_filled, password_filled: v.password_filled,
      submitted: v.submitted, ...(v.submit_error ? { submit_error: v.submit_error } : {}),
    };
  } finally {
    secret.value = null; secret = null;
  }
}

/** Attach to `cdpUrl`, fill the chosen page, detach. Always resolves a value-free object. */
async function fillViaCdp(opts) {
  const redactor = new Redactor();
  let conn;
  try {
    conn = await connect(opts.cdpUrl, { timeoutMs: opts.timeoutMs });
    const page = choosePage(await listPages(conn), opts.targetId);
    const { sessionId } = await conn.send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
    if (!sessionId) throw new FillError('cdp_error', 'could not attach to the page');
    const send = (m, p) => conn.send(m, p, sessionId);
    try {
      // The redactor wraps the api so it learns the value the moment it exists — any later error is scrubbed.
      const api = {
        fillRequest: (x) => opts.api.fillRequest(x),
        fillRedeem: async (x) => { const r = await opts.api.fillRedeem(x); if (r && r.data && typeof r.data.value === 'string') redactor.add(r.data.value); return r; },
      };
      const out = await fillOnSession(send, { ...opts, api });
      return redactor.scrubDeep({ ...out, target_id: page.targetId });
    } finally {
      try { await conn.send('Target.detachFromTarget', { sessionId }); } catch (_) { /* gone */ }
    }
  } catch (err) {
    return failureResult(err, redactor);
  } finally {
    if (conn) conn.close();
  }
}

/** Candidates for the page at `cdpUrl` (or an explicit origin). Value-free. */
async function candidatesViaCdp({ cdpUrl, targetId, origin, api, token }) {
  try {
    let want = origin;
    let pages;
    if (!want) {
      const conn = await connect(cdpUrl);
      try {
        const all = await listPages(conn);
        pages = all.map(pageSummary);
        want = choosePage(all, targetId).url;
      } finally { conn.close(); }
    }
    const out = await listCandidates(api, { origin: want, token });
    return { ok: true, ...out, ...(pages && pages.length > 1 ? { pages } : {}) };
  } catch (err) {
    return { ok: false, ...failureResult(err) };
  }
}

module.exports = { connect, fillViaCdp, fillOnSession, candidatesViaCdp, listPages, newMark: () => crypto.randomBytes(8).toString('hex') };
