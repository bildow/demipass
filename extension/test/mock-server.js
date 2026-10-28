// Local mock of the DemiPass API, per docs/browser-fill-api.md (dustforge
// feat/browser-fill, undeployed). Used by the unit tests' fetch double and by
// the browser smoke test. Never point this at, or proxy to, production.
//
//   node extension/test/mock-server.js [apiPort] [sitePort]
//
// Also serves a test login site on sitePort, reachable as two different
// origins: http://localhost:<sitePort> and http://127.0.0.1:<sitePort>.

import http from 'node:http';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const rand = (p, n = 16) => p + crypto.randomBytes(n).toString('base64url');

function normOrigin(x) {
  try {
    const u = new URL(x);
    if (u.protocol === 'https:') return u.origin;
    if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return u.origin;
  } catch {}
  return null;
}

export function createMockState({ accessTtlSec = 3600, pin = '1234', authReject403 = false } = {}) {
  return {
    did: 'did:mock:owner',
    accessTtlSec,
    pin,
    authReject403, // emulate dustforge with ADMIN_API_KEY set: bad bearer -> 403
    access: new Map(), // jti -> { sid, scope, exp, revoked }
    refresh: new Map(), // raw -> { sid, scope, revoked }
    device: new Map(), // device_code -> { user_code, scope, status, expires }
    secrets: new Map(), // ref -> { name, value, secret_type, login, origins }
    // request_id ('dpf_…', what the asking session sees) -> { id (the wallet's numeric id), ref, origin, jti,
    // status, expires, client_label, created } — bound to the asking token, like dustforge's blindkey_fill_requests.
    fills: new Map(),
    fillSeq: 0,
    proofs: new Map(), // sid -> intent with a fresh PIN proof
    calls: [], // { method, path, status, meta } — never values
  };
}

export function mintSession(state, scope = 'transact', sid = rand('sid_', 6)) {
  const jti = rand('jti_', 8);
  const exp = Math.floor(Date.now() / 1000) + state.accessTtlSec;
  state.access.set(jti, { sid, scope, exp, revoked: false });
  const token = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u({ sub: state.did, scope, exp, jti, sid })}.mock`;
  const refresh_token = rand('dpr_');
  state.refresh.set(refresh_token, { sid, scope, revoked: false });
  return { token, refresh_token, sid, jti };
}

function bearer(state, req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return { err: 401, error: 'Bearer token required' };
  const parts = h.slice(7).split('.');
  let claims = null;
  try { claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); } catch {}
  const rec = claims && state.access.get(claims.jti);
  if (!rec || rec.revoked) return { err: 401, error: 'token invalid: unknown or revoked' };
  if (rec.exp * 1000 < Date.now()) return { err: 401, error: 'token invalid: jwt expired' };
  return { sid: rec.sid, scope: rec.scope, jti: claims.jti };
}

function blindkeyAuth(state, req) {
  const a = bearer(state, req);
  if (a.err) return state.authReject403 ? { err: 403, error: 'admin access or Bearer token required' } : a;
  if (a.scope !== 'transact' && a.scope !== 'admin') return { err: 403, error: 'transact scope required' };
  return a;
}

async function readJson(req) {
  let s = '';
  for await (const c of req) { s += c; if (s.length > 100_000) break; }
  try { return s ? JSON.parse(s) : {}; } catch { return {}; }
}

export function apiHandler(state) {
  return async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    const url = new URL(req.url, 'http://mock');
    const body = req.method === 'POST' ? await readJson(req) : {};
    const meta = {};
    const send = (status, obj) => {
      state.calls.push({ method: req.method, path: url.pathname, status, meta });
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(obj));
    };
    const p = url.pathname;

    // ---- device flow -------------------------------------------------------
    if (p === '/api/identity/device/code' && req.method === 'POST') {
      const scope = body.scope || 'read';
      meta.scope = scope; meta.agent_label = String(body.agent_label || '').slice(0, 80);
      const device_code = rand('dpd_');
      const user_code = crypto.randomBytes(4).toString('hex').toUpperCase().replace(/^(.{4})/, '$1-');
      state.device.set(device_code, { user_code, scope, status: 'pending', expires: Date.now() + 600_000, label: meta.agent_label });
      return send(200, { ok: true, device_code, user_code, verification_url: 'https://demipass.com/device',
        verification_url_complete: 'https://demipass.com/device?code=' + user_code, interval: 1, expires_in: 600 });
    }
    if (p === '/api/identity/device/token' && req.method === 'POST') {
      const row = state.device.get(body.device_code);
      if (!row) return send(400, { error: 'invalid device_code' });
      if (row.expires < Date.now()) return send(400, { error: 'expired_token' });
      if (row.status === 'pending') return send(428, { error: 'authorization_pending' });
      if (row.status === 'denied') return send(403, { error: 'access_denied' });
      if (row.status === 'claimed') return send(400, { error: 'already_claimed' });
      row.status = 'claimed';
      const s = mintSession(state, row.scope);
      return send(200, { ok: true, token: s.token, refresh_token: s.refresh_token, refresh_expires_at: new Date(Date.now() + 90 * 864e5).toISOString(),
        did: state.did, scope: row.scope, email: 'owner@mock.test', auth_method: 'device', agent_label: row.label });
    }
    if (p === '/api/identity/refresh' && req.method === 'POST') {
      const rec = state.refresh.get(body.refresh_token);
      if (!rec || rec.revoked) return send(401, { error: 'invalid, expired, or revoked refresh token' });
      rec.revoked = true; // single-use rotation
      const s = mintSession(state, rec.scope, rec.sid);
      return send(200, { ok: true, token: s.token, refresh_token: s.refresh_token, did: state.did, scope: rec.scope, auth_method: 'refresh' });
    }
    if (p === '/api/identity/refresh/revoke' && req.method === 'POST') {
      const rec = state.refresh.get(body.refresh_token);
      if (!rec || rec.revoked) return send(200, { ok: true, revoked: false, note: 'token already invalid' });
      rec.revoked = true;
      return send(200, { ok: true, revoked: true });
    }
    if (p === '/api/identity/tokens/revoke' && req.method === 'POST') {
      const a = bearer(state, req);
      if (a.err) return send(a.err, { error: a.error });
      const rec = state.access.get(body.jti);
      if (!rec) return send(404, { error: 'token not found' });
      rec.revoked = true;
      return send(200, { ok: true, jti: body.jti, revoked: true });
    }

    // ---- wallet side (phone) ----------------------------------------------
    if (p === '/api/identity/gate/verify' && req.method === 'POST') {
      const a = bearer(state, req);
      if (a.err) return send(a.err, { error: a.error });
      if (body.gate !== 'pin' || body.pin !== state.pin) return send(401, { error: 'wrong PIN' });
      state.proofs.set(a.sid, body.intent);
      return send(200, { ok: true, gate: 'pin', intent: body.intent });
    }

    // ---- blindkey ----------------------------------------------------------
    if (!p.startsWith('/api/blindkey/')) return send(404, { error: 'not found' });
    const a = blindkeyAuth(state, req);
    if (a.err) return send(a.err, { error: a.error });

    if (p === '/api/blindkey/store' && req.method === 'POST') {
      const { name, value, secret_type, login, origins } = body;
      meta.name = name; meta.secret_type = secret_type; meta.login = login; meta.origins = origins;
      meta.value_length = typeof value === 'string' ? value.length : 0;
      if (!name || !value) return send(400, { error: 'name and value required' });
      if (name.length > 64) return send(400, { error: 'name must be 64 chars or less' });
      // dustforge clearNameForStore: a rotated name points at its live version.
      if (state.rotated && state.rotated.has(name)) return send(409, { error: `'${name}' was rotated; the current version is '${state.rotated.get(name)}' — store under that name` });
      if (login !== undefined && (typeof login !== 'string' || login.length > 256)) return send(400, { error: 'login must be a string of 256 chars or less' });
      let norm;
      if (origins !== undefined) {
        if (!Array.isArray(origins) || origins.length > 10) return send(400, { error: 'origins: array of up to 10' });
        norm = origins.map(normOrigin);
        if (norm.some((o) => !o)) return send(400, { error: 'origins: https, or http on localhost/127.0.0.1 only' });
      }
      const valid = ['api_key', 'oauth_token', 'password', 'signing_key', 'webhook_secret', 'connection_string', 'certificate', 'other'];
      const type = valid.includes(secret_type) ? secret_type : 'api_key';
      let ref = [...state.secrets].find(([, s]) => s.name === name)?.[0];
      if (ref) {
        const s = state.secrets.get(ref);
        s.value = value; s.secret_type = type;
        if (login !== undefined) s.login = login;
        if (norm) s.origins = [...new Set(norm)];
      } else {
        ref = `DP-${type === 'password' ? 'PWD' : 'API'}-${name.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase()}-${crypto.randomBytes(4).toString('hex')}`;
        state.secrets.set(ref, { name, value, secret_type: type, login: login || '', origins: norm ? [...new Set(norm)] : [] });
      }
      return send(200, { ok: true, name, ref, secret_type: type, note: 'Secret stored. It will never be returned in any API response.' });
    }
    if (p === '/api/blindkey/list' && req.method === 'GET') {
      const secrets = [...state.secrets].map(([ref, s]) => ({ name: s.name, ref_code: ref, secret_type: s.secret_type, status: 'active' }));
      return send(200, { did: state.did, secrets, total: secrets.length });
    }
    if (p === '/api/blindkey/origins' && req.method === 'POST') {
      if (state.failOrigins) return send(500, { error: 'origins update failed' }); // test switch
      const ref = body.ref || [...state.secrets].find(([, s]) => s.name === body.name)?.[0];
      const s = ref && state.secrets.get(ref);
      if (!s) return send(404, { error: 'secret not found' });
      const norm = (body.origins || []).map(normOrigin);
      if (norm.some((o) => !o)) return send(400, { error: 'bad origin' });
      s.origins = body.mode === 'set' ? [...new Set(norm)] : [...new Set([...s.origins, ...norm])].slice(0, 10);
      return send(200, { ok: true, ref, origins: s.origins });
    }
    if (p === '/api/blindkey/fill/candidates' && req.method === 'GET') {
      const origin = normOrigin(url.searchParams.get('origin') || '');
      meta.origin = origin;
      if (!origin) return send(400, { error: 'bad origin' });
      const candidates = [...state.secrets].filter(([, s]) => s.origins.includes(origin))
        .map(([ref, s]) => ({ ref, name: s.name, username: s.login, secret_type: s.secret_type }));
      return send(200, { ok: true, origin, candidates });
    }
    if (p === '/api/blindkey/fill/request' && req.method === 'POST') {
      const s = state.secrets.get(body.ref);
      const origin = normOrigin(body.origin || '');
      meta.ref = body.ref; meta.origin = body.origin;
      if (!s) return send(404, { error: 'secret not found' });
      if (!origin || !s.origins.includes(origin)) return send(403, { error: 'origin not bound to this secret', bound_origins: s.origins });
      // dustforge FILL_MAX_PENDING: at most 20 requests wait per person.
      const waiting = [...state.fills.values()].filter((f) => f.status === 'pending' && f.expires > Date.now()).length;
      if (waiting >= 20) return send(429, { error: 'too many fill requests waiting for approval — approve or deny some first' });
      const code = rand('dpf_', 12);
      state.fills.set(code, { id: ++state.fillSeq, ref: body.ref, origin, jti: a.jti, status: 'pending', expires: Date.now() + 120_000, client_label: String(body.client_label || ''), created: new Date().toISOString() });
      return send(201, { ok: true, request_id: code, status: 'pending', expires_in: 120 });
    }
    if (p === '/api/blindkey/fill/redeem' && req.method === 'POST') {
      const f = state.fills.get(body.request_id);
      meta.request_id = body.request_id;
      // Contract: a carbon session is one access token (jti). A refreshed token gets 404.
      if (!f || f.jti !== a.jti) return send(404, { error: 'fill request not found' });
      // Same order as dustforge: redeemed, denied, expired, pending, anything else.
      if (f.status === 'redeemed') return send(410, { error: 'already_redeemed' });
      if (f.status === 'denied') return send(403, { error: 'denied' });
      if (f.expires < Date.now()) { if (f.status === 'pending' || f.status === 'approved') f.status = 'expired'; return send(410, { error: 'expired' }); }
      if (f.status === 'pending') return send(428, { error: 'approval_pending' });
      if (f.status !== 'approved') return send(410, { error: f.status }); // e.g. 'withdrawn'
      const s = state.secrets.get(f.ref);
      if (!s) return send(404, { error: 'the login was deleted or revoked since the request' });
      f.status = 'redeemed';
      meta.event = 'secret_filled';
      return send(200, { ok: true, value: s.value, username: s.login, origin: f.origin, name: s.name, ref: f.ref });
    }
    // dustforge fix/fill-withdraw-dead-names: the asking session gives up its own request.
    if (p === '/api/blindkey/fill/withdraw' && req.method === 'POST') {
      meta.request_id = body.request_id;
      if (typeof body.request_id !== 'string' || !body.request_id) return send(400, { error: 'request_id required' });
      const f = state.fills.get(body.request_id);
      if (!f || f.jti !== a.jti) return send(404, { error: 'fill request not found' });
      const changed = f.status === 'pending' || f.status === 'approved';
      if (changed) f.status = 'withdrawn';
      return send(200, { ok: true, status: changed ? 'withdrawn' : f.status });
    }
    if (p === '/api/blindkey/fill/pending' && req.method === 'GET') {
      const requests = [...state.fills.values()].filter((f) => f.status === 'pending' && f.expires > Date.now())
        .map((f) => { const s = state.secrets.get(f.ref); return { id: f.id, intent: 'fill:' + f.id, name: s.name, ref: f.ref, username: s.login, origin: f.origin, client_label: f.client_label, created_at: f.created, expires_at: new Date(f.expires).toISOString(), own_session: f.jti === a.jti }; });
      return send(200, { ok: true, requests, grants: [] });
    }
    // As in dustforge: the wallet decides by the numeric id from /fill/pending. Deny is allowed from any of the
    // owner's sessions (the asking one included); approve is not allowed from the asking session.
    const m = p.match(/^\/api\/blindkey\/fill\/(\d+)\/(approve|deny)$/);
    if (m && req.method === 'POST') {
      meta.fill_id = Number(m[1]); meta.decision = m[2];
      const f = [...state.fills.values()].find((x) => x.id === Number(m[1]));
      if (!f) return send(404, { error: 'fill request not found' });
      if (f.status !== 'pending') return send(409, { error: `this fill request is already ${f.status}` });
      if (m[2] === 'deny') { f.status = 'denied'; meta.own_session = f.jti === a.jti; return send(200, { ok: true, id: f.id, status: 'denied' }); }
      if (f.jti === a.jti) return send(409, { error: 'approve this fill from your phone wallet, not from the session that asked for it' });
      if (state.proofs.get(a.sid) !== 'fill:' + m[1]) return send(403, { error: 'pin proof required', gate: 'pin', intent: 'fill:' + m[1] });
      state.proofs.delete(a.sid); // spent
      f.status = 'approved';
      return send(200, { ok: true, status: 'approved' });
    }
    return send(404, { error: 'not found' });
  };
}

// Test helpers that act as "the person": approve a device code, approve or
// deny a fill from a separate phone session using the PIN.
export async function approveDevice(state, userCode) {
  for (const row of state.device.values()) if (row.user_code === userCode && row.status === 'pending') { row.status = 'approved'; return true; }
  return false;
}

// Revokes every non-phone access token, as if it expired: the extension's next
// call gets 401, refreshes, and its pending fill request is orphaned (404).
export function expireAccessTokens(state) {
  let n = 0;
  for (const rec of state.access.values()) if (rec.sid !== 'sid_phone' && !rec.revoked) { rec.revoked = true; n++; }
  return n;
}

// requestId: the request_id the extension got ('dpf_…') or the wallet's numeric id.
export async function phoneDecide(apiBase, state, requestId, decision = 'approve') {
  const id = state.fills.has(requestId) ? state.fills.get(requestId).id : requestId;
  const phone = mintSession(state, 'transact', 'sid_phone');
  const h = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + phone.token };
  if (decision === 'approve') {
    await fetch(apiBase + '/api/identity/gate/verify', { method: 'POST', headers: h, body: JSON.stringify({ gate: 'pin', pin: state.pin, intent: 'fill:' + id }) });
  }
  const r = await fetch(`${apiBase}/api/blindkey/fill/${id}/${decision}`, { method: 'POST', headers: h });
  return r.status;
}

// ---- test site -------------------------------------------------------------
const LOGIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Mock login</title></head><body>
<h1>Mock login</h1>
<form id="login" method="post" action="/done">
  <label>Email <input id="user" name="email" type="email" autocomplete="username"></label>
  <label>Password <input id="pass" name="password" type="password" autocomplete="current-password"></label>
  <button type="submit">Sign in</button>
</form>
<form id="search"><input id="q" name="q" type="search" placeholder="Search"></form>
</body></html>`;

const LOGIN_FORM = `<form id="login" method="post" action="/done">
  <input id="user" name="email" type="email" autocomplete="username">
  <input id="pass" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button></form>`;
const page = (body) => `<!doctype html><html><head><meta charset="utf-8"><title>Mock</title></head><body>${body}</body></html>`;

// Pages for the hostile / tricky cases. `other` is the second origin of the
// same site (localhost <-> 127.0.0.1), used for cross-origin frames.
function trickyPage(pathname, other) {
  switch (pathname) {
    // single-page app: changes its URL with pushState / the hash (same document)
    case '/spa.html': return page(`${LOGIN_FORM}<script>window.pushNow=()=>history.pushState({}, '', '/spa.html?step=' + Math.random());</script>`);
    // login page with a cross-origin ad iframe that keeps reloading
    case '/ads.html': return page(`${LOGIN_FORM}<iframe id="ad" src="${other}/plain.html"></iframe>
      <script>window.rotate=()=>{setInterval(()=>{document.getElementById('ad').src='${other}/plain.html?'+Math.random()},700)};</script>`);
    // a page that forges a login with no person involved: script-set value + requestSubmit / dispatched events
    case '/forge.html': return page(`${LOGIN_FORM}<script>
      document.getElementById('login').addEventListener('submit', (e) => e.preventDefault());
      window.forge = (v) => { user.value = 'victim@example.com'; pass.value = v; document.getElementById('login').requestSubmit(); };
      window.forgeEvents = (v) => { user.value = 'victim@example.com'; pass.value = v;
        pass.dispatchEvent(new Event('input', { bubbles: true }));
        pass.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
        document.querySelector('#login button').dispatchEvent(new MouseEvent('click', { bubbles: true })); };
      window.addEventListener('message', (e) => { if (e.data === 'forge') window.forge('iframe-chosen-value'); });</script>`);
    // execCommand('insertText') makes trusted input events without a person; pmFill = another manager's fill
    case '/forge2.html': return page(`${LOGIN_FORM}<script>
      document.getElementById('login').addEventListener('submit', (e) => e.preventDefault());
      window.forge2 = (v) => { user.value = 'victim@example.com'; pass.focus(); document.execCommand('insertText', false, v); document.getElementById('login').requestSubmit(); return pass.value; };
      window.pmFill = (v) => { user.value = 'me@example.com'; pass.value = v; for (const t of ['input', 'change']) pass.dispatchEvent(new Event(t, { bubbles: true })); };
      window.fakeGone = () => window.dispatchEvent(new Event('pagehide'));</script>`);
    // show-password toggle: the field is type=text while the person types
    case '/toggle.html': return page(`${LOGIN_FORM}<button id="eye" type="button">show</button><script>
      document.getElementById('login').addEventListener('submit', (e) => e.preventDefault());
      eye.onclick = () => { pass.type = pass.type === 'password' ? 'text' : 'password'; };</script>`);
    // top login page (stays put on submit) embedding a cross-origin frame that forges a capture
    case '/top-frame.html': return page(`${LOGIN_FORM}<iframe id="f" src="${other}/forge.html"></iframe><script>
      document.getElementById('login').addEventListener('submit', (e) => e.preventDefault());
      window.forgeInFrame = () => document.getElementById('f').contentWindow.postMessage('forge', '*');</script>`);
    // N8: piggyback on typing in another field: a 1px password field steals focus on the first key,
    // then the page swaps in its own value with execCommand and submits on its own.
    case '/piggy.html': return page(`<form id="login" method="post" action="/done">
      <input id="user" name="email" type="email" autocomplete="username" style="width:1px;height:1px;border:0;padding:0">
      <input id="pass" name="password" type="password" style="width:1px;height:1px;border:0;padding:0"><button type="submit" style="width:1px;height:1px;border:0;padding:0">Sign in</button></form>
      <input id="q" placeholder="search"><script>
      login.addEventListener('submit', (e) => e.preventDefault());
      let stolen = false, done = false;
      q.addEventListener('keydown', () => { if (!stolen) { stolen = true; user.value = 'victim@example.com'; pass.focus(); } });
      let n = 0; pass.addEventListener('input', (e) => { if (done || !e.isTrusted || ++n < 2) return; done = true; pass.select(); document.execCommand('insertText', false, 'attacker-chosen'); login.requestSubmit(); window.result = pass.value; });
      </script>`);
    // N8b: the person types their real password; the page swaps it (nested / timer execCommand) before they submit
    case '/swap.html': return page(`${LOGIN_FORM}<script>
      login.addEventListener('submit', (e) => e.preventDefault());
      pass.addEventListener('input', (e) => { if (!e.isTrusted || pass.value.endsWith('!')) return; setTimeout(() => { pass.select(); document.execCommand('insertText', false, 'attacker-chosen!'); }, 0); });
      </script>`);
    case '/swap-sync.html': return page(`${LOGIN_FORM}<script>
      login.addEventListener('submit', (e) => e.preventDefault());
      let busy = false; pass.addEventListener('input', () => { if (busy) return; busy = true; const v = pass.value; pass.select(); document.execCommand('insertText', false, v + 'X'); busy = false; });
      </script>`);
    // sends with no sign-in words: an icon-only button in the form, an unlabeled role=button outside any form,
    // Enter in the username field of a page with no form
    case '/icon-btn.html': return page(`<form id="login" method="post" action="/done">
      <input id="user" name="email" type="email" autocomplete="username"><input id="pass" name="password" type="password">
      <button id="go" type="button"><svg width="16" height="16"><path d="M2 8h12"/></svg></button></form>
      <script>go.onclick = () => login.submit();</script>`);
    case '/outside-btn.html': return page(`<div><input id="user" type="text" autocomplete="username"><input id="pass" type="password"></div>
      <div id="go" role="button" tabindex="0" style="display:inline-block;width:40px;height:20px;background:#ccc"></div>
      <script>go.onclick = () => { location.href = '/done'; };</script>`);
    case '/formless.html': return page(`<div><input id="user" type="email"><input id="pass" type="password"></div>
      <script>user.addEventListener('keydown', (e) => { if (e.key === 'Enter') location.href = '/done'; });</script>`);
    // multi-step: the username on one page, the password on the next
    case '/step1.html': return page(`<form id="s1" method="get" action="/step2.html">
      <input id="user" name="email" type="email" autocomplete="username"><button type="submit">Next</button></form>`);
    case '/step2.html': return page(`<form id="login" method="post" action="/done">
      <input id="pass" name="password" type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>`);
    // a login form that stays on the page when submitted
    case '/stay.html': return page(`${LOGIN_FORM}<script>document.getElementById('login').addEventListener('submit', (e) => e.preventDefault());</script>`);
    default: return null;
  }
}

export function siteHandler() {
  return async (req, res) => {
    const url = new URL(req.url, 'http://site');
    const host = (req.headers.host || '').replace(/:\d+$/, '');
    const port = (req.headers.host || '').split(':').pop();
    const other = host === '127.0.0.1' ? `http://localhost:${port}` : `http://127.0.0.1:${port}`;
    const tricky = trickyPage(url.pathname, other);
    if (tricky) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(tricky); return; }
    if (url.pathname === '/login.html') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(LOGIN_PAGE); return; }
    if (url.pathname === '/done') {
      for await (const _ of req) { /* drain; the site does not keep it */ }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><title>Signed in</title><h1>Signed in</h1>');
      return;
    }
    if (url.pathname === '/plain.html') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><title>Plain</title><p>No login here.</p>'); return; }
    res.writeHead(404); res.end();
  };
}

function listen(handler, port, host) {
  return new Promise((resolve, reject) => {
    const s = http.createServer(handler);
    s.once('error', reject);
    s.listen(port, host, () => resolve(s));
  });
}

export async function startMock({ apiPort = 0, sitePort = 0, state = createMockState() } = {}) {
  const api = await listen(apiHandler(state), apiPort, '127.0.0.1');
  const site4 = await listen(siteHandler(), sitePort, '127.0.0.1');
  const port = site4.address().port;
  let site6 = null;
  try { site6 = await listen(siteHandler(), port, '::1'); } catch {}
  const apiBase = `http://127.0.0.1:${api.address().port}`;
  return {
    state, apiBase, sitePort: port,
    close: () => Promise.all([api, site4, site6].filter(Boolean).map((s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); }))),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const m = await startMock({ apiPort: Number(process.argv[2]) || 8787, sitePort: Number(process.argv[3]) || 8788 });
  console.log(`mock API  ${m.apiBase}`);
  console.log(`test site http://localhost:${m.sitePort}/login.html and http://127.0.0.1:${m.sitePort}/login.html`);
}
