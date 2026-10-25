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
    fills: new Map(), // id -> { ref, origin, jti, status, expires, client_label, created } — bound to the asking token
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
      const id = rand('dpf_', 12);
      state.fills.set(id, { ref: body.ref, origin, jti: a.jti, status: 'pending', expires: Date.now() + 120_000, client_label: String(body.client_label || ''), created: new Date().toISOString() });
      return send(201, { ok: true, request_id: id, status: 'pending', expires_in: 120 });
    }
    if (p === '/api/blindkey/fill/redeem' && req.method === 'POST') {
      const f = state.fills.get(body.request_id);
      meta.request_id = body.request_id;
      // Contract: a carbon session is one access token (jti). A refreshed token gets 404.
      if (!f || f.jti !== a.jti) return send(404, { error: 'fill request not found' });
      if (f.status === 'redeemed') return send(410, { error: 'already_redeemed' });
      if (f.expires < Date.now()) return send(410, { error: 'expired' });
      if (f.status === 'denied') return send(403, { error: 'denied' });
      if (f.status === 'pending') return send(428, { error: 'approval_pending' });
      f.status = 'redeemed';
      const s = state.secrets.get(f.ref);
      meta.event = 'secret_filled';
      return send(200, { ok: true, value: s.value, username: s.login, origin: f.origin, name: s.name, ref: f.ref });
    }
    if (p === '/api/blindkey/fill/pending' && req.method === 'GET') {
      const requests = [...state.fills].filter(([, f]) => f.status === 'pending' && f.expires > Date.now())
        .map(([id, f]) => { const s = state.secrets.get(f.ref); return { id, intent: 'fill:' + id, name: s.name, ref: f.ref, username: s.login, origin: f.origin, client_label: f.client_label, created_at: f.created, expires_at: new Date(f.expires).toISOString() }; });
      return send(200, { ok: true, requests });
    }
    const m = p.match(/^\/api\/blindkey\/fill\/(dpf_[\w-]+)\/(approve|deny)$/);
    if (m && req.method === 'POST') {
      const f = state.fills.get(m[1]);
      if (!f || f.status !== 'pending') return send(404, { error: 'no pending request' });
      if (f.jti === a.jti) return send(409, { error: 'the requesting session cannot approve its own fill' });
      if (m[2] === 'deny') { f.status = 'denied'; return send(200, { ok: true, status: 'denied' }); }
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

export async function phoneDecide(apiBase, state, requestId, decision = 'approve') {
  const phone = mintSession(state, 'transact', 'sid_phone');
  const h = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + phone.token };
  if (decision === 'approve') {
    await fetch(apiBase + '/api/identity/gate/verify', { method: 'POST', headers: h, body: JSON.stringify({ gate: 'pin', pin: state.pin, intent: 'fill:' + requestId }) });
  }
  const r = await fetch(`${apiBase}/api/blindkey/fill/${requestId}/${decision}`, { method: 'POST', headers: h });
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

export function siteHandler() {
  return async (req, res) => {
    const url = new URL(req.url, 'http://site');
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
