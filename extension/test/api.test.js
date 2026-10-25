import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient, ApiError, NotPairedError, jwtClaims, waitForFill, waitForPairing, requestAndWaitForFill } from '../lib/api.js';
import { startMock, createMockState, approveDevice, phoneDecide, expireAccessTokens } from './mock-server.js';

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims) => `${b64u({ alg: 'none' })}.${b64u(claims)}.sig`;
const future = () => Math.floor(Date.now() / 1000) + 3600;

// In-memory token store that records the order of writes.
function memTokens(init = {}) {
  const t = { access: init.access || null, refresh: init.refresh || null, log: [] };
  return Object.assign(t, {
    async getAccess() { return t.access; },
    async setAccess(v) { t.log.push('setAccess'); t.access = v; },
    async getRefresh() { return t.refresh; },
    async setRefresh(v) { t.log.push('setRefresh'); t.refresh = v; },
    async clear() { t.log.push('clear'); t.access = null; t.refresh = null; },
  });
}

// Scripted fetch: each route is a list of responses consumed in order.
function scripted(routes) {
  const calls = [];
  const f = async (url, init) => {
    const path = new URL(url).pathname;
    const key = `${init.method} ${path}`;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ key, auth: init.headers.Authorization || null, body });
    const q = routes[key];
    if (!q || q.length === 0) throw new Error('unexpected ' + key);
    const [status, json] = q.length > 1 ? q.shift() : q[0];
    return { status, json: async () => json };
  };
  f.calls = calls;
  return f;
}

const noSleep = async () => {};

test('jwtClaims reads exp/jti and tolerates junk', () => {
  assert.equal(jwtClaims(jwt({ exp: 5, jti: 'j' })).jti, 'j');
  assert.equal(jwtClaims('nope'), null);
  assert.equal(jwtClaims('a.!!!.c'), null);
  assert.equal(jwtClaims(null), null);
});

test('redeem state machine: 428 pending, 403 denied, 410 expired/already_redeemed, 200 approved', async () => {
  const at = jwt({ exp: future() });
  const fetch = scripted({
    'POST /api/blindkey/fill/redeem': [
      [428, { error: 'approval_pending' }],
      [403, { error: 'denied' }],
      [410, { error: 'expired' }],
      [410, { error: 'already_redeemed' }],
      [200, { ok: true, value: 's3cret', username: 'me', origin: 'https://example.com', name: 'n', ref: 'DP-PWD-x' }],
      [500, { error: 'boom' }],
    ],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  assert.deepEqual(await c.redeemOnce('dpf_1'), { state: 'pending' });
  assert.deepEqual(await c.redeemOnce('dpf_1'), { state: 'denied' });
  assert.deepEqual(await c.redeemOnce('dpf_1'), { state: 'expired' });
  assert.deepEqual(await c.redeemOnce('dpf_1'), { state: 'already_redeemed' });
  const ok = await c.redeemOnce('dpf_1');
  assert.equal(ok.state, 'approved');
  assert.equal(ok.fill.value, 's3cret');
  assert.equal(ok.fill.origin, 'https://example.com');
  await assert.rejects(c.redeemOnce('dpf_1'), (e) => e instanceof ApiError && e.status === 500 && !/s3cret/.test(e.message));
  // A 403 'denied' must not be mistaken for a bad token: no refresh happened.
  assert.equal(fetch.calls.filter((x) => x.key === 'POST /api/identity/refresh').length, 0);
});

test('waitForFill polls through 428 until approved', async () => {
  const at = jwt({ exp: future() });
  const fetch = scripted({
    'POST /api/blindkey/fill/redeem': [[428, { error: 'approval_pending' }], [428, { error: 'approval_pending' }],
      [200, { ok: true, value: 'v', username: '', origin: 'https://a.test', name: 'n', ref: 'r' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  let pendings = 0;
  const r = await waitForFill(c, 'dpf_1', { sleep: noSleep, onPending: () => pendings++ });
  assert.equal(r.state, 'approved');
  assert.equal(pendings, 2);
});

test('waitForFill gives up at the client deadline and honours cancel', async () => {
  const at = jwt({ exp: future() });
  const fetch = scripted({ 'POST /api/blindkey/fill/redeem': [[428, { error: 'approval_pending' }]] });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  let t = 0;
  const r = await waitForFill(c, 'dpf_1', { expiresIn: 10, sleep: async (ms) => { t += ms; }, now: () => t });
  assert.equal(r.state, 'expired');
  let n = 0;
  const r2 = await waitForFill(c, 'dpf_1', { sleep: noSleep, isCancelled: () => ++n > 2 });
  assert.equal(r2.state, 'cancelled');
});

test('fill request: 201 pending; 403 carries bound_origins and no refresh', async () => {
  const at = jwt({ exp: future() });
  const fetch = scripted({
    'POST /api/blindkey/fill/request': [
      [201, { ok: true, request_id: 'dpf_a', status: 'pending', expires_in: 120 }],
      [403, { error: 'origin not bound', bound_origins: ['https://example.com'] }],
    ],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  assert.deepEqual(await c.requestFill('DP-1', 'https://example.com', 'x'), { request_id: 'dpf_a', status: 'pending', expires_in: 120, jti: null });
  await assert.rejects(c.requestFill('DP-1', 'https://evil.test', 'x'), (e) => e.status === 403 && e.boundOrigins[0] === 'https://example.com');
  assert.equal(fetch.calls.filter((x) => x.key === 'POST /api/identity/refresh').length, 0);
});

test('refresh: expiring access token is refreshed first; new refresh token persisted before access', async () => {
  const old = jwt({ exp: Math.floor(Date.now() / 1000) + 10 });
  const fresh = jwt({ exp: future(), jti: 'new' });
  const fetch = scripted({
    'POST /api/identity/refresh': [[200, { ok: true, token: fresh, refresh_token: 'r2' }]],
    'GET /api/blindkey/fill/candidates': [[200, { ok: true, candidates: [] }]],
  });
  const tokens = memTokens({ access: old, refresh: 'r1' });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens });
  await c.candidates('https://example.com');
  assert.deepEqual(tokens.log, ['setRefresh', 'setAccess']);
  assert.equal(tokens.refresh, 'r2');
  assert.equal(fetch.calls[0].body.refresh_token, 'r1');
  assert.equal(fetch.calls[1].auth, 'Bearer ' + fresh);
});

test('refresh: a 401 triggers one refresh and one retry', async () => {
  const at = jwt({ exp: future() });
  const fresh = jwt({ exp: future(), jti: 'n' });
  const fetch = scripted({
    'GET /api/blindkey/fill/candidates': [[401, { error: 'token invalid: revoked' }], [200, { ok: true, candidates: [{ ref: 'r', name: 'n', username: 'u', secret_type: 'password' }] }]],
    'POST /api/identity/refresh': [[200, { ok: true, token: fresh, refresh_token: 'r2' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r1' }) });
  const out = await c.candidates('https://example.com');
  assert.equal(out.length, 1);
  assert.deepEqual(fetch.calls.map((x) => x.key), ['GET /api/blindkey/fill/candidates', 'POST /api/identity/refresh', 'GET /api/blindkey/fill/candidates']);
});

test("refresh: dustforge's 403 'admin access or Bearer token required' is treated as a rejected bearer", async () => {
  const at = jwt({ exp: future() });
  const fresh = jwt({ exp: future() });
  const fetch = scripted({
    'POST /api/blindkey/store': [[403, { error: 'admin access or Bearer token required' }], [200, { ok: true, name: 'k', ref: 'DP-API-k', secret_type: 'api_key' }]],
    'POST /api/identity/refresh': [[200, { ok: true, token: fresh, refresh_token: 'r2' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r1' }) });
  const out = await c.store({ name: 'k', value: 'sk-123', secret_type: 'api_key' });
  assert.equal(out.ref, 'DP-API-k');
});

test('refresh: a dead refresh token clears both tokens and reports not paired', async () => {
  const fetch = scripted({ 'POST /api/identity/refresh': [[401, { error: 'invalid, expired, or revoked refresh token' }]] });
  const tokens = memTokens({ access: null, refresh: 'dead' });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens });
  await assert.rejects(c.candidates('https://example.com'), NotPairedError);
  assert.equal(tokens.refresh, null);
  assert.equal(await c.isPaired(), false);
});

test('refresh: a network error keeps the tokens', async () => {
  const fetch = async () => { throw new TypeError('Failed to fetch'); };
  const tokens = memTokens({ access: null, refresh: 'r1' });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens });
  await assert.rejects(c.candidates('https://example.com'), (e) => e instanceof ApiError && e.status === 0);
  assert.equal(tokens.refresh, 'r1');
});

test('refresh is single-flight: parallel calls share one rotation', async () => {
  let refreshes = 0;
  const fresh = jwt({ exp: future() });
  const fetch = async (url, init) => {
    const p = new URL(url).pathname;
    if (p === '/api/identity/refresh') {
      refreshes++;
      await new Promise((r) => setTimeout(r, 20));
      return { status: 200, json: async () => ({ ok: true, token: fresh, refresh_token: 'r' + (refreshes + 1) }) };
    }
    return { status: 200, json: async () => ({ ok: true, candidates: [] }) };
  };
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: null, refresh: 'r1' }) });
  await Promise.all([c.candidates('https://a.test'), c.candidates('https://b.test'), c.candidates('https://c.test')]);
  assert.equal(refreshes, 1);
});

test('no refresh token -> NotPairedError without any network call', async () => {
  const fetch = scripted({});
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens() });
  await assert.rejects(c.candidates('https://a.test'), NotPairedError);
  assert.equal(fetch.calls.length, 0);
});

test('device flow: 428 pending, 403 denied, 400 expired, 200 stores both tokens (refresh first)', async () => {
  const fresh = jwt({ exp: future() });
  const fetch = scripted({
    'POST /api/identity/device/code': [[200, { ok: true, device_code: 'dpd_x', user_code: 'ABCD-1234', interval: 5, expires_in: 600 }]],
    'POST /api/identity/device/token': [
      [428, { error: 'authorization_pending' }],
      [403, { error: 'access_denied' }],
      [400, { error: 'expired_token' }],
      [200, { ok: true, token: fresh, refresh_token: 'r1', scope: 'transact' }],
    ],
  });
  const tokens = memTokens();
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens });
  const p = await c.startPairing('test');
  assert.equal(fetch.calls[0].body.scope, 'transact');
  assert.equal(p.verification_url, 'https://demipass.com/device');
  assert.equal(p.verification_url_complete, 'https://demipass.com/device?code=ABCD-1234');
  assert.equal((await c.pollPairing('dpd_x')).state, 'pending');
  assert.equal((await c.pollPairing('dpd_x')).state, 'denied');
  assert.equal((await c.pollPairing('dpd_x')).state, 'expired');
  assert.equal((await c.pollPairing('dpd_x')).state, 'paired');
  assert.deepEqual(tokens.log, ['setRefresh', 'setAccess']);
});

test('sign out revokes the refresh token and the access jti, and clears local tokens', async () => {
  const at = jwt({ exp: future(), jti: 'jti_1' });
  const fetch = scripted({
    'POST /api/identity/refresh/revoke': [[200, { ok: true, revoked: true }]],
    'POST /api/identity/tokens/revoke': [[200, { ok: true, revoked: true }]],
  });
  const tokens = memTokens({ access: at, refresh: 'r1' });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens });
  assert.deepEqual(await c.signOut(), { refreshRevoked: true, accessRevoked: true });
  assert.equal(fetch.calls[0].body.refresh_token, 'r1');
  assert.equal(fetch.calls[1].body.jti, 'jti_1');
  assert.equal(tokens.refresh, null);
  assert.equal(tokens.access, null);
});

test('store sends login + origins (contract field names)', async () => {
  const at = jwt({ exp: future() });
  const fetch = scripted({ 'POST /api/blindkey/store': [[200, { ok: true, name: 'n', ref: 'DP-PWD-n', secret_type: 'password' }]] });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  await c.store({ name: 'n', value: 'pw', secret_type: 'password', login: 'me@example.com', origins: ['https://example.com'] });
  assert.deepEqual(fetch.calls[0].body, { name: 'n', value: 'pw', secret_type: 'password', login: 'me@example.com', origins: ['https://example.com'] });
  assert.equal('username' in fetch.calls[0].body, false);
});

// ---- the same client against the mock over real HTTP ----------------------

test('end to end against the mock: pair, store, candidates, fill approved / denied on the phone, sign out', async (t) => {
  const state = createMockState();
  const m = await startMock({ state });
  t.after(() => m.close());
  const tokens = memTokens();
  const c = new ApiClient({ base: m.apiBase, fetch, tokens });

  const p = await c.startPairing('node test');
  await approveDevice(state, p.user_code);
  const paired = await waitForPairing(c, p.device_code, { interval: 0, sleep: noSleep });
  assert.equal(paired.state, 'paired');

  await c.store({ name: 'site', value: 'hunter2', secret_type: 'password', login: 'me@example.com', origins: ['https://example.com'] });
  const cands = await c.candidates('https://example.com');
  assert.deepEqual(cands.map((x) => [x.name, x.username]), [['site', 'me@example.com']]);
  assert.deepEqual(await c.candidates('https://login.example.com'), []);

  await assert.rejects(c.requestFill(cands[0].ref, 'https://evil.test', 't'), (e) => e.status === 403);
  const req = await c.requestFill(cands[0].ref, 'https://example.com', 't');
  assert.equal(req.status, 'pending');
  assert.equal((await c.redeemOnce(req.request_id)).state, 'pending');
  assert.equal(await phoneDecide(m.apiBase, state, req.request_id, 'approve'), 200);
  const r = await c.redeemOnce(req.request_id);
  assert.equal(r.state, 'approved');
  assert.equal(r.fill.value, 'hunter2');
  assert.equal((await c.redeemOnce(req.request_id)).state, 'already_redeemed');

  const req2 = await c.requestFill(cands[0].ref, 'https://example.com', 't');
  assert.equal(await phoneDecide(m.apiBase, state, req2.request_id, 'deny'), 200);
  assert.equal((await c.redeemOnce(req2.request_id)).state, 'denied');

  // The mock never records a value in its call log.
  assert.equal(JSON.stringify(state.calls).includes('hunter2'), false);

  const out = await c.signOut();
  assert.equal(out.refreshRevoked, true);
  assert.equal(await c.isPaired(), false);
});

// ---- fill requests are bound to the asking token (jti) ---------------------

const fillRoutes = (extra = {}) => ({
  'POST /api/blindkey/fill/request': [[201, { ok: true, request_id: 'dpf_a', status: 'pending', expires_in: 120 }]],
  ...extra,
});

test('requestFill refreshes first when the access token expires within 5 minutes', async () => {
  const soon = jwt({ exp: Math.floor(Date.now() / 1000) + 240, jti: 'old' }); // 4 min: outside the 60 s skew
  const fresh = jwt({ exp: future(), jti: 'new' });
  const fetch = scripted(fillRoutes({ 'POST /api/identity/refresh': [[200, { ok: true, token: fresh, refresh_token: 'r2' }]] }));
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: soon, refresh: 'r1' }) });
  const req = await c.requestFill('DP-1', 'https://example.com', 'x');
  assert.deepEqual(fetch.calls.map((x) => x.key), ['POST /api/identity/refresh', 'POST /api/blindkey/fill/request']);
  assert.equal(fetch.calls[1].auth, 'Bearer ' + fresh);
  assert.equal(req.jti, 'new');
});

test('requestFill does not refresh when the token has more than 5 minutes left', async () => {
  const ok = jwt({ exp: Math.floor(Date.now() / 1000) + 400, jti: 'cur' });
  const fetch = scripted(fillRoutes());
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: ok, refresh: 'r1' }) });
  const req = await c.requestFill('DP-1', 'https://example.com', 'x');
  assert.deepEqual(fetch.calls.map((x) => x.key), ['POST /api/blindkey/fill/request']);
  assert.equal(req.jti, 'cur');
});

test('redeem 404 after the token changed means the request was lost to a refresh', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({
    'POST /api/blindkey/fill/redeem': [[401, { error: 'token invalid: jwt expired' }], [404, { error: 'fill request not found' }]],
    'POST /api/identity/refresh': [[200, { token: jwt({ exp: future(), jti: 'j2' }), refresh_token: 'r2' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  assert.deepEqual(await c.redeemOnce('dpf_a', 'j'), { state: 'lost' });
});

test('redeem 404 with the same token is final (login deleted): no re-ask, no extra phone card', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({
    'POST /api/blindkey/fill/request': [[201, { ok: true, request_id: 'dpf_1', status: 'pending', expires_in: 120 }]],
    'POST /api/blindkey/fill/redeem': [[404, { error: 'the login was deleted or revoked since the request' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  const r = await requestAndWaitForFill(c, { ref: 'DP-1', origin: 'https://example.com', sleep: noSleep });
  assert.equal(r.state, 'gone');
  assert.equal(r.error, 'the login was deleted or revoked since the request');
  assert.equal(fetch.calls.filter((x) => x.key === 'POST /api/blindkey/fill/request').length, 1);
});

test('a 429 while polling backs off and keeps waiting; the approved fill still arrives', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({
    'POST /api/blindkey/fill/request': [[201, { ok: true, request_id: 'dpf_1', status: 'pending', expires_in: 120 }]],
    'POST /api/blindkey/fill/redeem': [
      [428, { error: 'approval_pending' }],
      [429, { error: 'Rate limit exceeded' }],
      [429, { error: 'Rate limit exceeded' }],
      [428, { error: 'approval_pending' }],
      [200, { ok: true, value: 'v', username: 'u', origin: 'https://example.com', name: 'n', ref: 'DP-1' }],
    ],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  const waits = [];
  const r = await requestAndWaitForFill(c, { ref: 'DP-1', origin: 'https://example.com', sleep: async (ms) => { waits.push(ms); }, intervalMs: 2000 });
  assert.equal(r.state, 'approved');
  assert.deepEqual(waits, [2000, 4000, 8000, 2000]);
});

test('waitForFill reports lost without a redeem once the jti has changed', async () => {
  const fetch = scripted({});
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: jwt({ exp: future(), jti: 'new' }), refresh: 'r' }) });
  const r = await waitForFill(c, 'dpf_a', { jti: 'old', sleep: noSleep });
  assert.equal(r.state, 'lost');
  assert.equal(fetch.calls.length, 0);
});

test('requestAndWaitForFill asks again once after a lost request, then succeeds', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({
    'POST /api/blindkey/fill/request': [
      [201, { ok: true, request_id: 'dpf_1', status: 'pending', expires_in: 120 }],
      [201, { ok: true, request_id: 'dpf_2', status: 'pending', expires_in: 120 }],
    ],
    'POST /api/blindkey/fill/redeem': [
      [428, { error: 'approval_pending' }],
      [401, { error: 'token invalid: jwt expired' }], // the asking token dies -> refresh -> 404
      [404, { error: 'fill request not found' }],
      [428, { error: 'approval_pending' }],
      [200, { ok: true, value: 'v', username: 'u', origin: 'https://example.com', name: 'n', ref: 'DP-1' }],
    ],
    'POST /api/identity/refresh': [[200, { token: jwt({ exp: future(), jti: 'j2' }), refresh_token: 'r2' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  const asks = [];
  const r = await requestAndWaitForFill(c, { ref: 'DP-1', origin: 'https://example.com', clientLabel: 'x', sleep: noSleep, onAsk: (req, n) => asks.push([req.request_id, n]) });
  assert.equal(r.state, 'approved');
  assert.equal(r.asks, 2);
  assert.deepEqual(asks, [['dpf_1', 1], ['dpf_2', 2]]);
  assert.equal(fetch.calls.filter((x) => x.key === 'POST /api/blindkey/fill/redeem')[4].body.request_id, 'dpf_2');
});

test('requestAndWaitForFill gives up after the second lost request', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({
    'POST /api/blindkey/fill/request': [[201, { ok: true, request_id: 'dpf_x', status: 'pending', expires_in: 120 }]],
    'POST /api/blindkey/fill/redeem': [[401, { error: 'token invalid: jwt expired' }], [404, { error: 'fill request not found' }], [401, { error: 'token invalid: jwt expired' }], [404, { error: 'fill request not found' }]],
    'POST /api/identity/refresh': [[200, { token: jwt({ exp: future(), jti: 'j2' }), refresh_token: 'r2' }], [200, { token: jwt({ exp: future(), jti: 'j3' }), refresh_token: 'r3' }]],
  });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  const r = await requestAndWaitForFill(c, { ref: 'DP-1', origin: 'https://example.com', clientLabel: 'x', sleep: noSleep });
  assert.equal(r.state, 'lost');
  assert.equal(fetch.calls.filter((x) => x.key === 'POST /api/blindkey/fill/request').length, 2);
});

test('against the mock: a refresh while waiting orphans the request (404); the re-ask is approved', async (t) => {
  const state = createMockState();
  const m = await startMock({ state });
  t.after(() => m.close());
  const c = new ApiClient({ base: m.apiBase, fetch, tokens: memTokens() });
  const p = await c.startPairing('node test');
  await approveDevice(state, p.user_code);
  await waitForPairing(c, p.device_code, { interval: 0, sleep: noSleep });
  await c.store({ name: 'site', value: 'hunter2', secret_type: 'password', login: 'me', origins: ['https://example.com'] });
  const ref = (await c.candidates('https://example.com'))[0].ref;

  const asks = [];
  let expired = false;
  const r = await requestAndWaitForFill(c, {
    ref, origin: 'https://example.com', clientLabel: 't', intervalMs: 0,
    sleep: async () => {
      if (asks.length === 1 && !expired) { expired = true; expireAccessTokens(state); } // token dies mid-wait
      else if (asks.length === 2) await phoneDecide(m.apiBase, state, asks[1], 'approve');
    },
    onAsk: (req) => asks.push(req.request_id),
  });
  assert.equal(r.state, 'approved');
  assert.equal(r.fill.value, 'hunter2');
  assert.equal(r.asks, 2);
  const redeems = state.calls.filter((x) => x.path === '/api/blindkey/fill/redeem').map((x) => x.status);
  assert.ok(redeems.includes(404), 'old request answered 404 for the refreshed token: ' + redeems);
  assert.equal(state.fills.get(asks[0]).status, 'pending', 'first request never redeemed');
});

// ---- sign-out races (audit S1) --------------------------------------------------

function gated() { let release; const gate = new Promise((r) => { release = r; }); return { gate, release }; }

test('sign-out while a refresh is in flight: the late refresh is discarded and revoked, not persisted', async () => {
  const { gate, release } = gated();
  const tokens = memTokens({ refresh: 'rt-1' });
  const calls = [];
  const c = new ApiClient({ base: 'https://api.test', tokens, fetch: async (url, init) => {
    const path = new URL(url).pathname; const body = init.body ? JSON.parse(init.body) : {};
    calls.push([path, body.refresh_token || body.jti || null]);
    if (path === '/api/identity/refresh') { await gate; return { status: 200, json: async () => ({ token: jwt({ exp: future(), jti: 'late' }), refresh_token: 'rt-2' }) }; }
    return { status: 200, json: async () => ({ ok: true }) };
  } });
  const inflight = c.refresh().catch((e) => e);
  await new Promise((r) => setTimeout(r, 5));
  const out = c.signOut();
  await new Promise((r) => setTimeout(r, 5));
  release();
  await out;
  assert.ok((await inflight) instanceof NotPairedError);
  assert.equal(await c.isPaired(), false);
  assert.equal(tokens.refresh, null);
  assert.equal(tokens.access, null);
  const revoked = calls.filter(([p]) => p === '/api/identity/refresh/revoke').map(([, t]) => t);
  assert.ok(revoked.includes('rt-2'), 'the refresh token minted after sign-out is revoked: ' + revoked.join(','));
  assert.ok(revoked.includes('rt-1'));
  assert.ok(calls.some(([p, j]) => p === '/api/identity/tokens/revoke' && j === 'late'), 'and its access token');
});

test('sign-out while a pairing poll is in flight: the late pairing is discarded and revoked', async () => {
  const { gate, release } = gated();
  const tokens = memTokens({});
  const revoked = [];
  const c = new ApiClient({ base: 'https://api.test', tokens, fetch: async (url, init) => {
    const path = new URL(url).pathname; const body = init.body ? JSON.parse(init.body) : {};
    if (path === '/api/identity/device/token') { await gate; return { status: 200, json: async () => ({ token: jwt({ exp: future(), jti: 'p' }), refresh_token: 'rt-p' }) }; }
    if (path === '/api/identity/refresh/revoke') revoked.push(body.refresh_token);
    return { status: 200, json: async () => ({ ok: true }) };
  } });
  const poll = c.pollPairing('dc');
  await new Promise((r) => setTimeout(r, 5));
  const out = c.signOut();
  await new Promise((r) => setTimeout(r, 5));
  release();
  await out;
  assert.deepEqual(await poll, { state: 'cancelled' });
  assert.equal(await c.isPaired(), false);
  assert.deepEqual(revoked, ['rt-p']);
});

test('a refresh that finished before sign-out is revoked by sign-out', async () => {
  const tokens = memTokens({ refresh: 'rt-1' });
  const revoked = [];
  const c = new ApiClient({ base: 'https://api.test', tokens, fetch: async (url, init) => {
    const path = new URL(url).pathname; const body = init.body ? JSON.parse(init.body) : {};
    if (path === '/api/identity/refresh') return { status: 200, json: async () => ({ token: jwt({ exp: future(), jti: 'a2' }), refresh_token: 'rt-2' }) };
    if (path === '/api/identity/refresh/revoke') revoked.push(body.refresh_token);
    return { status: 200, json: async () => ({ ok: true }) };
  } });
  await c.refresh();
  await c.signOut();
  assert.deepEqual(revoked, ['rt-2']);
  assert.equal(await c.isPaired(), false);
});

// ---- withdrawing an abandoned fill request ---------------------------------------

test('withdrawFill withdraws by request_id (never a lookup by ref + origin)', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({ 'POST /api/blindkey/fill/withdraw': [[200, { ok: true, status: 'withdrawn' }]] });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  assert.deepEqual(await c.withdrawFill('dpf_1'), { withdrawn: true, status: 'withdrawn' });
  assert.deepEqual(fetch.calls.map((x) => [x.key, x.body]), [['POST /api/blindkey/fill/withdraw', { request_id: 'dpf_1' }]]);
});

test('redeem 410 withdrawn is its own state', async () => {
  const at = jwt({ exp: future(), jti: 'j' });
  const fetch = scripted({ 'POST /api/blindkey/fill/redeem': [[410, { error: 'withdrawn' }]] });
  const c = new ApiClient({ base: 'https://api.test', fetch, tokens: memTokens({ access: at, refresh: 'r' }) });
  assert.deepEqual(await c.redeemOnce('dpf_1', 'j'), { state: 'withdrawn' });
});

test('against the mock: withdraw takes only this request off the phone; a sibling request with the same ref + origin stays (audit N5)', async (t) => {
  const m = await startMock({ state: createMockState() });
  t.after(() => m.close());
  const { state } = m;
  const s = (await import('./mock-server.js')).mintSession(state);
  const c = new ApiClient({ base: m.apiBase, fetch, tokens: memTokens({ access: s.token, refresh: s.refresh_token }) });
  await c.store({ name: 'w', value: 'pw', secret_type: 'password', origins: ['https://a.test'] });
  const ref = [...state.secrets.keys()][0];
  const tab1 = await c.requestFill(ref, 'https://a.test', 'x');
  const tab2 = await c.requestFill(ref, 'https://a.test', 'x');
  assert.deepEqual(await c.withdrawFill(tab1.request_id), { withdrawn: true, status: 'withdrawn' });
  assert.equal(state.fills.get(tab1.request_id).status, 'withdrawn');
  assert.equal(state.fills.get(tab2.request_id).status, 'pending', 'the sibling is untouched');
  assert.deepEqual(await c.redeemOnce(tab1.request_id, tab1.jti), { state: 'withdrawn' });
  // Another session cannot withdraw it.
  const other = (await import('./mock-server.js')).mintSession(state);
  const c2 = new ApiClient({ base: m.apiBase, fetch, tokens: memTokens({ access: other.token, refresh: other.refresh_token }) });
  assert.deepEqual(await c2.withdrawFill(tab2.request_id), { withdrawn: false, status: 'not_found' });
  assert.equal(state.fills.get(tab2.request_id).status, 'pending');
});


test('sign-out does not hang on a refresh that never answers; the late answer is still discarded', async () => {
  const { gate, release } = gated();
  const tokens = memTokens({ refresh: 'rt-1' });
  const revoked = [];
  const c = new ApiClient({ base: 'https://api.test', tokens, fetch: async (url, init) => {
    const path = new URL(url).pathname; const body = init.body ? JSON.parse(init.body) : {};
    if (path === '/api/identity/refresh') { await gate; return { status: 200, json: async () => ({ token: jwt({ exp: future(), jti: 'late' }), refresh_token: 'rt-late' }) }; }
    if (path === '/api/identity/refresh/revoke') revoked.push(body.refresh_token);
    return { status: 200, json: async () => ({ ok: true }) };
  } });
  const inflight = c.refresh().catch((e) => e);
  await new Promise((r) => setTimeout(r, 5));
  const t0 = Date.now();
  await c.signOut(); // the probe's order: sign out first, the refresh answers afterwards
  assert.ok(Date.now() - t0 < 4500, 'sign-out returned');
  release();
  assert.ok((await inflight) instanceof NotPairedError);
  assert.equal(await c.isPaired(), false);
  assert.ok(revoked.includes('rt-late'));
});

test('a sign-out landing between the generation check and the write still wins', async () => {
  const tokens = memTokens({ refresh: 'rt-1' });
  const c = new ApiClient({ base: 'https://api.test', tokens, fetch: async () => ({ status: 200, json: async () => ({ ok: true }) }) });
  const origSet = tokens.setAccess;
  tokens.setAccess = async (v) => { await origSet(v); c.generation++; }; // sign-out bumps right after the write
  await assert.rejects(c.persist(c.generation, 'rt-new', jwt({ exp: future(), jti: 'n' })), NotPairedError);
  assert.equal(tokens.refresh, null);
  assert.equal(tokens.access, null);
});
