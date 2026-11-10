'use strict';
// fleetgate-mcp: onboarding (consent filed for app approval → approval_id → token), submit through the door with a
// re-mint on 401, refusals passed through, and the token never appearing in any tool answer. Mock DemiPass + mock door.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

const state = { consents: [], approved: false, minted: [], doorCalls: [], doorRejectFirst: true };
function json(res, status, body) { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); }
function readBody(req) { return new Promise(ok => { let b = ''; req.on('data', c => { b += c; }); req.on('end', () => ok(b ? JSON.parse(b) : {})); }); }

const dpSrv = http.createServer(async (req, res) => {
  const b = await readBody(req);
  if (req.headers.authorization !== 'Bearer pane-session') return json(res, 401, { error: 'bad session' });
  if (req.method === 'GET' && req.url === '/api/services/consents') return json(res, 200, { ok: true, mine: state.consents, approved_by_me: [] });
  if (req.method === 'POST' && req.url === '/api/services/consent') {
    if (!b.approval_id) return json(res, 202, { status: 'approval_pending', approval_id: 77, expires_at: '2026-11-11T00:00:00Z' });
    if (!state.approved || b.approval_id !== 77) return json(res, 202, { status: 'approval_pending', approval_id: 77 });
    state.consents.push({ id: 9, service: b.service, daily_cap_dd: b.daily_cap_dd, status: 'active' });
    return json(res, 201, { ok: true, consent_id: 9, service: b.service, daily_cap_dd: b.daily_cap_dd });
  }
  if (req.method === 'POST' && req.url === '/api/services/token') {
    const n = state.minted.length + 1; state.minted.push(b);
    return json(res, 201, { ok: true, token: 'svc-token-SECRET-' + n, token_id: 'jti-' + n, service: b.service, cap_dd: b.cap_dd, expires_at: new Date(Date.now() + 3600e3).toISOString() });
  }
  json(res, 404, { error: 'no route' });
});
const doorSrv = http.createServer(async (req, res) => {
  const b = await readBody(req);
  if (req.url === '/door/health') return json(res, 200, { ok: true, version: 'test', tenant: 'fleetgate' });
  if (req.url === '/door/v1/prices') return json(res, 200, { slug: 'fleetgate', actions: [{ action: 'submit', price_dd: 696 }] });
  if (req.url === '/door/v1/pulls' && req.method === 'POST') {
    state.doorCalls.push({ auth: req.headers.authorization, body: b });
    if (state.doorRejectFirst) { state.doorRejectFirst = false; return json(res, 401, { error: 'token expired' }); }
    if (b.repo === 'broke') return json(res, 402, { error: 'insufficient DD' });
    return json(res, 201, { ok: true, pull: { number: 51, url: 'https://repo.dustroot.com/atlas/boltcluster/pulls/51' }, charges: [{ action: 'submit', dd: 696 }], token_id: 'jti-x' });
  }
  json(res, 404, { error: 'no route' });
});

let mcp;
const call = async (name, args = {}) => {
  const r = await mcp.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  const text = r.result.content[0].text;
  assert.ok(!/svc-token-SECRET/.test(text), `${name} must never return the token: ${text}`);
  return JSON.parse(text);
};

test.before(async () => {
  await new Promise(ok => dpSrv.listen(0, '127.0.0.1', ok)); await new Promise(ok => doorSrv.listen(0, '127.0.0.1', ok));
  process.env.DEMIPASS_TOKEN = 'pane-session';
  process.env.DEMIPASS_URL = `http://127.0.0.1:${dpSrv.address().port}`;
  process.env.FLEETGATE_DOOR_URL = `http://127.0.0.1:${doorSrv.address().port}/door`;
  process.env.FLEETGATE_DAILY_CAP_DD = '3000';
  mcp = require('../fleetgate-mcp.js');
});
test.after(() => { dpSrv.close(); doorSrv.close(); });

test('tools/list names the four tools', async () => {
  const r = await mcp.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.deepStrictEqual(r.result.tools.map(t => t.name).sort(), ['fleetgate_onboard', 'fleetgate_prices', 'fleetgate_status', 'fleetgate_submit']);
});

test('submit before onboarding: refused, nothing sent to the door', async () => {
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'a.md', content: 'x' }] });
  assert.strictEqual(r.ok, false); assert.match(r.error, /fleetgate_onboard/);
  assert.strictEqual(state.doorCalls.length, 0);
});

test('onboard: no consent → approval_pending with approval_id; still pending until approved; then a token', async () => {
  let r = await call('fleetgate_onboard', {});
  assert.strictEqual(r.status, 'approval_pending'); assert.strictEqual(r.approval_id, 77); assert.match(r.next, /DemiPass app/);
  r = await call('fleetgate_onboard', { approval_id: 77 });
  assert.strictEqual(r.status, 'approval_pending');
  state.approved = true;
  r = await call('fleetgate_onboard', { approval_id: 77 });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.consent.id, 9); assert.strictEqual(r.token_id, 'jti-1');
  assert.strictEqual(state.minted[0].cap_dd, 3000, 'the token may spend the whole daily consent (one submission > the 500 default)');
  assert.strictEqual(state.minted[0].ttl, '24h');
});

test('onboard again: the existing consent is reused, never re-filed', async () => {
  const r = await call('fleetgate_onboard', {});
  assert.strictEqual(r.ok, true); assert.strictEqual(r.consent.existing, true); assert.strictEqual(state.consents.length, 1);
});

test('submit: a 401 re-mints once and retries with the same submission_id; the PR comes back', async () => {
  const before = state.minted.length;
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 'docs: fix', files: [{ path: 'docs/a.md', content: 'hello' }], submission_id: 'sub-12345678' });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.pull.number, 51); assert.strictEqual(r.submission_id, 'sub-12345678');
  assert.strictEqual(state.minted.length, before + 1, 're-minted once');
  const [a, b] = state.doorCalls.slice(-2);
  assert.notStrictEqual(a.auth, b.auth); assert.strictEqual(a.body.submission_id, b.body.submission_id);
  assert.match(b.auth, /^Bearer svc-token-SECRET-/);
});

test('submit refusals pass through (402), and bad input is refused locally', async () => {
  let r = await call('fleetgate_submit', { repo: 'broke', title: 't', files: [{ path: 'a.md', content: 'x' }] });
  assert.strictEqual(r.ok, false); assert.strictEqual(r.http_status, 402); assert.match(r.hint, /Nothing was created/);
  const n = state.doorCalls.length;
  r = await call('fleetgate_submit', { repo: '../evil', title: 't', files: [{ path: 'a', content: 'x' }] }); assert.strictEqual(r.ok, false);
  r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [] }); assert.strictEqual(r.ok, false);
  r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'a', content: 'x' }], submission_id: 'short' }); assert.strictEqual(r.ok, false);
  assert.strictEqual(state.doorCalls.length, n, 'nothing sent for local refusals');
});

test('prices and status', async () => {
  const p = await call('fleetgate_prices'); assert.strictEqual(p.ok, true); assert.strictEqual(p.actions[0].price_dd, 696);
  const s = await call('fleetgate_status'); assert.strictEqual(s.onboarded, true); assert.strictEqual(s.door_health.ok, true); assert.ok(s.token_id);
});
