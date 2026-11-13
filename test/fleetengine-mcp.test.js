'use strict';
// fleetengine-mcp: onboarding (consent filed for app approval → approval_id → token with a follow-up budget), runs
// through the service with a re-mint on 401, job_id replay, refusals passed through (DemiPass's 402 and its own 202),
// the token bound to its wallet and never appearing in any tool answer. Mock DemiPass + mock FleetEngine.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

const jwt = (sub) => 'eyJhbGciOiJFZERTQSJ9.' + Buffer.from(JSON.stringify({ sub, scope: 'transact' })).toString('base64url') + '.sig';
const SESSION_A = jwt('did:key:zPaneA'), SESSION_B = jwt('did:key:zPaneB');
const walletOf = new Map();   // service token → wallet
const state = { consents: [], approved: false, minted: [], posts: [], gets: [], consentPosts: [], rejectFirst: true, dropNext: false, jobs: new Map() };
function json(res, status, body) { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); }
function readBody(req) { return new Promise(ok => { let b = ''; req.on('data', c => { b += c; }); req.on('end', () => ok(b ? JSON.parse(b) : {})); }); }

const dpSrv = http.createServer(async (req, res) => {
  const b = await readBody(req);
  if (req.headers.authorization !== 'Bearer ' + SESSION_A && req.headers.authorization !== 'Bearer ' + SESSION_B) return json(res, 401, { error: 'bad session' });
  if (req.method === 'GET' && req.url === '/api/services/consents') return json(res, 200, { ok: true, mine: state.consents, approved_by_me: [] });
  if (req.method === 'POST' && req.url === '/api/services/consent') {
    state.consentPosts.push(b);
    if (!b.approval_id || !state.approved || b.approval_id !== 41) return json(res, 202, { status: 'approval_pending', approval_id: 41, expires_at: '2026-11-14T00:00:00Z' });
    if (b.daily_cap_dd !== 6000) return json(res, 409, { error: 'approval was for a different call' });
    state.consents.push({ id: 12, service: b.service, daily_cap_dd: b.daily_cap_dd, status: 'active' });
    return json(res, 201, { ok: true, consent_id: 12, service: b.service, daily_cap_dd: b.daily_cap_dd });
  }
  if (req.method === 'POST' && req.url === '/api/services/token') {
    const n = state.minted.length + 1; state.minted.push(b);
    const t = 'svc-token-SECRET-bbbbbbbbbbbb-' + n;
    walletOf.set(t, req.headers.authorization === 'Bearer ' + SESSION_A ? 'did:key:zPaneA' : 'did:key:zPaneB');
    return json(res, 201, { ok: true, token: t, token_id: 'jti-' + n, service: b.service, cap_dd: b.cap_dd, expires_at: new Date(Date.now() + 3600e3).toISOString() });
  }
  json(res, 404, { error: 'no route' });
});

// Mock FleetEngine, in the shape of fleetengine lib/app.js: 202 {ok, job_id, status, digest, charges}; replay finds it.
const feSrv = http.createServer(async (req, res) => {
  const b = await readBody(req);
  const tok = String(req.headers.authorization || '').replace(/^Bearer /, '');
  if (req.url === '/fe/health') return json(res, 200, { ok: true, version: 'fleetengine/0.1', tenant: 'fleetengine', engines: ['audit'] });
  if (req.url === '/fe/v1/engines') return json(res, 200, { engines: [{ name: 'audit', calls_models: false, pools: ['files'] }] });
  if (req.url === '/fe/v1/prices') return json(res, 200, { slug: 'fleetengine', actions: [{ action: 'job', price_dd: 14 }] });
  if (req.url === '/fe/v1/jobs' && req.method === 'POST') {
    state.posts.push({ auth: req.headers.authorization, body: b });
    if (state.dropNext) { state.dropNext = false; return req.socket.destroy(); }
    if (state.rejectFirst) { state.rejectFirst = false; return json(res, 401, { error: 'token expired' }); }
    if (!walletOf.has(tok)) return json(res, 401, { error: 'unknown token' });
    if (b.requisition.premise === 'broke') return json(res, 402, { error: 'insufficient DD', refused: 'balance' });
    if (b.requisition.premise === 'needs-approval') return json(res, 202, { status: 'approval_pending', approval_id: 99 });
    const key = walletOf.get(tok) + ':' + b.job_id;
    const replayed = state.jobs.has(key);
    if (!replayed) state.jobs.set(key, { job_id: b.job_id, status: 'queued', requisition: b.requisition });
    return json(res, 202, { ok: true, ...(replayed ? { replayed: true } : {}), job_id: b.job_id, status: 'queued', digest: 'd'.repeat(64), charges: [{ action: 'job', dd: 14 }] });
  }
  const m = /^\/fe\/v1\/jobs\/([A-Za-z0-9_-]+)$/.exec(req.url);
  if (m && req.method === 'GET') {
    state.gets.push({ auth: req.headers.authorization, id: m[1] });
    if (!walletOf.has(tok)) return json(res, 401, { error: 'unknown token' });
    const j = state.jobs.get(walletOf.get(tok) + ':' + m[1]);
    return j ? json(res, 200, { job_id: j.job_id, status: 'done', outcome: { countersign: 'countersigned_with_confidence' } }) : json(res, 404, { error: 'no such job for this wallet', job_id: m[1] });
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
const REQ = { pool: { files: [{ path: 'spec.md', content: '# spec' }] }, premise: 'the spec is complete', effort: 'scan' };

test.before(async () => {
  await new Promise(ok => dpSrv.listen(0, '127.0.0.1', ok)); await new Promise(ok => feSrv.listen(0, '127.0.0.1', ok));
  process.env.DEMIPASS_TOKEN = SESSION_A;
  process.env.DEMIPASS_URL = `http://127.0.0.1:${dpSrv.address().port}`;
  process.env.FLEETENGINE_URL = `http://127.0.0.1:${feSrv.address().port}/fe`;
  process.env.FLEETENGINE_DAILY_CAP_DD = '3000';
  mcp = require('../fleetengine-mcp.js');
});
test.after(() => { dpSrv.close(); feSrv.close(); });

test('tools/list names the seven tools', async () => {
  const r = await mcp.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.deepStrictEqual(r.result.tools.map(t => t.name).sort(),
    ['fleetengine_engines', 'fleetengine_job', 'fleetengine_onboard', 'fleetengine_pattern_run', 'fleetengine_prices', 'fleetengine_run', 'fleetengine_status']);
});

test('run before onboarding: refused, nothing sent to FleetEngine, no consent filed on the phone', async () => {
  const r = await call('fleetengine_run', { engine: 'audit', requisition: REQ });
  assert.strictEqual(r.ok, false); assert.match(r.error, /fleetengine_onboard/); assert.match(r.note, /nothing was sent to FleetEngine/);
  assert.strictEqual(state.posts.length, 0); assert.strictEqual(state.consentPosts.length, 0);
});

test('onboard: approval_pending with approval_id; then a token whose follow-up budget is the whole daily consent', async () => {
  let r = await call('fleetengine_onboard', { daily_cap_dd: 6000 });
  assert.strictEqual(r.status, 'approval_pending'); assert.strictEqual(r.approval_id, 41); assert.match(r.next, /DemiPass app/);
  state.approved = true;
  r = await call('fleetengine_onboard', { approval_id: 41 });   // the cap asked for (6000) is remembered for the redeem
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(r.consent.id, 12); assert.strictEqual(r.token_id, 'jti-1');
  assert.strictEqual(state.minted[0].service, 'fleetengine'); assert.strictEqual(state.minted[0].follow_up_dd, 6000); assert.strictEqual(state.minted[0].ttl, '24h');
  assert.strictEqual(state.minted[0].cap_dd, undefined, 'ordinary charges keep the default cap');
  assert.deepStrictEqual(r.service_ready, { ok: true }, 'the free readiness probe (a job lookup) accepted the token');
  assert.ok(!r.warning);
});

test('onboard again: the existing consent is reused, never re-filed', async () => {
  const n = state.consentPosts.length;
  const r = await call('fleetengine_onboard', {});
  assert.strictEqual(r.ok, true); assert.strictEqual(r.consent.existing, true); assert.strictEqual(state.consents.length, 1);
  assert.strictEqual(state.consentPosts.length, n, "an existing consent files nothing new");
});

test('run: a 401 re-mints once and retries with the same job_id; the job comes back queued', async () => {
  const before = state.minted.length;
  const r = await call('fleetengine_run', { engine: 'audit', requisition: REQ, job_id: 'job-12345678' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(r.job_id, 'job-12345678'); assert.strictEqual(r.status, 'queued');
  assert.strictEqual(state.minted.length, before + 1, 're-minted once');
  const [a, b] = state.posts.slice(-2);
  assert.notStrictEqual(a.auth, b.auth); assert.strictEqual(a.body.job_id, b.body.job_id);
  assert.strictEqual(b.body.requisition.engine, 'audit', 'the engine travels inside the requisition');
});

test('run again with the same job_id replays: one job, never a second charge', async () => {
  const r = await call('fleetengine_run', { engine: 'audit', requisition: REQ, job_id: 'job-12345678' });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.replayed, true); assert.strictEqual(state.jobs.size, 1);
});

test('job: the paying wallet reads its outcome; an unknown id is "no such job"', async () => {
  let r = await call('fleetengine_job', { job_id: 'job-12345678' });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.status, 'done');
  r = await call('fleetengine_job', { job_id: 'job-nothere1' });
  assert.strictEqual(r.ok, false); assert.strictEqual(r.http_status, 404);
  r = await call('fleetengine_job', { job_id: '../x' }); assert.strictEqual(r.ok, false);
});

test('refusals pass through: DemiPass 402, and DemiPass\'s own 202 (approval pending) is not mistaken for a queued job', async () => {
  let r = await call('fleetengine_run', { engine: 'audit', requisition: { ...REQ, premise: 'broke' } });
  assert.strictEqual(r.ok, false); assert.strictEqual(r.http_status, 402); assert.match(r.hint, /Nothing was queued/); assert.match(r.job_id, /^fe-[a-f0-9]{24}$/);
  r = await call('fleetengine_run', { engine: 'audit', requisition: { ...REQ, premise: 'needs-approval' } });
  assert.strictEqual(r.ok, false); assert.strictEqual(r.http_status, 202); assert.strictEqual(r.approval_id, 99); assert.match(r.hint, /approval/);
});

test('bad input is refused locally, nothing sent', async () => {
  const n = state.posts.length;
  let r = await call('fleetengine_run', { engine: 'Audit!', requisition: REQ }); assert.strictEqual(r.ok, false);
  r = await call('fleetengine_run', { engine: 'audit', requisition: [] }); assert.strictEqual(r.ok, false);
  r = await call('fleetengine_run', { engine: 'audit', requisition: { ...REQ, engine: 'ideate' } }); assert.strictEqual(r.ok, false);
  r = await call('fleetengine_run', { engine: 'audit', requisition: REQ, job_id: 'x' }); assert.strictEqual(r.ok, false);
  r = await call('fleetengine_pattern_run', { pattern: 42 }); assert.strictEqual(r.ok, false);
  r = await call('fleetengine_pattern_run', { pattern: 'p', inputs: [] }); assert.strictEqual(r.ok, false);
  assert.strictEqual(state.posts.length, n, 'nothing sent for local refusals');
});

test('the connection drops after the intake may have charged: the answer carries the job_id to retry with', async () => {
  state.dropNext = true;
  const r = await call('fleetengine_run', { engine: 'audit', requisition: REQ });
  assert.strictEqual(r.ok, false); assert.match(r.job_id, /^fe-[a-f0-9]{24}$/); assert.match(r.next, new RegExp(r.job_id));
  const again = await call('fleetengine_run', { engine: 'audit', requisition: REQ, job_id: r.job_id });
  assert.strictEqual(again.ok, true); assert.strictEqual(state.posts.at(-1).body.job_id, r.job_id);
});

test('pattern_run: one job on the shadow engine carrying the pattern and its inputs', async () => {
  const pattern = { steps: [{ id: 'a', engine: 'audit' }, { id: 'b', engine: 'ideate' }], edges: [{ from: 'a.countersign.reframings[0]', to: 'b.premise', injection: { mode: 'gated', on: 'a.countersign.verdict', equals: 'countersigned_with_reframings' } }] };
  const r = await call('fleetengine_pattern_run', { pattern, inputs: REQ, delivery: { conduit_name: 'aaron' }, job_id: 'pat-00000001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  const sent = state.posts.at(-1).body;
  assert.strictEqual(sent.requisition.engine, 'shadow'); assert.deepStrictEqual(sent.requisition.pattern, pattern);
  assert.deepStrictEqual(sent.requisition.inputs, REQ); assert.deepStrictEqual(sent.requisition.delivery, { conduit_name: 'aaron' });
});

test('another wallet signed in while the server runs: the held token is not used for it', async () => {
  const before = state.minted.length;
  process.env.DEMIPASS_TOKEN = SESSION_B;
  state.consents.push({ id: 13, service: 'fleetengine', daily_cap_dd: 3000, status: 'active' });
  const r = await call('fleetengine_run', { engine: 'audit', requisition: REQ, job_id: 'job-walletB1' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.strictEqual(state.minted.length, before + 1, 'a token was minted for wallet B');
  assert.strictEqual(state.posts.at(-1).auth, 'Bearer svc-token-SECRET-bbbbbbbbbbbb-' + state.minted.length);
  process.env.DEMIPASS_TOKEN = SESSION_A;
  assert.strictEqual((await call('fleetengine_status')).onboarded, false, "back on wallet A: B's held token is not A's");
  assert.strictEqual((await call('fleetengine_onboard', { daily_cap_dd: 6000 })).ok, true, 'A gets its own token again');
});

test('an expired session: run returns DemiPass\'s own refusal, nothing sent to FleetEngine', async () => {
  const n = state.posts.length;
  mcp._reset();
  process.env.DEMIPASS_TOKEN = jwt('did:key:zExpired');   // DemiPass answers 401 to it
  const r = await call('fleetengine_run', { engine: 'audit', requisition: REQ, job_id: 'job-expired1' });
  process.env.DEMIPASS_TOKEN = SESSION_A;
  assert.strictEqual(r.ok, false); assert.strictEqual(r.http_status, 401, JSON.stringify(r));
  assert.doesNotMatch(JSON.stringify(r), /could not be reached/); assert.match(r.note, /nothing was sent to FleetEngine/);
  assert.strictEqual(r.job_id, 'job-expired1'); assert.strictEqual(state.posts.length, n);
});

test('engines, prices and status', async () => {
  const e = await call('fleetengine_engines'); assert.strictEqual(e.ok, true); assert.strictEqual(e.engines[0].name, 'audit');
  const p = await call('fleetengine_prices'); assert.strictEqual(p.ok, true); assert.strictEqual(p.actions[0].price_dd, 14);
  const s = await call('fleetengine_status'); assert.strictEqual(s.onboarded, true, JSON.stringify(s)); assert.strictEqual(s.service_health.ok, true); assert.ok(s.token_id);
});

test('an http endpoint that is not loopback is refused before any token is sent', async () => {
  const keep = process.env.FLEETENGINE_URL;
  mcp._reset(); process.env.FLEETENGINE_URL = 'http://evil.example/fe';
  const r = await call('fleetengine_engines');
  assert.strictEqual(r.ok, false); assert.match(r.error, /must be https/);
  process.env.FLEETENGINE_URL = keep; mcp._reset();
});
