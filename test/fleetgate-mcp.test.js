'use strict';
// fleetgate-mcp: onboarding (consent filed for app approval → approval_id → token), submit through the door with a
// re-mint on 401, refusals passed through, and the token never appearing in any tool answer. Mock DemiPass + mock door.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

// Sessions shaped like DemiPass JWTs: the server reads the wallet (sub) to bind a held token to it.
const jwt = (sub) => 'eyJhbGciOiJFZERTQSJ9.' + Buffer.from(JSON.stringify({ sub, scope: 'transact' })).toString('base64url') + '.sig';
const SESSION_A = jwt('did:key:zPaneA'), SESSION_B = jwt('did:key:zPaneB');
const wallets = new Map();
const admission = { ok:true,protocol:1,release_authorized:false,charter_sha256:'a'.repeat(64),lanes:[{name:'intake',repos:['boltcluster'],paths:['docs/**'],add_only:[],deny:[]}] };
const state = { consents: [], approved: false, minted: [], doorCalls: [], doorRejectFirst: true, consentPosts: [], dropNext: false };
function json(res, status, body) { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); }
function readBody(req) { return new Promise(ok => { let b = ''; req.on('data', c => { b += c; }); req.on('end', () => ok(b ? JSON.parse(b) : {})); }); }

const dpSrv = http.createServer(async (req, res) => {
  const b = await readBody(req);
  if (req.headers.authorization !== 'Bearer ' + SESSION_A && req.headers.authorization !== 'Bearer ' + SESSION_B) return json(res, 401, { error: 'bad session' });
  if (req.method === 'GET' && req.url === '/api/services/consents') return json(res, 200, { ok: true, mine: state.consents, approved_by_me: [] });
  if (req.method === 'POST' && req.url === '/api/services/consent') {
    state.consentPosts.push(b);
    if (!b.approval_id) return json(res, 202, { status: 'approval_pending', approval_id: 77, expires_at: '2026-11-11T00:00:00Z' });
    if (!state.approved || b.approval_id !== 77) return json(res, 202, { status: 'approval_pending', approval_id: 77 });
    if (b.daily_cap_dd !== 5000) return json(res, 409, { error: 'approval was for a different call' });
    state.consents.push({ id: 9, service: b.service, daily_cap_dd: b.daily_cap_dd, status: 'active' });
    return json(res, 201, { ok: true, consent_id: 9, service: b.service, daily_cap_dd: b.daily_cap_dd });
  }
  if (req.method === 'POST' && req.url === '/api/services/token') {
    const n = state.minted.length + 1; state.minted.push(b);
    wallets.set('Bearer svc-token-SECRET-aaaaaaaaaaaa-' + n, req.headers.authorization === 'Bearer '+SESSION_A ? 'did:key:zPaneA':'did:key:zPaneB');
    if (state.switchDuringMint) { state.switchDuringMint = false; process.env.DEMIPASS_TOKEN = SESSION_B; }   // the machine's session changes mid-mint
    return json(res, 201, { ok: true, token: 'svc-token-SECRET-aaaaaaaaaaaa-' + n, token_id: 'jti-' + n, service: b.service, cap_dd: b.cap_dd, expires_at: new Date(Date.now() + 3600e3).toISOString() });
  }
  json(res, 404, { error: 'no route' });
});
const doorSrv = http.createServer(async (req, res) => {
  const b = await readBody(req);
  if (req.url === '/door/v1/onboard') {
    if(state.admissionRefused)return json(res,403,{ok:false,error:'no signed lane'});
    return json(res,200,{ok:true,wallet:state.wrongWallet ? 'did:key:zWrong' : wallets.get(req.headers.authorization),admission});
  }
  if (req.url === '/door/health') return json(res, 200, { ok: true, version: 'test', tenant: 'fleetgate' });
  if (req.url === '/door/v1/prices') return json(res, 200, { slug: 'fleetgate', actions: [{ action: 'submit', price_dd: 696 }] });
  if (req.url === '/door/v1/pulls' && req.method === 'POST') {
    state.doorCalls.push({ auth: req.headers.authorization, body: b });
    if (state.dropNext) { state.dropNext = false; return req.socket.destroy(); }
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
  process.env.DEMIPASS_TOKEN = SESSION_A;
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

test('submit before onboarding: refused, nothing sent to the door, and no consent filed on the phone', async () => {
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'a.md', content: 'x' }] });
  assert.strictEqual(r.ok, false); assert.match(r.error, /fleetgate_onboard/);
  assert.strictEqual(state.doorCalls.length, 0); assert.strictEqual(state.consentPosts.length, 0);
});

test('ping answers an empty result', async () => {
  const r = await mcp.handleMessage({ jsonrpc: '2.0', id: 5, method: 'ping' });
  assert.deepStrictEqual(r.result, {});
});

test('onboard: no consent → approval_pending with approval_id; still pending until approved; then a token', async () => {
  let r = await call('fleetgate_onboard', { daily_cap_dd: 5000 });
  assert.strictEqual(r.status, 'approval_pending'); assert.strictEqual(r.approval_id, 77); assert.match(r.next, /DemiPass app/);
  r = await call('fleetgate_onboard', { approval_id: 77 });
  assert.strictEqual(r.status, 'approval_pending');
  state.approved = true;
  r = await call('fleetgate_onboard', { approval_id: 77 });   // the cap asked for (5000) is remembered for the redeem
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.ok(!r.warning); assert.strictEqual(r.consent.id, 9); assert.strictEqual(r.token_id, 'jti-1');
  assert.strictEqual(state.minted[0].follow_up_dd, 5000, 'the review rounds a submission starts may bill up to the whole daily consent'); assert.strictEqual(state.minted[0].cap_dd, undefined, 'ordinary charges keep the default cap');
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

test('the connection drops after the door may have charged: the answer carries the submission_id to retry with', async () => {
  state.dropNext = true;
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'a.md', content: 'x' }] });
  assert.strictEqual(r.ok, false); assert.match(r.submission_id, /^[a-f0-9]{24}$/); assert.match(r.next, new RegExp(r.submission_id));
  const again = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'a.md', content: 'x' }], submission_id: r.submission_id });
  assert.strictEqual(again.ok, true); assert.strictEqual(state.doorCalls.at(-1).body.submission_id, r.submission_id);
});

test('another wallet signed in while the server runs: the held token is not used for it (#17 review round 2, P1)', async () => {
  const before = state.minted.length;
  process.env.DEMIPASS_TOKEN = SESSION_B;
  state.consents.push({ id: 10, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' });
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'b.md', content: 'y' }], submission_id: 'sub-walletB-1' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.strictEqual(state.minted.length, before + 1, 'a token was minted for wallet B');
  assert.strictEqual(state.doorCalls.at(-1).auth, 'Bearer svc-token-SECRET-aaaaaaaaaaaa-' + state.minted.length);
  process.env.DEMIPASS_TOKEN = SESSION_A;
  assert.strictEqual((await call('fleetgate_status')).onboarded, false, "back on wallet A: B's held token is not A's");
  assert.strictEqual((await call('fleetgate_onboard', { daily_cap_dd: 5000 })).ok, true, 'A gets its own token again');
});

test('the session switching while a token is minted: the token stays bound to the wallet that minted it (#17 review round 3)', async () => {
  process.env.DEMIPASS_TOKEN = SESSION_A;
  state.switchDuringMint = true;
  const r = await call('fleetgate_onboard', { daily_cap_dd: 5000, renew: true });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.strictEqual(process.env.DEMIPASS_TOKEN, SESSION_B, 'the switch happened during the mint');
  assert.strictEqual((await call('fleetgate_status')).onboarded, false, "B does not get A's freshly minted token");
  process.env.DEMIPASS_TOKEN = SESSION_A;
  assert.strictEqual((await call('fleetgate_status')).onboarded, true, "…and A keeps it");
});

test('an expired session: submit returns DemiPass\'s own refusal, not "the door could not be reached" (#17 review round 5)', async () => {
  const doorBefore = state.doorCalls.length;
  process.env.DEMIPASS_TOKEN = jwt('did:key:zExpired');   // DemiPass answers 401 to it
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'c.md', content: 'z' }], submission_id: 'sub-expired-1' });
  process.env.DEMIPASS_TOKEN = SESSION_A;
  assert.strictEqual(r.ok, false); assert.strictEqual(r.http_status, 401, JSON.stringify(r));
  assert.doesNotMatch(JSON.stringify(r), /could not be reached/); assert.match(r.note, /nothing was sent to the door/);
  assert.strictEqual(r.submission_id, 'sub-expired-1'); assert.strictEqual(state.doorCalls.length, doorBefore);
});

test('prices and status', async () => {
  const p = await call('fleetgate_prices'); assert.strictEqual(p.ok, true); assert.strictEqual(p.actions[0].price_dd, 696);
  const s = await call('fleetgate_status'); assert.strictEqual(s.onboarded, true); assert.strictEqual(s.door_health.ok, true); assert.ok(s.token_id);
});

test('payment consent alone is not onboarded; refusal recovers on next status without more consent',async()=>{
 const n=state.consentPosts.length, paid=state.doorCalls.length;
 state.admissionRefused=true;
 let r=await call('fleetgate_onboard');assert.strictEqual(r.ok,false);assert.strictEqual(r.status,'admission_required');
 r=await call('fleetgate_status');assert.strictEqual(r.onboarded,false);assert.strictEqual(r.ok,false);
 state.admissionRefused=false;
 r=await call('fleetgate_status');assert.strictEqual(r.onboarded,true,JSON.stringify(r));assert.strictEqual(r.admission.release_authorized,false);
 assert.strictEqual(state.consentPosts.length,n);assert.strictEqual(state.doorCalls.length,paid,'readiness never submits');
 state.admissionRefused=true;
 r=await call('fleetgate_status');assert.strictEqual(r.onboarded,false,'cached token cannot conceal removed authority');
 state.admissionRefused=false;
});
test('a wrong-wallet admission result never counts',async()=>{
 state.wrongWallet=true;const r=await call('fleetgate_onboard');assert.strictEqual(r.ok,false);assert.match(r.error,/wrong-wallet/);state.wrongWallet=false;
});
