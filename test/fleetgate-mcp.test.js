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
    if (state.oldDoorOnboard) return json(res, 404, { error: 'not found', route: '/v1/onboard' });
    if (state.echoToken) return json(res, 403, { ok: false, error: 'refused ' + req.headers.authorization });
    if (state.switchDuringAdmission) { state.switchDuringAdmission = false; process.env.DEMIPASS_TOKEN = SESSION_B; }
    if(state.admissionRefused)return json(res,403,{ok:false,error:'no signed lane'});
    return json(res,200,{ok:true,wallet:state.wrongWallet ? 'did:key:zWrong' : wallets.get(req.headers.authorization),admission,
      ...(state.spend ? { spend: state.spend } : {})});
  }
  if (req.url === '/door/v1/check' || req.url.startsWith('/door/v1/pulls/')) {
    state.freeCalls = (state.freeCalls || []).concat([{ url: req.url, method: req.method, auth: req.headers.authorization, body: b }]);
    if (state.oldDoor) return json(res, 404, { error: 'not found', route: req.url.slice(5) });
    if (state.rawEcho) { res.writeHead(502, { 'content-type': 'text/plain' }); return res.end('x'.repeat(470) + ' upstream said: Authorization: ' + req.headers.authorization + ' end'); }
    if (state.switchDuringFree) { state.switchDuringFree = false; process.env.DEMIPASS_TOKEN = SESSION_B; }
    if (state.freeRejectFirst) { state.freeRejectFirst = false; return json(res, 401, { error: 'token expired' }); }
    if (req.url === '/door/v1/check') return json(res, 200, b.paths.includes('charters/x.json')
      ? { ok: false, lane: null, paths: [{ path: 'charters/x.json', allowed: false, why: 'never accepted through the door' }], why: 'some paths are not admitted' }
      : { ok: true, lane: 'intake', paths: b.paths.map(path => ({ path, status: 'added', allowed: true, lanes: ['intake'] })) });
    if (req.url === '/door/v1/pulls/boltcluster/sub-follow-001') return json(res, 200, { ok: true, submission_id: 'sub-follow-001', pull: { number: 51 },
      next: { who: 'operator', what: 'Waiting for review on aaaa from rev-open.' }, gate: { verdict: 'blocked', checks: [] }, reviews: [] });
    return json(res, 404, { ok: false, code: 'no_submission', error: 'No submission to atlas/boltcluster from this wallet.' });
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

test('tools/list names the six tools', async () => {
  const r = await mcp.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.deepStrictEqual(r.result.tools.map(t => t.name).sort(), ['fleetgate_check', 'fleetgate_follow', 'fleetgate_onboard', 'fleetgate_prices', 'fleetgate_status', 'fleetgate_submit']);
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

test('check: free; admitted paths name the lane and point at submit; refusals pass through; never a submission', async () => {
  const paid = state.doorCalls.length;
  let r = await call('fleetgate_check', { repo: 'boltcluster', paths: ['docs/a.md'] });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.lane, 'intake'); assert.match(r.next, /fleetgate_submit/);
  r = await call('fleetgate_check', { repo: 'boltcluster', paths: ['charters/x.json'] });
  assert.strictEqual(r.ok, false); assert.strictEqual(r.paths[0].allowed, false);
  r = await call('fleetgate_check', { repo: 'boltcluster', paths: [] }); assert.strictEqual(r.ok, false); assert.match(r.error, /paths/);
  r = await call('fleetgate_check', { repo: '../x', paths: ['a'] }); assert.strictEqual(r.ok, false);
  assert.strictEqual(state.doorCalls.length, paid, 'a check never submits');
});

test('follow: the door\'s answer with next; another or unknown id gets the own-only hint; a 401 re-mints once', async () => {
  let r = await call('fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.next.who, 'operator');
  r = await call('fleetgate_follow', { repo: 'boltcluster', submission_id: 'someone-elses-01' });
  assert.strictEqual(r.ok, false); assert.strictEqual(r.code, 'no_submission'); assert.match(r.hint, /own submissions/);
  r = await call('fleetgate_follow', { repo: 'boltcluster', submission_id: 'bad id' }); assert.strictEqual(r.ok, false); assert.match(r.error, /submission_id/);
  const minted = state.minted.length; state.freeRejectFirst = true;
  r = await call('fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' });
  assert.strictEqual(r.ok, true); assert.strictEqual(state.minted.length, minted + 1, 're-minted once');
  const last = state.freeCalls.slice(-2); assert.notStrictEqual(last[0].auth, last[1].auth, 'retried with the new token');
});

test('an older door (no follow, no check): a plain answer saying so, not a bare 404', async () => {
  state.oldDoor = true;
  let r = await call('fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' });
  assert.strictEqual(r.ok, false); assert.match(r.error, /predates/);
  r = await call('fleetgate_check', { repo: 'boltcluster', paths: ['docs/a.md'] });
  assert.strictEqual(r.ok, false); assert.match(r.error, /predates/);
  state.oldDoor = false;
});

test('status shows the token\'s spend when the door reports it, and only well-formed numbers', async () => {
  state.spend = { token_cap_dd: 800, token_spent_dd: 12, follow_up_dd: 3000 };
  let r = await call('fleetgate_status');
  assert.deepStrictEqual(r.spend, { token_cap_dd: 800, token_spent_dd: 12, follow_up_dd: 3000 }); assert.match(r.next, /fleetgate_check/);
  mcp._reset(); state.spend = { token_cap_dd: 'lots', token_spent_dd: 1, follow_up_dd: 1 };
  r = await call('fleetgate_status'); assert.strictEqual(r.spend, undefined);
  // never a cached figure: a failed admission check or another wallet shows no spend (Codex connector P2 on #27)
  state.spend = { token_cap_dd: 800, token_spent_dd: 12, follow_up_dd: 3000 };
  r = await call('fleetgate_status'); assert.ok(r.spend);
  state.admissionRefused = true; r = await call('fleetgate_status'); assert.strictEqual(r.spend, undefined); state.admissionRefused = false;
  process.env.DEMIPASS_TOKEN = SESSION_B; r = await call('fleetgate_status'); assert.strictEqual(r.spend, undefined, JSON.stringify(r));
  process.env.DEMIPASS_TOKEN = SESSION_A; mcp._reset();
  state.spend = null;
});

test('a submission answer points at fleetgate_follow with its own repo and id', async () => {
  state.doorRejectFirst = false;
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'docs/a.md', content: 'x' }], submission_id: 'sub-next-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.match(r.next, /fleetgate_follow \{repo: "boltcluster", submission_id: "sub-next-0001"\}/);
});

test('a refused admission that echoes the just-minted token never returns it (#27 independent review, 1)', async () => {
  mcp._reset(); state.echoToken = true;
  for (const [name, args] of [['fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' }], ['fleetgate_check', { repo: 'boltcluster', paths: ['docs/a.md'] }], ['fleetgate_status', {}]]) {
    const r = await call(name, args);   // call() asserts the token is absent from the whole answer
    assert.strictEqual(r.ok, false, name);
  }
  state.echoToken = false; mcp._reset();
});

test('free tools never file a payment consent, even with none active (#27 independent review, 2)', async () => {
  mcp._reset(); const saved = state.consents; state.consents = []; const posts = state.consentPosts.length;
  for (const [name, args] of [['fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' }], ['fleetgate_check', { repo: 'boltcluster', paths: ['docs/a.md'] }]]) {
    const r = await call(name, args); assert.strictEqual(r.ok, false); assert.strictEqual(r.status, 'not_onboarded', JSON.stringify(r));
  }
  assert.strictEqual(state.consentPosts.length, posts, 'no consent filed');
  state.consents = saved; mcp._reset();
});

test('a wallet switch while status\'s admission check is in flight shows no spend (#27 independent review, 3)', async () => {
  mcp._reset(); state.spend = { token_cap_dd: 800, token_spent_dd: 12, follow_up_dd: 3000 }; state.switchDuringAdmission = true;
  const r = await call('fleetgate_status');
  assert.strictEqual(r.spend, undefined, JSON.stringify(r)); assert.strictEqual(r.onboarded, false);
  process.env.DEMIPASS_TOKEN = SESSION_A; state.spend = null; mcp._reset();
});

test('repo must be a string: an array is refused before any network call (#27 independent review, 4)', async () => {
  const n = (state.freeCalls || []).length, m = state.minted.length;
  for (const [name, args] of [['fleetgate_follow', { repo: ['boltcluster'], submission_id: 'sub-follow-001' }], ['fleetgate_check', { repo: ['boltcluster'], paths: ['a'] }], ['fleetgate_submit', { repo: ['boltcluster'], title: 't', files: [{ path: 'a', content: 'b' }] }]]) {
    const r = await call(name, args); assert.strictEqual(r.ok, false); assert.match(r.error, /repo/);
  }
  assert.strictEqual((state.freeCalls || []).length, n); assert.strictEqual(state.minted.length, m);
});

test('a cold start against a door without /v1/onboard says the door is too old (#27 independent review, 5)', async () => {
  mcp._reset(); state.oldDoorOnboard = true;
  const r = await call('fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' });
  assert.strictEqual(r.ok, false); assert.match(r.error, /predates/, JSON.stringify(r));
  state.oldDoorOnboard = false; mcp._reset();
});

test('a wallet switch while follow or check is in flight shows nothing from the door (#27 independent review r2, 1)', async () => {
  for (const [name, args] of [['fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' }], ['fleetgate_check', { repo: 'boltcluster', paths: ['docs/a.md'] }]]) {
    mcp._reset(); process.env.DEMIPASS_TOKEN = SESSION_A;
    await call('fleetgate_status');          // a token held for wallet A
    state.switchDuringFree = true;
    const r = await call(name, args);
    assert.strictEqual(r.ok, false, name); assert.strictEqual(r.status, 'wallet_changed', JSON.stringify(r));
    assert.ok(!('pull' in r) && !('paths' in r) && !('spend' in r), JSON.stringify(r));
  }
  process.env.DEMIPASS_TOKEN = SESSION_A; mcp._reset();
});

test('explicit onboarding with a switch during admission shows no spend (#27 independent review r2, 2)', async () => {
  mcp._reset(); state.spend = { token_cap_dd: 800, token_spent_dd: 12, follow_up_dd: 3000 }; state.switchDuringAdmission = true;
  const r = await call('fleetgate_onboard');
  assert.strictEqual(r.spend, undefined, JSON.stringify(r));
  process.env.DEMIPASS_TOKEN = SESSION_A; state.spend = null; mcp._reset();
});

test('a non-JSON error echoing the bearer across the 500-character cut leaks no fragment of it (#27 independent review r3)', async () => {
  mcp._reset(); process.env.DEMIPASS_TOKEN = SESSION_A; await call('fleetgate_status');
  state.rawEcho = true;
  for (const [name, args] of [['fleetgate_follow', { repo: 'boltcluster', submission_id: 'sub-follow-001' }], ['fleetgate_check', { repo: 'boltcluster', paths: ['docs/a.md'] }]]) {
    const r = await call(name, args);            // call() asserts no svc-token-SECRET anywhere in the answer
    assert.strictEqual(r.ok, false); assert.ok(!/aaaaaaaaaaaa-[0-9]/.test(JSON.stringify(r)), JSON.stringify(r).slice(-200));
  }
  state.rawEcho = false; mcp._reset();
});

// ── item 4: submit from a git checkout ──
const { execFileSync } = require('child_process');
const os = require('os'), fsx = require('fs'), pathx = require('path');
function repo() {
  const d = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-git-'));
  const g = (...a) => execFileSync('git', ['-C', d, '-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { stdio: 'pipe' });
  g('init', '-q', '-b', 'main');
  fsx.mkdirSync(pathx.join(d, 'docs')); fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'old\n'); fsx.writeFileSync(pathx.join(d, 'README.md'), 'r\n');
  g('add', '-A'); g('commit', '-q', '-m', 'base');
  g('checkout', '-q', '-b', 'work');
  return { d, g };
}
const lastDoorBody = () => state.doorCalls[state.doorCalls.length - 1].body;

test('git: the changed files at ref, title from the commit subject, provenance in the body; nothing else read', async () => {
  state.doorRejectFirst = false;
  const { d, g } = repo();
  fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'new ü\n'); fsx.writeFileSync(pathx.join(d, 'docs/b.md'), 'added\n');
  g('add', '-A'); g('commit', '-q', '-m', 'docs: update a, add b');
  const r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'work', base: 'main' }, submission_id: 'from-git-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  const b = lastDoorBody();
  assert.strictEqual(b.title, 'docs: update a, add b');
  assert.deepStrictEqual(b.files.sort((x, y) => x.path.localeCompare(y.path)), [{ path: 'docs/a.md', content: 'new ü\n' }, { path: 'docs/b.md', content: 'added\n' }]);
  assert.match(b.body, /From git: `[0-9a-f]{12}` over merge base `[0-9a-f]{12}` \(2 files\)/);
  assert.deepStrictEqual(r.from_git.files.sort(), ['docs/a.md', 'docs/b.md']);
});

test('git: deletes, renames, symlinks and binaries are refused by name before anything is sent', async () => {
  for (const [name, mutate] of [
    ['delete', (d) => fsx.unlinkSync(pathx.join(d, 'README.md'))],
    ['rename', (d) => fsx.renameSync(pathx.join(d, 'docs/a.md'), pathx.join(d, 'docs/c.md'))],
    ['symlink', (d) => fsx.symlinkSync('README.md', pathx.join(d, 'docs/link.md'))],
    ['binary', (d) => fsx.writeFileSync(pathx.join(d, 'docs/x.md'), Buffer.from([0x89, 0x50, 0x00, 0xff]))],
  ]) {
    const { d, g } = repo(); mutate(d); g('add', '-A'); g('commit', '-q', '-m', name);
    const n = state.doorCalls.length;
    const r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'HEAD', base: 'main' } });
    assert.strictEqual(r.ok, false, name); assert.match(r.error, /can't be submitted/, name); assert.match(r.note, /Nothing was sent/);
    assert.strictEqual(state.doorCalls.length, n, `${name}: nothing sent`);
  }
});

test('git: bad dir, option-like or range refs, no changes, and files with git are refused', async () => {
  const { d } = repo(); const n = state.doorCalls.length;
  for (const git of [{ dir: 'relative/path' }, { dir: d, ref: '-x' }, { dir: d, ref: 'a..b' }, { dir: d, base: '--all' }, { dir: d, extra: 1 }, { dir: d, ref: 'main', base: 'main' }]) {
    const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', git });
    assert.strictEqual(r.ok, false, JSON.stringify(git));
  }
  const r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'a', content: 'b' }], git: { dir: d } });
  assert.match(r.error, /not both/);
  assert.strictEqual(state.doorCalls.length, n);
});

test('supersedes is passed to the door, and must name another submission', async () => {
  state.doorRejectFirst = false;
  let r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'docs/a.md', content: 'x' }], submission_id: 'second-sub-0002', supersedes: 'first-sub-00001' });
  assert.strictEqual(r.ok, true); assert.strictEqual(lastDoorBody().supersedes, 'first-sub-00001');
  r = await call('fleetgate_submit', { repo: 'boltcluster', title: 't', files: [{ path: 'docs/a.md', content: 'x' }], submission_id: 'second-sub-0002', supersedes: 'second-sub-0002' });
  assert.strictEqual(r.ok, false); assert.match(r.error, /earlier submission/);
});

test('git: diff.relative and a subdirectory dir do not narrow the change; mode changes, executables and non-UTF-8 paths are refused (#28 independent review)', async () => {
  state.doorRejectFirst = false;
  let { d, g } = repo();
  fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'changed\n'); fsx.writeFileSync(pathx.join(d, 'README.md'), 'changed too\n');
  g('add', '-A'); g('commit', '-q', '-m', 'two files'); g('config', 'diff.relative', 'true');
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: pathx.join(d, 'docs'), ref: 'work', base: 'main' }, submission_id: 'relative-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.deepStrictEqual(lastDoorBody().files.map(f => f.path).sort(), ['README.md', 'docs/a.md']);
  for (const [name, mutate] of [
    ['chmod', (dd, gg) => { fsx.chmodSync(pathx.join(dd, 'README.md'), 0o755); gg('update-index', '--chmod=+x', 'README.md'); }],
    ['executable', (dd) => { fsx.writeFileSync(pathx.join(dd, 'run.sh'), '#!/bin/sh\n', { mode: 0o755 }); }],
    ['latin1 path', (dd) => { fsx.writeFileSync(Buffer.concat([Buffer.from(pathx.join(dd, 'docs') + '/'), Buffer.from([0xff]), Buffer.from('.md')]), 'x\n'); }],
  ]) {
    ({ d, g } = repo()); mutate(d, g); g('add', '-A'); g('commit', '-q', '-m', name);
    const n = state.doorCalls.length;
    r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'HEAD', base: 'main' } });
    assert.strictEqual(r.ok, false, name); assert.match(r.error, /can't be submitted/, name); assert.strictEqual(state.doorCalls.length, n, name);
  }
});

test('git: diff.ignoreSubmodules=all cannot hide a submodule change; a top level differing only by whitespace stays itself (#28 independent review r2)', async () => {
  state.doorRejectFirst = false;
  const sub = repo(); const { d, g } = repo();
  fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'edit\n');
  g('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', sub.d, 'vendored'); g('add', '-A'); g('commit', '-q', '-m', 'edit plus submodule');
  g('config', 'diff.ignoreSubmodules', 'all');
  const n = state.doorCalls.length;
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'work', base: 'main' } });
  assert.strictEqual(r.ok, false, JSON.stringify(r)); assert.match(r.error, /vendored|\.gitmodules/); assert.strictEqual(state.doorCalls.length, n);
  // "x " and "x": the request names the one with the trailing space, and only its change is read
  const base = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-ws-')), a = pathx.join(base, 'proj'), b = pathx.join(base, 'proj ');
  for (const [dir, content] of [[a, 'from proj\n'], [b, 'from proj-space\n']]) {
    fsx.mkdirSync(dir); const gg = (...x) => execFileSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@t', ...x], { stdio: 'pipe' });
    gg('init', '-q', '-b', 'main'); fsx.writeFileSync(pathx.join(dir, 'README.md'), 'r\n'); gg('add', '-A'); gg('commit', '-q', '-m', 'base');
    gg('checkout', '-q', '-b', 'work'); fsx.mkdirSync(pathx.join(dir, 'docs')); fsx.writeFileSync(pathx.join(dir, 'docs/a.md'), content); gg('add', '-A'); gg('commit', '-q', '-m', 'w');
  }
  r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: b, ref: 'work', base: 'main' }, submission_id: 'ws-path-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(lastDoorBody().files[0].content, 'from proj-space\n');
});

test('git: replace objects are ignored; paths the door would refuse (non-ASCII, over 200, dot-files) are refused locally (#28 independent review r3)', async () => {
  state.doorRejectFirst = false;
  let { d, g } = repo();
  fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'committed\n'); g('add', '-A'); g('commit', '-q', '-m', 'real');
  const real = g('rev-parse', 'HEAD:docs/a.md').toString().trim();
  const fake = execFileSync('git', ['-C', d, 'hash-object', '-w', '--stdin'], { input: 'substituted\n' }).toString().trim();
  g('replace', real, fake);
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'HEAD', base: 'main' }, submission_id: 'replace-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(lastDoorBody().files[0].content, 'committed\n');
  for (const name of ['docs/caf\u00e9.md', 'docs/' + 'x'.repeat(200) + '.md', 'docs/.hidden.md']) {
    ({ d, g } = repo()); fsx.writeFileSync(pathx.join(d, name), 'x\n'); g('add', '-A'); g('commit', '-q', '-m', 'p');
    const n = state.doorCalls.length;
    r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'HEAD', base: 'main' } });
    assert.strictEqual(r.ok, false, name); assert.match(r.error, /ASCII letters/, name); assert.strictEqual(state.doorCalls.length, n, name);
  }
});

test('git: a grafts file cannot move the merge base; a blob missing from a partial clone is refused, never fetched (#28 independent review r4)', async () => {
  state.doorRejectFirst = false;
  let { d, g } = repo();
  // repo(): main has the base commit, work adds a change. Add B on main, then F on work from B; graft F onto main's root.
  const root = g('rev-list', '--max-parents=0', 'main').toString().trim();
  g('checkout', '-q', 'main'); fsx.writeFileSync(pathx.join(d, 'README.md'), 'B\n'); g('commit', '-q', '-am', 'B');
  g('checkout', '-q', '-b', 'f'); fsx.mkdirSync(pathx.join(d, 'docs'), { recursive: true }); fsx.writeFileSync(pathx.join(d, 'docs/f.md'), 'F\n'); g('add', '-A'); g('commit', '-q', '-m', 'F');
  const F = g('rev-parse', 'HEAD').toString().trim();
  fsx.writeFileSync(pathx.join(d, '.git/info/grafts'), `${F} ${root}\n`);
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'f', base: 'main' }, submission_id: 'grafts-00001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.deepStrictEqual(lastDoorBody().files.map(f => f.path), ['docs/f.md']);
  // a real partial clone (blob:none from a reachable source): the work branch's blob is fetchable, so a lazy fetch would
  // succeed; it must be refused instead, and the clone must still lack the blob afterwards
  const src = repo(); fsx.writeFileSync(pathx.join(src.d, 'docs/a.md'), 'only upstream\n'); src.g('add', '-A'); src.g('commit', '-q', '-m', 'upstream change');
  src.g('config', 'uploadpack.allowFilter', 'true'); src.g('config', 'uploadpack.allowAnySHA1InWant', 'true');
  const pc = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-partial-'));
  execFileSync('git', ['clone', '-q', '--no-checkout', '--filter=blob:none', '--branch', 'main', `file://${src.d}`, pc], { stdio: 'pipe' });
  execFileSync('git', ['-C', pc, 'fetch', '-q', '--filter=blob:none', 'origin', 'work:work'], { stdio: 'pipe' });
  const blob = execFileSync('git', ['-C', pc, 'rev-parse', 'work:docs/a.md']).toString().trim();
  const has = () => { try { execFileSync('git', ['-C', pc, '--no-lazy-fetch', 'cat-file', '-e', blob], { stdio: 'pipe', env: { ...process.env, GIT_NO_LAZY_FETCH: '1' } }); return true; } catch (_) { return false; } };
  assert.strictEqual(has(), false, 'the fixture lacks the blob');
  const n = state.doorCalls.length;
  r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: pc, ref: 'work', base: 'main' } });
  assert.strictEqual(r.ok, false, JSON.stringify(r)); assert.match(r.error, /isn't in this checkout/); assert.strictEqual(state.doorCalls.length, n);
  assert.strictEqual(has(), false, 'nothing was fetched');
});

test('git: a shallow checkout is refused; no program from the checkout\'s config runs (gpg.program via log.showSignature, fsmonitor) (#28 independent review r5)', async () => {
  state.doorRejectFirst = false;
  const src = repo(); fsx.writeFileSync(pathx.join(src.d, 'docs/a.md'), 'x\n'); src.g('add', '-A'); src.g('commit', '-q', '-m', 'c');
  const sh = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-shallow-'));
  execFileSync('git', ['clone', '-q', '--depth', '1', '--no-single-branch', `file://${src.d}`, sh], { stdio: 'pipe' });
  const n = state.doorCalls.length;
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: sh, ref: 'origin/work', base: 'origin/main' } });
  assert.strictEqual(r.ok, false); assert.match(r.error, /shallow/); assert.strictEqual(state.doorCalls.length, n);
  // a checkout whose config names programs: none of them may run
  const { d, g } = repo(); fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'y\n'); g('add', '-A'); g('commit', '-q', '-m', 'p');
  const marker = pathx.join(d, '..', `ran-${pathx.basename(d)}`);
  const prog = pathx.join(d, '..', `prog-${pathx.basename(d)}.sh`);
  fsx.writeFileSync(prog, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`, { mode: 0o755 });
  g('config', 'log.showSignature', 'true'); g('config', 'gpg.program', prog); g('config', 'core.fsmonitor', prog);
  // a signature-looking header makes git consult gpg.program when it is allowed to verify
  const tree = g('rev-parse', 'HEAD^{tree}').toString().trim(), parent = g('rev-parse', 'HEAD^').toString().trim();
  const raw = `tree ${tree}\nparent ${parent}\nauthor t <t@t> 1700000000 +0000\ncommitter t <t@t> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n\nsigned\n`;
  const signed = execFileSync('git', ['-C', d, 'hash-object', '-t', 'commit', '-w', '--stdin'], { input: raw }).toString().trim();
  g('update-ref', 'refs/heads/work', signed);
  r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'work', base: 'main' }, submission_id: 'noprog-00001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.strictEqual(fsx.existsSync(marker), false, 'no configured program ran');
});
