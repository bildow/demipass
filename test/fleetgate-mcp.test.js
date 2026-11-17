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
  if (req.method === 'GET' && req.url === '/api/services/consents') {
    if (state.delayConsentsMs) { const ms = state.delayConsentsMs; state.delayConsentsMs = 0; return setTimeout(() => json(res, 200, { ok: true, mine: state.consents, approved_by_me: [] }), ms); }
    return json(res, 200, { ok: true, mine: state.consents, approved_by_me: [] });
  }
  if (req.method === 'POST' && req.url === '/api/services/consent') {
    state.consentPosts.push(b);
    // a raise of an existing consent (the payment ask): approval 88, approved, declined or expired as the test says
    if (b.daily_cap_dd !== 5000 && b.daily_cap_dd !== 3000) {
      if (!b.approval_id) { const same = state.raiseFor && state.raiseFor.service === b.service && state.raiseFor.daily_cap_dd === b.daily_cap_dd && state.raise == null;
        if (!same) state.cards = (state.cards || 0) + 1;
        state.raiseFor = { service: b.service, daily_cap_dd: b.daily_cap_dd };
        if (state.slowRaiseMs) { const ms = state.slowRaiseMs; state.slowRaiseMs = 0; return setTimeout(() => json(res, 202, { status: 'approval_pending', approval_id: 88 }), ms); }
        return json(res, 202, { status: 'approval_pending', approval_id: 88, expires_at: '2026-11-18T00:00:00Z' }); }
      // redeeming binds to what was approved: the same id, service and cap (#35 r1, 4)
      if (b.approval_id !== 88 || !state.raiseFor || b.service !== state.raiseFor.service || b.daily_cap_dd !== state.raiseFor.daily_cap_dd) return json(res, 409, { error: 'approval was for a different call' });
      if (state.raise === 'declined') return json(res, 403, { error: 'the owner declined this request' });
      if (state.raise === 'expired') return json(res, 410, { error: 'this request expired' });
      if (state.raise !== 'approved') return json(res, 202, { status: 'approval_pending', approval_id: 88 });
      state.consents = state.consents.filter(c => c.service !== b.service).concat([{ id: 12, service: b.service, daily_cap_dd: b.daily_cap_dd, status: 'active' }]);
      return json(res, 201, { ok: true, consent_id: 12, service: b.service, daily_cap_dd: b.daily_cap_dd });
    }
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
  if (req.url === '/door/v1/reviews' && req.method === 'POST') {
    state.reviewPosts = (state.reviewPosts || []).concat([b]);
    return json(res, 202, { ok: true, review_id: b.review_id, state: 'queued', next: { who: 'worker', what: 'Queued' } });
  }
  if (req.url.startsWith('/door/v1/reviews/')) {
    const id = req.url.slice('/door/v1/reviews/'.length);
    const pay = (refused, ask) => ({ refused, needed_dd: 1589, resumable: true, ask, next: 'Your fleetgate daily consent is used up for today. The work waits and resumes by itself.' });
    if (id.startsWith('review-waiting-')) return json(res, 200, { ok: true, review_id: id, state: 'waiting_payment', next: { who: 'you', what: 'raise it' },
      payment: pay('daily_cap', { kind: 'consent', service: 'fleetgate', more_dd: id === 'review-waiting-neg' ? -1 : 1589 }) });
    if (id === 'review-fund-01') return json(res, 200, { ok: true, review_id: id, state: 'waiting_payment', next: { who: 'you', what: 'fund it' },
      payment: { ...pay('insufficient', { kind: 'fund', more_dd: 1589 }), next: 'Fund it in the DemiPass app.' } });
    return id === 'review-known-01' ? json(res, 200, { ok: true, review_id: id, state: 'done', verdict: 'approved by all three seats', seats: [1, 2, 3], receipt_sha256: 'c'.repeat(64) })
      : json(res, 404, { ok: false, code: 'no_review', error: 'No review from this wallet.' });
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

test('tools/list names the seven tools', async () => {
  const r = await mcp.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.deepStrictEqual(r.result.tools.map(t => t.name).sort(), ['fleetgate_check', 'fleetgate_follow', 'fleetgate_onboard', 'fleetgate_prices', 'fleetgate_review', 'fleetgate_status', 'fleetgate_submit']);
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

test('the encoded request is measured before sending; supersedes takes the door\'s 6-character ids (#28 independent review r6)', async () => {
  state.doorRejectFirst = false;
  const { d, g } = repo();
  for (const n of ['a', 'b', 'c']) fsx.writeFileSync(pathx.join(d, `docs/${n}.md`), '\\'.repeat(128 * 1024 - 8) + '\n');
  g('add', '-A'); g('commit', '-q', '-m', 'backslashes');
  const n = state.doorCalls.length;
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: d, ref: 'work', base: 'main' } });
  assert.strictEqual(r.ok, false, JSON.stringify(r).slice(0, 300)); assert.match(r.error, /once encoded, over the door's 524288/); assert.strictEqual(state.doorCalls.length, n);
  r = await call('fleetgate_submit', { repo: 'boltcluster', files: [{ path: 'docs/a.md', content: 'x\n' }], title: 't', submission_id: 'newer-000001', supersedes: 'abc123' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(lastDoorBody().supersedes, 'abc123');
});

// ── item 3: review-only requests ──
test('review: the packet from a checkout (deletes included, https origin without credentials); follow by review_id', async () => {
  mcp._reset(); state.doorRejectFirst = false;
  const { d, g } = repo();
  fsx.unlinkSync(pathx.join(d, 'README.md')); fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'reviewed\n');
  g('add', '-A'); g('commit', '-q', '-m', 'sealed: wave 2'); g('remote', 'add', 'origin', 'https://user:secret-tok@github.com/bildow/demipass.git?x=1#frag');
  const r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'main' }, note: 'exact revision', review_id: 'review-test-001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.match(r.next, /fleetgate_follow \{review_id: "review-test-001"\}/);
  const b = state.reviewPosts[state.reviewPosts.length - 1];
  assert.strictEqual(b.title, 'sealed: wave 2'); assert.strictEqual(b.source.remote, 'https://github.com/bildow/demipass');
  assert.match(b.source.head, /^[0-9a-f]{40}$/); assert.match(b.source.base, /^[0-9a-f]{40}$/);
  assert.deepStrictEqual(b.files.sort((x, y) => (x.path < y.path ? -1 : 1)), [{ status: 'D', path: 'README.md' }, { status: 'M', path: 'docs/a.md' }]);
  assert.match(b.diff, /^diff --git a\/README.md b\/README.md/m); assert.strictEqual(b.note, 'exact revision');
  let f = await call('fleetgate_follow', { review_id: 'review-known-01' });
  assert.strictEqual(f.state, 'done'); assert.strictEqual(f.seats.length, 3);
  f = await call('fleetgate_follow', { review_id: 'someone-elses-1' }); assert.strictEqual(f.ok, false); assert.match(f.hint, /own reviews/);
});

test('review: bad git input and no changes are refused with nothing sent', async () => {
  const { d } = repo(); const n = (state.reviewPosts || []).length;
  for (const git of [{ dir: 'rel' }, { dir: d, ref: '--all' }, { dir: d, ref: 'main', base: 'main' }]) {
    const r = await call('fleetgate_review', { git }); assert.strictEqual(r.ok, false, JSON.stringify(git)); assert.match(r.note || '', /Nothing was sent/);
  }
  assert.strictEqual((state.reviewPosts || []).length, n);
});

test('review: the encoded request is measured before sending (as submit, #28 r6)', async () => {
  const { d, g } = repo();
  fsx.writeFileSync(pathx.join(d, 'docs/big.md'), '\\'.repeat(395000) + '\n'); g('add', '-A'); g('commit', '-q', '-m', 'big');
  const n = (state.reviewPosts || []).length;
  const r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'main' } });
  assert.strictEqual(r.ok, false); assert.match(r.error, /once encoded, over the door's 524288/); assert.strictEqual((state.reviewPosts || []).length, n, 'no review was posted (#29 r1, 5)');
});

test('review: ssh remotes left out; binary-marking config can\'t hide a change; a submodule\'s drivers never run; door path rules local (#29 independent review r1)', async () => {
  state.doorRejectFirst = false;
  // ssh remote: left out, not rewritten
  let { d, g } = repo(); fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'x\n'); g('add', '-A'); g('commit', '-q', '-m', 'x');
  g('remote', 'add', 'origin', 'git@private.example:org/repo.git');
  let r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'main' }, review_id: 'review-ssh-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.ok(!('remote' in state.reviewPosts.at(-1).source));
  // * -diff and core.bigFileThreshold=1: the hunk is still in the packet
  ({ d, g } = repo()); fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'the hidden change\n'); fsx.writeFileSync(pathx.join(d, '.gitattributes'), '* -diff\n');
  g('add', '-A'); g('commit', '-q', '-m', 'hide'); g('config', 'core.bigFileThreshold', '1');
  r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'main' }, review_id: 'review-bin-00001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.match(state.reviewPosts.at(-1).diff, /\+the hidden change/); assert.ok(!/Binary files/.test(state.reviewPosts.at(-1).diff));
  // a populated submodule with diff.submodule=diff and a textconv driver: the driver never runs
  const sub = repo(); fsx.writeFileSync(pathx.join(sub.d, 'docs/s.txt'), 'one\n'); sub.g('add', '-A'); sub.g('commit', '-q', '-m', 's1');
  ({ d, g } = repo());
  g('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', '-b', 'work', sub.d, 'vendored'); g('commit', '-q', '-m', 'add sub');
  g('checkout', '-q', '-b', 'base2'); g('checkout', '-q', 'work');
  fsx.writeFileSync(pathx.join(sub.d, 'docs/s.txt'), 'two\n'); sub.g('commit', '-q', '-am', 's2');
  execFileSync('git', ['-C', pathx.join(d, 'vendored'), 'pull', '-q', 'origin', 'work'], { stdio: 'pipe' });
  g('add', 'vendored'); g('commit', '-q', '-m', 'bump sub');
  const marker = pathx.join(d, '..', `tc-${pathx.basename(d)}`), prog = pathx.join(d, '..', `tc-${pathx.basename(d)}.sh`);
  fsx.writeFileSync(prog, `#!/bin/sh\ntouch '${marker}'\ncat "$1"\n`, { mode: 0o755 });
  fsx.mkdirSync(pathx.join(d, '.git', 'modules', 'vendored', 'info'), { recursive: true });
  fsx.writeFileSync(pathx.join(d, '.git', 'modules', 'vendored', 'info', 'attributes'), '*.txt diff=evil\n');
  execFileSync('git', ['-C', pathx.join(d, 'vendored'), 'config', 'diff.evil.textconv', prog]);
  g('config', 'diff.submodule', 'diff');
  r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'base2' }, review_id: 'review-sub-00001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(fsx.existsSync(marker), false, 'the submodule\'s textconv never ran');
  // door path rules: a newline in a path is refused locally
  ({ d, g } = repo()); fsx.writeFileSync(pathx.join(d, 'docs', 'line\nbreak.txt'), 'x\n'); g('add', '-A'); g('commit', '-q', '-m', 'nl');
  const n = state.reviewPosts.length;
  r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'main' } });
  assert.strictEqual(r.ok, false); assert.match(r.error, /without newlines/); assert.strictEqual(state.reviewPosts.length, n);
});

test('review and submit: supplied ids must be strings, an empty one is not replaced; SHA-256 repositories refused locally (#29 independent review r2)', async () => {
  state.doorRejectFirst = false;
  let { d, g } = repo(); fsx.writeFileSync(pathx.join(d, 'docs/a.md'), 'x\n'); g('add', '-A'); g('commit', '-q', '-m', 'x');
  const n = (state.reviewPosts || []).length, m = state.doorCalls.length;
  for (const bad of [12345678, ['review-valid-001'], '', null, 0]) {
    let r = await call('fleetgate_review', { git: { dir: d, ref: 'work', base: 'main' }, review_id: bad });
    assert.strictEqual(r.ok, false, JSON.stringify(bad));
    r = await call('fleetgate_submit', { repo: 'boltcluster', files: [{ path: 'docs/a.md', content: 'x\n' }], title: 't', submission_id: bad });
    assert.strictEqual(r.ok, false, JSON.stringify(bad));
  }
  assert.strictEqual((state.reviewPosts || []).length, n); assert.strictEqual(state.doorCalls.length, m);
  // a SHA-256 repository
  const d2 = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-sha256-'));
  const g2 = (...a) => execFileSync('git', ['-C', d2, '-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { stdio: 'pipe' });
  g2('init', '-q', '--object-format=sha256', '-b', 'main'); fsx.writeFileSync(pathx.join(d2, 'a.md'), 'a\n'); g2('add', '-A'); g2('commit', '-q', '-m', 'base');
  g2('checkout', '-q', '-b', 'work'); fsx.writeFileSync(pathx.join(d2, 'a.md'), 'b\n'); g2('commit', '-q', '-am', 'w');
  const r = await call('fleetgate_review', { git: { dir: d2, ref: 'work', base: 'main' } });
  assert.strictEqual(r.ok, false); assert.match(r.error, /SHA-256/); assert.strictEqual((state.reviewPosts || []).length, n);
});

test('git: core.worktree in the checkout cannot send git to another repository (submit and review) (#29 independent review r3)', async () => {
  state.doorRejectFirst = false;
  const A = repo(), B = repo();
  fsx.writeFileSync(pathx.join(A.d, 'docs/a.md'), 'from A\n'); A.g('add', '-A'); A.g('commit', '-q', '-m', 'A change');
  fsx.writeFileSync(pathx.join(B.d, 'docs/a.md'), 'from B (private)\n'); B.g('add', '-A'); B.g('commit', '-q', '-m', 'B change');
  A.g('config', 'core.worktree', B.d);
  let r = await call('fleetgate_submit', { repo: 'boltcluster', git: { dir: A.d, ref: 'work', base: 'main' }, submission_id: 'worktree-0001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(lastDoorBody().files[0].content, 'from A\n');
  r = await call('fleetgate_review', { git: { dir: A.d, ref: 'work', base: 'main' }, review_id: 'review-wt-00001' });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.match(state.reviewPosts.at(-1).diff, /\+from A/); assert.ok(!/from B/.test(state.reviewPosts.at(-1).diff));
});

test('git: neither a global git config nor a DemiPass variable reaches git (code pass 2026-11-16, item 3)', () => {
  const home = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-home-'));
  fsx.writeFileSync(pathx.join(home, '.gitconfig'), '[diff]\n\texternal = /nonexistent/evil-diff\n');
  const base = { ...process.env, HOME: home, XDG_CONFIG_HOME: pathx.join(home, '.config'), DEMIPASS_TOKEN: 'secret-session', DEMIPASS_URL: 'http://x' };
  // without the fix git would read it:
  assert.strictEqual(execFileSync('git', ['config', '--get', 'diff.external'], { env: base }).toString().trim(), '/nonexistent/evil-diff');
  const env = mcp._gitEnv(base);
  assert.ok(!Object.keys(env).some(k => k.startsWith('DEMIPASS_')), 'no DEMIPASS_* variable');
  assert.strictEqual(env.GIT_CONFIG_GLOBAL, '/dev/null'); assert.strictEqual(env.GIT_CONFIG_NOSYSTEM, '1');
  let got = ''; try { got = execFileSync('git', ['config', '--get', 'diff.external'], { env, stdio: 'pipe' }).toString().trim(); } catch (_) { got = ''; }
  assert.strictEqual(got, '', 'the global diff.external is not seen');
});

test('status against a dead door answers within 20 s (a 15 s timeout, no second wait) (code pass 2026-11-16, item 7)', async () => {
  const dead = http.createServer(() => { /* accepts, never answers */ });
  await new Promise(r => dead.listen(0, '127.0.0.1', r));
  const keep = process.env.FLEETGATE_DOOR_URL;
  process.env.FLEETGATE_DOOR_URL = `http://127.0.0.1:${dead.address().port}/door`;
  mcp._reset();
  try {
    const t0 = Date.now();
    const r = await call('fleetgate_status');
    const ms = Date.now() - t0;
    assert.ok(ms < 20000, `took ${ms} ms`); assert.strictEqual(r.ok, false);
    assert.ok(r.status === 'timed_out' || (r.readiness && r.readiness.status === 'door_unreachable'), JSON.stringify(r).slice(0, 200));
  } finally {
    process.env.FLEETGATE_DOOR_URL = keep; mcp._reset(); dead.closeAllConnections && dead.closeAllConnections(); dead.close();
  }
});

test('a free call has one 15 s deadline across its requests: a slow health then a hanging admission still answers in time (#30 independent review)', async () => {
  const slow = http.createServer((req, res) => {
    if (req.url.endsWith('/health')) return setTimeout(() => json(res, 200, { ok: true, version: 'fleetgate-door/4' }), 8000);
    /* every other route hangs */
  });
  await new Promise(r => slow.listen(0, '127.0.0.1', r));
  const keep = process.env.FLEETGATE_DOOR_URL;
  process.env.FLEETGATE_DOOR_URL = `http://127.0.0.1:${slow.address().port}/door`;
  mcp._reset();
  try {
    const t0 = Date.now();
    const r = await call('fleetgate_status');
    const ms = Date.now() - t0;
    assert.ok(ms < 17000, `took ${ms} ms`); assert.strictEqual(r.ok, false);
  } finally {
    process.env.FLEETGATE_DOOR_URL = keep; mcp._reset(); slow.closeAllConnections && slow.closeAllConnections(); slow.close();
  }
});

test('a timed-out free call is inert afterwards: its late answers mint nothing and change no held token (#30 independent review r2)', async () => {
  mcp._reset();
  state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }];
  state.delayConsentsMs = 16000;   // DemiPass answers the consent lookup after the call's 15 s
  const minted = state.minted.length;
  const t0 = Date.now();
  const r = await call('fleetgate_status');
  const ms = Date.now() - t0;
  assert.strictEqual(r.status, 'timed_out'); assert.ok(ms >= 14900 && ms < 15600, `answered at ${ms} ms, at the deadline`);
  await new Promise(ok => setTimeout(ok, 2500));   // the abandoned lookup has now returned
  assert.strictEqual(state.minted.length, minted, 'no token was minted after the call answered');
  mcp._reset();
});

test('status reports this machine\'s git against the 2.45 requirement; an old or missing git says what still works', async () => {
  mcp._reset();
  let r = await call('fleetgate_status');
  assert.strictEqual(r.git.required, '2.45'); assert.match(r.git.version, /^\d+\.\d+(\.\d+)?$/); assert.strictEqual(typeof r.git.ok, 'boolean');
  // an old git and no git, through a fake git on PATH (the MCP reads git's own --version)
  const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-oldgit-'));
  fsx.writeFileSync(pathx.join(dir, 'git'), '#!/bin/sh\necho "git version 2.43.0"\n', { mode: 0o755 });
  const keep = process.env.PATH;
  try {
    process.env.PATH = `${dir}:${keep}`;
    delete require.cache[require.resolve('../fleetgate-mcp.js')];
    const m2 = require('../fleetgate-mcp.js');
    const s2 = JSON.parse((await m2.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fleetgate_status', arguments: {} } })).result.content[0].text);
    assert.deepStrictEqual([s2.git.version, s2.git.ok], ['2.43.0', false]); assert.match(s2.git.error, /fleetgate_submit \{files\} works/);
    process.env.PATH = dir.replace(/$/, '-none');   // no git at all
    delete require.cache[require.resolve('../fleetgate-mcp.js')];
    const m3 = require('../fleetgate-mcp.js');
    const s3 = JSON.parse((await m3.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fleetgate_status', arguments: {} } })).result.content[0].text);
    assert.strictEqual(s3.git.ok, false); assert.match(s3.git.error, /git not found/);
  } finally { process.env.PATH = keep; }
});

test('status never waits on a slow git past its deadline, and never blocks on it (#31 independent review)', async () => {
  const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-slowgit-'));
  fsx.writeFileSync(pathx.join(dir, 'git'), '#!/bin/sh\nsleep 30\necho "git version 2.56.1"\n', { mode: 0o755 });
  const keep = process.env.PATH;
  try {
    process.env.PATH = `${dir}:${keep}`;
    delete require.cache[require.resolve('../fleetgate-mcp.js')];
    const m = require('../fleetgate-mcp.js');
    let ticks = 0; const iv = setInterval(() => { ticks++; }, 1000);   // the event loop keeps running meanwhile
    const t0 = Date.now();
    const r = JSON.parse((await m.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fleetgate_status', arguments: {} } })).result.content[0].text);
    const ms = Date.now() - t0; clearInterval(iv);
    assert.ok(ms < 15600, `took ${ms} ms`); assert.ok(ticks >= 5, `event loop ran ${ticks} ticks (a blocking probe gives 0)`);
    assert.ok(r.status === 'timed_out' || (r.git && r.git.ok === false), JSON.stringify(r).slice(0, 200));
  } finally { process.env.PATH = keep; }
});

test('a git that exists but cannot run is not reported as missing (#31 independent review r2)', async () => {
  const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'fg-noexec-'));
  fsx.writeFileSync(pathx.join(dir, 'git'), '#!/bin/sh\necho "git version 2.56.1"\n', { mode: 0o644 });   // not executable
  const keep = process.env.PATH;
  try {
    process.env.PATH = `${dir}`;
    delete require.cache[require.resolve('../fleetgate-mcp.js')];
    const m = require('../fleetgate-mcp.js');
    const r = JSON.parse((await m.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fleetgate_status', arguments: {} } })).result.content[0].text);
    assert.strictEqual(r.git.ok, false); assert.match(r.git.error, /git could not run \(EACCES\)/);
  } finally { process.env.PATH = keep; }
});


// ── the payment ask (Aaron 2026-11-17: agents and panes never block on a spending limit) ──
test('a review waiting on the daily consent: follow files ONE raise (current + need, to 500), redeems it once approved, never re-asks', async () => {
  mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }]; state.raise = null;
  const posts = () => state.consentPosts.filter(b => b.daily_cap_dd === 7000);
  let r = await call('fleetgate_follow', { review_id: 'review-waiting-01' });
  assert.strictEqual(r.state, 'waiting_payment'); assert.strictEqual(r.ask.status, 'asked', JSON.stringify(r));
  assert.strictEqual(r.ask.approval_id, 88); assert.strictEqual(r.ask.daily_cap_dd, 7000); assert.strictEqual(r.ask.from_dd, 5000);
  assert.match(r.ask.next, /from 5000 to 7000 DD\/day/); assert.match(r.ask.next, /Nothing for you to do/);
  assert.strictEqual(posts().length, 1); assert.strictEqual(posts()[0].approval_id, undefined, 'filed as a new request');
  r = await call('fleetgate_follow', { review_id: 'review-waiting-01' });
  assert.strictEqual(r.ask.status, 'asked'); assert.strictEqual(posts().filter(b => !b.approval_id).length, 1, 'not filed twice');
  // another refusal while the first ask waits: no second card
  r = await call('fleetgate_follow', { review_id: 'review-waiting-02' });
  assert.strictEqual(r.ask.status, 'asked'); assert.strictEqual(posts().filter(b => !b.approval_id).length, 1, 'one ask per wallet at a time');
  state.raise = 'approved';
  r = await call('fleetgate_follow', { review_id: 'review-waiting-01' });
  assert.strictEqual(r.ask.status, 'raised'); assert.strictEqual(r.ask.daily_cap_dd, 7000); assert.match(r.ask.next, /resumes by itself/);
  r = await call('fleetgate_follow', { review_id: 'review-waiting-01' });
  assert.strictEqual(r.ask.status, 'raised'); assert.strictEqual(posts().filter(b => !b.approval_id).length, 1, 'raised: never asked again for this refusal');
  const st = await call('fleetgate_status'); assert.ok(st.payment_asks.some(a => a.subject === 'review:review-waiting-01' && a.status === 'raised'));
  state.consents = saved; state.raise = null; mcp._reset();
});

test('a declined or expired raise is never filed again for that refusal', async () => {
  for (const how of ['declined', 'expired']) {
    mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }]; state.raise = null;
    const before = state.consentPosts.filter(b => b.daily_cap_dd === 7000 && !b.approval_id).length;
    let r = await call('fleetgate_follow', { review_id: 'review-waiting-03' }); assert.strictEqual(r.ask.status, 'asked');
    state.raise = how;
    r = await call('fleetgate_follow', { review_id: 'review-waiting-03' }); assert.strictEqual(r.ask.status, how); assert.match(r.ask.next, /not asked again/);
    r = await call('fleetgate_follow', { review_id: 'review-waiting-03' }); assert.strictEqual(r.ask.status, how);
    assert.strictEqual(state.consentPosts.filter(b => b.daily_cap_dd === 7000 && !b.approval_id).length, before + 1, `${how}: one ask only`);
    state.consents = saved; state.raise = null;
  }
  mcp._reset();
});

test('a wallet short of funds: the next step is the owner\'s (fund it); no consent is filed', async () => {
  mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }];
  const n = state.consentPosts.length;
  const r = await call('fleetgate_follow', { review_id: 'review-fund-01' });
  assert.strictEqual(r.ask.status, 'yours'); assert.strictEqual(r.ask.kind, 'fund'); assert.strictEqual(state.consentPosts.length, n);
  state.consents = saved; mcp._reset();
});


test('a declined raise is never re-filed from another refusal of the same wallet (#35 r1, 2)', async () => {
  mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }]; state.raise = null;
  const fresh = () => state.consentPosts.filter(b => b.daily_cap_dd > 5000 && !b.approval_id).length;
  const n0 = fresh();
  let r = await call('fleetgate_follow', { review_id: 'review-waiting-11' }); assert.strictEqual(r.ask.status, 'asked');
  r = await call('fleetgate_follow', { review_id: 'review-waiting-12' }); assert.strictEqual(r.ask.status, 'asked', 'B shares A\'s pending ask');
  state.raise = 'declined';
  r = await call('fleetgate_follow', { review_id: 'review-waiting-11' }); assert.strictEqual(r.ask.status, 'declined');
  r = await call('fleetgate_follow', { review_id: 'review-waiting-12' }); assert.strictEqual(r.ask.status, 'declined', 'B sees the same decline');
  r = await call('fleetgate_follow', { review_id: 'review-waiting-13' }); assert.strictEqual(r.ask.status, 'declined', 'a new refusal is not asked either');
  assert.strictEqual(fresh(), n0 + 1, 'one card in all');
  state.consents = saved; state.raise = null; mcp._reset();
});


test('an amount the door sends that is not a positive number is not trusted: the step\'s need sizes the raise (#35 r1, 3)', async () => {
  mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }]; state.raise = null;
  const r = await call('fleetgate_follow', { review_id: 'review-waiting-neg' });
  assert.strictEqual(r.ask.status, 'asked'); assert.strictEqual(r.ask.daily_cap_dd, 7000, 'current 5000 + needed 1589, to 500');
  state.consents = saved; mcp._reset();
});


test('a raise keeps the consent\'s Conduit opt-in, filed and redeemed alike (dustforge#131 review 2)', async () => {
  mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, on_request_cap_dd: 500, status: 'active' }]; state.raise = null;
  const n = state.consentPosts.length;
  let r = await call('fleetgate_follow', { review_id: 'review-waiting-21' }); assert.strictEqual(r.ask.status, 'asked');
  state.raise = 'approved';
  r = await call('fleetgate_follow', { review_id: 'review-waiting-21' }); assert.strictEqual(r.ask.status, 'raised');
  const posts = state.consentPosts.slice(n).filter(b => b.daily_cap_dd === 7000);
  assert.strictEqual(posts.length, 2, 'filed, then redeemed'); assert.ok(posts.every(b => b.on_request_cap_dd === 500), JSON.stringify(posts));
  state.consents = saved; state.raise = null; mcp._reset();
});


test('a raise whose answer is still in flight holds the wallet: a timed-out follow and another refusal file nothing more (#35 r2, 1)', async () => {
  mcp._reset(); const saved = state.consents; state.consents = [{ id: 9, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }]; state.raise = null;
  const fresh = () => state.consentPosts.filter(b => b.daily_cap_dd > 5000 && !b.approval_id).length;
  state.raiseFor = null; state.cards = 0;
  state.slowRaiseMs = 16000;   // the POST answers after the follow's 15 s deadline
  const first = await call('fleetgate_follow', { review_id: 'review-waiting-31' });
  assert.strictEqual(first.status, 'timed_out', JSON.stringify(first));
  const cards0 = state.cards || 0;
  // the first request ended with no answer (the SDK's own 15 s timeout): its outcome is unknown, so the wallet is held
  // for a day; nothing is re-sent (a resend after a decline would make a new card: #35 r3, 1)
  let r = await call('fleetgate_follow', { review_id: 'review-waiting-32' });
  assert.strictEqual(r.ask.status, 'filing', 'still in flight, or lost: either way held');
  await new Promise(ok => setTimeout(ok, 1500));   // past the SDK's own 15 s timeout: the answer is lost
  r = await call('fleetgate_follow', { review_id: 'review-waiting-32' });
  assert.strictEqual(r.ask.status, 'filing', JSON.stringify(r.ask)); assert.match(r.ask.next, /answer was lost/);
  state.raise = 'declined';
  r = await call('fleetgate_follow', { review_id: 'review-waiting-33' });
  assert.strictEqual(r.ask.status, 'filing');
  assert.strictEqual(state.cards || 0, cards0, 'no card re-sent or added');
  state.raise = null;
  state.consents = saved; mcp._reset();
});
