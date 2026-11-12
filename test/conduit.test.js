#!/usr/bin/env node
/**
 * Conduit onboarding + client: consent → approval_pending → token → register → config file (0600); every call re-reads
 * the file; an expired token or a 401 mints a new one from the DemiPass bearer; a wallet that already has a name keeps
 * it; a pre-rebuild CONDUIT_TOKEN env var is ignored. Local HTTP stand-ins for DemiPass and Conduit.
 *   node test/conduit.test.js
 */
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-conduit-'));
process.env.CONDUIT_CONFIG = path.join(tmp, 'conduit.json');
process.env.CONDUIT_TOKEN = 'Qh0ZQidLN0CHlegacyKyleBearerNotAJwt';
delete process.env.CONDUIT_URL; delete process.env.CONDUIT_SENDER;
const demipass = require('../index.js');

let failures = 0;
const check = async (name, fn) => { try { await fn(); console.log(`  ok    ${name}`); } catch (e) { failures++; console.log(`  FAIL  ${name}\n        ${e.stack.split('\n').slice(0, 3).join('\n        ')}`); } };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims) => `${b64({ alg: 'EdDSA' })}.${b64(claims)}.sig`;
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
const body = (req) => new Promise((r) => { let raw = ''; req.on('data', (c) => (raw += c)); req.on('end', () => r(raw ? JSON.parse(raw) : {})); });

// ── fake DemiPass ──
const dp = { consentActive: false, mints: 0, issued: new Set(), seen: [] };
const dpSrv = http.createServer(async (req, res) => {
  const b = await body(req); dp.seen.push({ m: req.method, p: req.url, b, auth: req.headers.authorization });
  if (req.headers.authorization !== 'Bearer ' + SESSION && req.headers.authorization !== 'Bearer ' + SESSION_B) return json(res, 401, { error: 'bad session' });
  const sub = req.headers.authorization === 'Bearer ' + SESSION_B ? 'did:key:zOther' : 'did:key:zTester';
  if (req.method === 'GET' && req.url === '/api/services/consents') return json(res, 200, { ok: true, mine: dp.consentActive ? [{ id: 3, service: 'conduit', status: 'active', daily_cap_dd: 300 }] : [], approved_by_me: [] });
  if (req.method === 'POST' && req.url === '/api/services/consent') {
    if (!b.approval_id) return json(res, 202, { status: 'approval_pending', approval_id: 11, expires_at: '2026-11-10T00:00:00Z' });
    assert.strictEqual(b.approval_id, 11); dp.consentActive = true; return json(res, 201, { ok: true, consent_id: 3, service: 'conduit', daily_cap_dd: b.daily_cap_dd });
  }
  if (req.method === 'POST' && req.url === '/api/services/token') {
    if (!dp.consentActive) return json(res, 403, { error: 'consent to pay conduit first', consent_required: true });
    dp.mints++; const exp = Math.floor(Date.now() / 1000) + 3600; const jti = `tok${dp.mints}`;
    const token = jwt({ sub, aud: 'svc:conduit', scope: 'transact', jti, exp, cap_dd: b.cap_dd || 200 });
    dp.issued.add(token);
    return json(res, 201, { ok: true, token, token_id: jti, service: 'conduit', cap_dd: b.cap_dd || 200, expires_at: new Date(exp * 1000).toISOString() });
  }
  json(res, 404, { error: 'not_found' });
});
const SESSION = jwt({ sub: 'did:key:zTester', username: 'tester', scope: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 });
const SESSION_B = jwt({ sub: 'did:key:zOther', username: 'other', scope: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 });

// ── fake Conduit ──
const cd = { agents: new Map(), walletName: null, revoked: new Set(), posts: [], reads: 0 };
const cdSrv = http.createServer(async (req, res) => {
  const b = await body(req);
  if (req.url === '/health') return json(res, 200, { ok: true, service: 'conduit', version: '0.1.0', auth: 'demipass', agents: cd.agents.size, prices_dd: { post: 2, forward: 2, read: 1, ack: 1 } });
  const tok = (req.headers.authorization || '').replace(/^Bearer /, '');
  if (!dp.issued.has(tok) || cd.revoked.has(tok)) return json(res, 401, { error: 'invalid_token' });
  if (req.method === 'POST' && req.url === '/agents/register') {
    if (cd.walletName && cd.walletName !== b.name) return json(res, 409, { error: 'wallet_has_name', name: cd.walletName });
    const existed = cd.agents.has(b.name); cd.walletName = b.name;
    cd.agents.set(b.name, { name: b.name, owns: (b.owns || []).map((s) => s.toLowerCase()).sort(), description: b.description || '' });
    return json(res, existed ? 200 : 201, { ...cd.agents.get(b.name), via: 'own' });
  }
  if (req.method === 'GET' && req.url === '/agents') return json(res, 200, { agents: [...cd.agents.values()] });
  if (req.method === 'POST' && req.url === '/messages') { cd.posts.push(b); return json(res, 201, { msg_id: `msg_${cd.posts.length}`, thread: 'th_1', to: b.to, state: 'delivered', charge_id: 'sc_1' }); }
  if (req.method === 'GET' && req.url.startsWith('/inbox')) { cd.reads++; return json(res, 200, { agent: cd.walletName, messages: [], next_since: 0 }); }
  json(res, 404, { error: 'not_found' });
});

dpSrv.listen(0, '127.0.0.1', () => cdSrv.listen(0, '127.0.0.1', async () => {
  const dpBase = `http://127.0.0.1:${dpSrv.address().port}`;
  const cdBase = `http://127.0.0.1:${cdSrv.address().port}`;
  demipass.configure({ baseUrl: dpBase, bearerToken: SESSION });

  await check('status before onboarding: not onboarded, legacy CONDUIT_TOKEN ignored, says run conduit_onboard', async () => {
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.me.onboarded, false); assert.strictEqual(s.next, 'run conduit_onboard');
    assert.match(s.me.env_token_ignored, /not a DemiPass service token/);
    assert.strictEqual(s.url, 'http://phasewhip.taildb5a42.ts.net:8080');
  });
  await check('a send before onboarding fails on the missing consent, naming conduit_onboard', async () => {
    fs.writeFileSync(process.env.CONDUIT_CONFIG, JSON.stringify({ url: cdBase }));
    await assert.rejects(demipass.conduitSend({ to: 'brain', body: 'hi' }), /run conduit_onboard/);
  });
  await check('onboard with no consent → approval_pending with the approval_id to repeat with', async () => {
    const r = await demipass.conduitOnboard({ url: cdBase, owns: ['kodiak'] });
    assert.strictEqual(r.ok, false); assert.strictEqual(r.status, 'approval_pending'); assert.strictEqual(r.approval_id, 11);
    assert.strictEqual(r.daily_cap_dd, 300); assert.match(r.next, /approval_id=11/);
    assert.deepStrictEqual(dp.seen.pop().b, { service: 'conduit', daily_cap_dd: 300 });
  });
  let token1;
  await check('onboard with approval_id: consent → token → register (name = username) → listed; file 0600, token never returned', async () => {
    const r = await demipass.conduitOnboard({ url: cdBase, owns: ['Kodiak', 'atlas/incus-dashboard'], approval_id: 11, description: 'test pane' });
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(r.name, 'tester'); assert.deepStrictEqual(r.owns, ['atlas/incus-dashboard', 'kodiak']);
    assert.deepStrictEqual(r.consent, { id: 3, daily_cap_dd: 300 }); assert.strictEqual(r.token.minted, true); assert.strictEqual(r.token.token_id, 'tok1');
    assert.strictEqual(r.config_mode, '600'); assert.ok(!JSON.stringify(r).includes('.sig'), 'token leaked into the result');
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8'));
    token1 = f.token; assert.ok(dp.issued.has(token1)); assert.strictEqual(f.name, 'tester'); assert.strictEqual(f.consent_id, 3); assert.strictEqual(f.url, cdBase);
    assert.strictEqual(fs.statSync(process.env.CONDUIT_CONFIG).mode & 0o777, 0o600);
    assert.deepStrictEqual(r.steps.map((s) => s.step), ['health', 'consent', 'token', 'register', 'directory']);
  });
  await check('onboard again is idempotent: existing consent, token reused, owns kept when omitted', async () => {
    const r = await demipass.conduitOnboard();
    assert.strictEqual(r.ok, true); assert.strictEqual(r.token.minted, false); assert.strictEqual(dp.mints, 1);
    assert.deepStrictEqual(r.owns, ['atlas/incus-dashboard', 'kodiak']); assert.ok(r.steps[1].existing);
  });
  await check('send posts {to, subject, body, client_msg_id} with the file token; no env needed', async () => {
    const r = await demipass.conduitSend({ to: 'brain', subject: 'kodiak', body: 'hello', client_msg_id: 'c1' });
    assert.strictEqual(r.ok, true); assert.strictEqual(r.msg_id, 'msg_1');
    assert.deepStrictEqual(cd.posts.pop(), { to: 'brain', subject: 'kodiak', body: 'hello', client_msg_id: 'c1' });
  });
  await check('status after onboarding reports name, token expiry and the directory', async () => {
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.me.onboarded, true); assert.strictEqual(s.me.name, 'tester'); assert.strictEqual(s.me.token_valid, true);
    assert.strictEqual(s.health.ok, true); assert.strictEqual(s.agents.length, 1); assert.strictEqual(s.next, undefined);
  });
  await check('an expired token in the file is minted again on the next call, without onboarding', async () => {
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8'));
    fs.writeFileSync(process.env.CONDUIT_CONFIG, JSON.stringify({ ...f, expires_at: new Date(Date.now() + 60000).toISOString() }));
    const r = await demipass.conduitInbox({ limit: 5 });
    assert.strictEqual(r.agent, 'tester'); assert.strictEqual(dp.mints, 2);
    const f2 = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8'));
    assert.notStrictEqual(f2.token, token1); assert.strictEqual(f2.token_id, 'tok2'); assert.strictEqual(f2.name, 'tester');
    assert.strictEqual(fs.statSync(process.env.CONDUIT_CONFIG).mode & 0o777, 0o600);
  });
  await check('a 401 from Conduit (token revoked) mints once and retries', async () => {
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')); cd.revoked.add(f.token);
    const r = await demipass.conduitSend({ thread: 'th_1', body: 'reply' });
    assert.strictEqual(r.ok, true); assert.strictEqual(dp.mints, 3);
    assert.deepStrictEqual(cd.posts.pop(), { thread: 'th_1', body: 'reply' });
  });
  await check('a wallet that already has a name keeps it; the requested name is reported', async () => {
    const r = await demipass.conduitOnboard({ name: 'workbench' });
    assert.strictEqual(r.ok, true); assert.strictEqual(r.name, 'tester');
    const note = r.steps.find((s) => s.step === 'register' && s.note); assert.ok(note && note.requested === 'workbench', JSON.stringify(r.steps));
    assert.deepStrictEqual(r.owns, ['atlas/incus-dashboard', 'kodiak']);
  });
  await check('relay down → ok:false at step health, nothing filed, and the working relay URL is kept (#16 review P2)', async () => {
    const before = dp.seen.length;
    const r = await demipass.conduitOnboard({ url: 'http://127.0.0.1:9' });
    assert.strictEqual(r.ok, false); assert.strictEqual(r.step, 'health'); assert.strictEqual(dp.seen.length, before);
    assert.strictEqual(JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')).url, cdBase);
    assert.strictEqual(demipass.conduitConfig().url, cdBase);
  });
  await check('another wallet signed in on the same machine never uses the previous wallet\'s token (#16 review P1)', async () => {
    const mints = dp.mints;
    demipass.configure({ baseUrl: dpBase, bearerToken: SESSION_B });
    const r = await demipass.conduitOnboard({});
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(dp.mints, mints + 1, 'a token was minted for the new wallet');
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8'));
    assert.strictEqual(JSON.parse(Buffer.from(f.token.split('.')[1], 'base64url')).sub, 'did:key:zOther');
    assert.strictEqual(f.wallet, 'did:key:zOther');
    demipass.configure({ baseUrl: dpBase, bearerToken: SESSION });
    const m2 = dp.mints;
    await demipass.conduitSend({ to: 'kodiak', body: 'back' });
    assert.strictEqual(dp.mints, m2 + 1, 'the first wallet again: its own token is minted, not the other\'s reused');
    assert.strictEqual(cd.posts.pop().body, 'back');
  });

  dpSrv.close(); cdSrv.close(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? `\n${failures} failing` : '\nall passing');
  process.exit(failures ? 1 : 0);
}));
