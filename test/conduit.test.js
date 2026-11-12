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
const dp = { consentActive: false, mints: 0, issued: new Set(), seen: [], endpoint: null, registryHits: 0 };
const dpSrv = http.createServer(async (req, res) => {
  const b = await body(req); dp.seen.push({ m: req.method, p: req.url, b, auth: req.headers.authorization });
  if (req.method === 'GET' && req.url === '/api/services/conduit') { dp.registryHits++; return json(res, 200, { slug: 'conduit', name: 'Conduit', endpoint: dp.endpoint, mcp_server: dp.endpoint ? 'demipass#demipass-mcp' : null }); }
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
const cd = { agents: new Map(), walletName: null, revoked: new Set(), posts: [], reads: 0, retired: new Map(), registers: [], stickyRetire: false };
const cdSrv = http.createServer(async (req, res) => {
  const b = await body(req);
  if (req.url === '/health') return json(res, 200, { ok: true, service: 'conduit', version: '0.1.0', auth: 'demipass', agents: cd.agents.size, prices_dd: { post: 2, forward: 2, read: 1, ack: 1 } });
  const tok = (req.headers.authorization || '').replace(/^Bearer /, '');
  if (!dp.issued.has(tok) || cd.revoked.has(tok)) return json(res, 401, { error: 'invalid_token' });
  // Retirement (relay review): calls AS a retired address get 410 address_retired; sends TO one 410 recipient_retired; the
  // body carries retired_by ('expiry' | 'owner'; absent = an older relay). Re-registering from the owning wallet
  // reactivates it (stickyRetire: a relay that keeps it retired).
  const as = req.headers['x-conduit-address'];
  const by = (n) => (cd.retired.get(n) ? { retired_by: cd.retired.get(n) } : {});
  if (as && cd.retired.has(as) && req.url !== '/agents/register') return json(res, 410, { error: 'address_retired', name: as, retired_at: '2026-11-05T00:00:00.000Z', ...by(as), detail: 're-register it' });
  if (req.method === 'POST' && req.url === '/messages' && cd.retired.has(b.to)) return json(res, 410, { error: 'recipient_retired', to: b.to, retired_at: '2026-11-04T00:00:00.000Z', ...by(b.to) });
  if (req.method === 'POST' && req.url === '/agents/register') {
    cd.registers.push(b); if (!cd.stickyRetire && cd.retired.delete(b.name)) b.reactivated = true;
    if (!b.session_id && cd.walletName && cd.walletName !== b.name) return json(res, 409, { error: 'wallet_has_name', name: cd.walletName });
    const existed = cd.agents.has(b.name); if (!b.session_id) cd.walletName = b.name;
    cd.agents.set(b.name, { name: b.name, owns: (b.owns || []).map((s) => s.toLowerCase()).sort(), description: b.description || '' });
    return json(res, existed ? 200 : 201, { ...cd.agents.get(b.name), via: 'own' });
  }
  if (req.method === 'GET' && req.url === '/agents') return json(res, 200, { agents: [...cd.agents.values()] });
  if (req.method === 'POST' && req.url === '/messages') { cd.posts.push(b); return json(res, 201, { msg_id: `msg_${cd.posts.length}`, thread: 'th_1', to: b.to, state: 'delivered', charge_id: 'sc_1' }); }
  if (req.method === 'GET' && (req.url.startsWith('/history?') || req.url.startsWith('/receipts?'))) return json(res, 200, { address: req.headers['x-conduit-address'], route: req.url });
  if (req.method === 'GET' && req.url.startsWith('/inbox')) { cd.reads++; return json(res, 200, { agent: cd.walletName, messages: [], next_since: 0 }); }
  json(res, 404, { error: 'not_found' });
});

dpSrv.listen(0, '127.0.0.1', () => cdSrv.listen(0, '127.0.0.1', async () => {
  const dpBase = `http://127.0.0.1:${dpSrv.address().port}`;
  const cdBase = `http://127.0.0.1:${cdSrv.address().port}`;
  demipass.configure({ baseUrl: dpBase, bearerToken: SESSION });

  await check('status before onboarding: not onboarded, legacy CONDUIT_TOKEN ignored, says run conduit_onboard; url = default when the registry has no endpoint', async () => {
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.me.onboarded, false); assert.strictEqual(s.next, 'run conduit_onboard');
    assert.match(s.me.env_token_ignored, /not a DemiPass service token/);
    assert.strictEqual(s.url, 'http://phasewhip.taildb5a42.ts.net:8080'); assert.strictEqual(s.url_source, 'default'); assert.strictEqual(dp.registryHits, 1);
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
    { const p = cd.posts.pop(); assert.match(p.client_msg_id || '', /^cm_[0-9a-f]{24}$/, 'a generated idempotency key'); delete p.client_msg_id; assert.deepStrictEqual(p, { thread: 'th_1', body: 'reply' }); }
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
  await check('onboarding with a cached token Conduit has revoked mints once and registers (#16 review round 2)', async () => {
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')); cd.revoked.add(f.token);
    // the directory is the truth for what the name owns; the file's copy is stale (#16 review, after merge)
    const mine = cd.agents.get(cd.walletName); mine.owns = ['dir-owned']; f.owns = ['stale']; fs.writeFileSync(process.env.CONDUIT_CONFIG, JSON.stringify(f));
    const m = dp.mints;
    const r = await demipass.conduitOnboard({});
    assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(dp.mints, m + 1);
    assert.deepStrictEqual(r.owns, ['dir-owned'], 'owns from the directory, looked up with the fresh token');
    assert.notStrictEqual(JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')).token, f.token);
  });
  await check('a token only in CONDUIT_TOKEN is minted into the shared file by onboarding (#16 review round 2)', async () => {
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8'));
    process.env.CONDUIT_TOKEN = f.token; delete f.token; delete f.token_id; delete f.expires_at; fs.writeFileSync(process.env.CONDUIT_CONFIG, JSON.stringify(f));
    const m = dp.mints;
    const r = await demipass.conduitOnboard({});
    assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(dp.mints, m + 1);
    assert.ok(JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')).token, 'the file now holds a token');
    delete process.env.CONDUIT_TOKEN;
  });

  await check('no url in the file and no CONDUIT_URL → the tenant registry endpoint is used, and never written to the file', async () => {
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')); delete f.url; fs.writeFileSync(process.env.CONDUIT_CONFIG, JSON.stringify(f));
    dp.endpoint = cdBase + '/'; demipass._conduitRegistryReset();
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.url, cdBase); assert.strictEqual(s.url_source, 'registry'); assert.strictEqual(s.health.ok, true);
    const r = await demipass.conduitSend({ to: 'brain', body: 'via registry' }); assert.strictEqual(r.ok, true);
    const r2 = await demipass.conduitOnboard(); assert.strictEqual(r2.ok, true); assert.strictEqual(r2.url_source, 'registry');
    const f2 = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')); assert.strictEqual(f2.url, undefined);
    assert.strictEqual(dp.registryHits, 2, 'registry answer is cached');
  });
  await check('a failed registry lookup is not cached: the next call asks again (#18 review round 2)', async () => {
    const f = JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')); delete f.url; fs.writeFileSync(process.env.CONDUIT_CONFIG, JSON.stringify(f));
    let up = false, hits = 0;
    const flaky = http.createServer((req, res) => { if (req.url !== '/api/services/conduit') return json(res, 404, {}); hits++; if (!up) { res.writeHead(503); return res.end(); } json(res, 200, { slug: 'conduit', endpoint: 'http://127.0.0.1:8' }); });
    await new Promise((r) => flaky.listen(0, '127.0.0.1', r));
    demipass.configure({ baseUrl: `http://127.0.0.1:${flaky.address().port}`, bearerToken: SESSION });
    assert.strictEqual((await demipass.conduitStatus()).url_source, 'default', 'registry down: default for now');
    up = true;
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.url, 'http://127.0.0.1:8'); assert.strictEqual(s.url_source, 'registry');
    const h = hits; await demipass.conduitStatus(); assert.strictEqual(hits, h, 'an answer is cached');
    flaky.close(); demipass.configure({ baseUrl: dpBase, bearerToken: SESSION });
  });
  await check('a DemiPass hosted under a path keeps that path in the registry lookup (#18 review round 3)', async () => {
    const sub = http.createServer((req, res) => req.url === '/dp/api/services/conduit' ? json(res, 200, { slug: 'conduit', endpoint: 'http://127.0.0.1:9' }) : json(res, 404, {}));
    await new Promise((r) => sub.listen(0, '127.0.0.1', r));
    demipass.configure({ baseUrl: `http://127.0.0.1:${sub.address().port}/dp/`, bearerToken: SESSION });
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.url, 'http://127.0.0.1:9'); assert.strictEqual(s.url_source, 'registry');
    sub.close(); demipass.configure({ baseUrl: dpBase, bearerToken: SESSION });
  });
  await check('configure({ baseUrl }) to another DemiPass asks that registry, not the cached answer (#18 review P2)', async () => {
    const other = http.createServer((req, res) => json(res, 200, { slug: 'conduit', endpoint: 'http://127.0.0.1:7' }));
    await new Promise((r) => other.listen(0, '127.0.0.1', r));
    demipass.configure({ baseUrl: `http://127.0.0.1:${other.address().port}`, bearerToken: SESSION });
    const s = await demipass.conduitStatus();
    assert.strictEqual(s.url, 'http://127.0.0.1:7'); assert.strictEqual(s.url_source, 'registry');
    other.close(); demipass.configure({ baseUrl: dpBase, bearerToken: SESSION });
    assert.strictEqual((await demipass.conduitStatus()).url, cdBase, 'back on the first DemiPass: its own registry answer');
  });
  await check('an explicit url wins over the registry and is persisted', async () => {
    const r = await demipass.conduitOnboard({ url: cdBase }); assert.strictEqual(r.url_source, 'argument');
    assert.strictEqual(JSON.parse(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8')).url, cdBase);
    assert.strictEqual((await demipass.conduitStatus()).url_source, 'config_file');
  });

  await check('pane onboarding keeps shared payer/cap, exact UUID address, separate file and header', async () => {
    const before = fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8');
    const shared = JSON.parse(before);
    const family = 'astra', sid = '11111111-2222-3333-4444-555555555555';
    const expected = `${family}-${sid}`;
    const r = await demipass.conduitOnboard({ model_family: family, session_id: sid, url: cdBase });
    assert.strictEqual(r.ok, true); assert.strictEqual(r.name, expected);
    assert.strictEqual(r.wallet, shared.wallet);
    assert.strictEqual(r.consent.daily_cap_dd, shared.daily_cap_dd);
    assert.notStrictEqual(r.config_file, process.env.CONDUIT_CONFIG);
    assert.strictEqual(fs.readFileSync(process.env.CONDUIT_CONFIG, 'utf8'), before);
    assert.strictEqual(fs.statSync(r.config_file).mode & 0o777, 0o600);
    assert.strictEqual((await demipass.conduitHistory({ since: 7, limit: 2 })).address, expected);
    assert.strictEqual((await demipass.conduitReceipts({ since: 8 })).route, '/receipts?since=8&limit=100');
    await assert.rejects(demipass.conduitOnboard({ model_family: 'sol', session_id: sid }), /another pane/);
    assert.throws(() => demipass.conduitPaneAddress({ model_family: '../bad', session_id: sid }));
    assert.throws(() => demipass.conduitPaneAddress({ model_family: family, session_id: 'short-prefix' }));
  });
  const PANE = 'astra-11111111-2222-3333-4444-555555555555';
  await check('a pane address retired by idle expiry is re-registered once (same identity, previous owns) and the call retried', async () => {
    const o = await demipass.conduitOnboard({ owns: ['pane-subject'] }); assert.strictEqual(o.ok, true, JSON.stringify(o));
    cd.retired.set(PANE, 'expiry'); cd.registers.length = 0; const posts = cd.posts.length;
    const r = await demipass.conduitSend({ to: 'brain', body: 'back after a week', client_msg_id: 'c-retired' });
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(cd.registers.length, 1);
    assert.deepStrictEqual(cd.registers[0], { name: PANE, model_family: 'astra', session_id: '11111111-2222-3333-4444-555555555555', owns: ['pane-subject'], reactivated: true });
    assert.ok(!cd.retired.has(PANE)); assert.strictEqual(cd.posts.length, posts + 1, 'the original call retried exactly once');
    assert.strictEqual(cd.posts[cd.posts.length - 1].client_msg_id, 'c-retired', 'the retry keeps the idempotency key');
    assert.ok(JSON.parse(fs.readFileSync(demipass.conduitConfig().file, 'utf8')).revived_at);
  });
  await check('a relay that keeps an expired address retired: one re-register, one retry, then a clear 410 (no loop)', async () => {
    cd.retired.set(PANE, 'expiry'); cd.stickyRetire = true; cd.registers.length = 0; const posts = cd.posts.length;
    try {
      await assert.rejects(demipass.conduitSend({ to: 'brain', body: 'still gone' }), (e) => {
        assert.strictEqual(e.status, 410); assert.strictEqual(e.code, 'address_retired'); assert.strictEqual(e.retired_by, 'expiry');
        assert.match(e.message, /retired after 7 days idle.*still retired after re-registering once/); return true;
      });
      assert.strictEqual(cd.registers.length, 1); assert.strictEqual(cd.posts.length, posts);
    } finally { cd.stickyRetire = false; cd.retired.delete(PANE); }
  });
  await check('an address retired by its owner, or by an older relay that does not say why, is never revived automatically', async () => {
    for (const why of ['owner', undefined]) {
      cd.retired.set(PANE, why); cd.registers.length = 0; const posts = cd.posts.length;
      await assert.rejects(demipass.conduitSend({ to: 'brain', body: 'deliberately retired' }), (e) => {
        assert.strictEqual(e.status, 410); assert.strictEqual(e.code, 'address_retired'); assert.strictEqual(e.retired_by, why || null);
        assert.match(e.message, new RegExp(`${PANE} was ${why === 'owner' ? 'retired by its owner' : 'retired \\(the relay did not say why\\)'}.*not revived automatically.*re-onboard deliberately with conduit_onboard`, 'i'));
        return true;
      });
      assert.strictEqual(cd.registers.length, 0, `no re-register (retired_by ${why})`); assert.strictEqual(cd.posts.length, posts);
      assert.ok(cd.retired.has(PANE), 'still retired');
    }
    // the deliberate path: an explicit conduit_onboard brings it back
    const o = await demipass.conduitOnboard({ owns: ['pane-subject'] }); assert.strictEqual(o.ok, true, JSON.stringify(o));
    assert.ok(!cd.retired.has(PANE)); assert.strictEqual((await demipass.conduitSend({ to: 'brain', body: 'back on purpose' })).ok, true);
  });
  await check('sending to a retired pane address is a clear recipient_retired error worded from retired_by, never a revive', async () => {
    const ghost = 'fable-99999999-8888-4777-8666-555555555555';
    const cases = [['expiry', /that pane address was retired after 7 days idle/], ['owner', /that pane address was retired by its owner/], [undefined, /that pane address was retired \(the relay did not say why\)/]];
    try {
      for (const [why, re] of cases) {
        cd.retired.set(ghost, why); cd.registers.length = 0;
        await assert.rejects(demipass.conduitSend({ to: ghost, body: 'hello?' }), (e) => {
          assert.match(e.message, new RegExp(`"${ghost}" is gone`)); assert.match(e.message, re);
          assert.strictEqual(e.code, 'recipient_retired'); assert.strictEqual(e.status, 410); assert.strictEqual(e.body.to, ghost);
          return true;
        });
        assert.strictEqual(cd.registers.length, 0, 'never re-registers someone else\'s address');
      }
    } finally { cd.retired.delete(ghost); }
  });
  await check('pane mode refuses a relay that falls back to a different name', async () => {
    const old = http.createServer((req, res) => {
      if (req.url === '/health') return json(res, 200, { ok: true });
      if (req.url === '/agents') return json(res, 200, []);
      return json(res, 409, { error: 'wallet_has_name', name: 'aaron' });
    });
    await new Promise(r => old.listen(0, '127.0.0.1', r));
    try {
      const r = await demipass.conduitOnboard({ url: `http://127.0.0.1:${old.address().port}` });
      assert.strictEqual(r.ok, false); assert.strictEqual(r.step, 'register');
      assert.notStrictEqual(demipass.conduitConfig().name, 'aaron');
    } finally { old.close(); }
  });

  await check('unbound pane refuses legacy routing before any network call', async () => {
    const child = require('child_process').spawnSync(process.execPath, ['-e', `
      const assert=require('assert');const sdk=require('./index.js');
      assert.strictEqual(sdk.conduitConfig().onboarded,false);
      assert.strictEqual(sdk.conduitConfig().name,'');
      (async()=>{
        const r=await sdk.conduitOnboard();assert.strictEqual(r.step,'pane_identity');
        await assert.rejects(sdk.conduitSend({to:'someone',body:'must not send'}),/Pane identity required/);
      })().catch(()=>{process.exitCode=1});
    `], { cwd: path.join(__dirname, '..'), env: {...process.env, CONDUIT_REQUIRE_PANE:'1', CONDUIT_MODEL_FAMILY:'', CONDUIT_SESSION_ID:''}, encoding:'utf8', timeout:3000 });
    assert.strictEqual(child.status,0,child.stderr);
  });

  await check('Claude Code\'s CLAUDE_CODE_SESSION_ID is read; a partial env identity is reported, not thrown (fresh process)', async () => {
    const { execFileSync } = require('child_process');
    const run = (env) => JSON.parse(execFileSync(process.execPath, ['-e', 'const d=require(process.argv[1]); const c=d.conduitConfig(); console.log(JSON.stringify({a:c.pane_address,e:c.pane_error||null}))', require.resolve('../index.js')],
      { env: { PATH: process.env.PATH, HOME: process.env.HOME, CONDUIT_CONFIG: process.env.CONDUIT_CONFIG, ...env }, encoding: 'utf8' }));
    let r = run({ CONDUIT_MODEL_FAMILY: 'opus', CLAUDE_CODE_SESSION_ID: 'ABCDEF01-2345-6789-abcd-ef0123456789' });
    assert.strictEqual(r.a, 'opus-abcdef01-2345-6789-abcd-ef0123456789', 'from CLAUDE_CODE_SESSION_ID, lower-cased');
    r = run({ CONDUIT_MODEL_FAMILY: 'opus', CLAUDE_CODE_SESSION_ID: 'not-a-uuid' });
    assert.strictEqual(r.a, null); assert.match(r.e || '', /incomplete or malformed/);
    // and with a shared legacy config present, messaging is refused rather than sent as the legacy name (Codex #19 P2)
    const send = execFileSync(process.execPath, ['-e', 'const d=require(process.argv[1]); d.configure({bearerToken:"x.e30.s"}); d.conduitSend({to:"brain",body:"hi"}).then(()=>console.log("SENT"),e=>console.log("REFUSED "+e.message))', require.resolve('../index.js')],
      { env: { PATH: process.env.PATH, HOME: process.env.HOME, CONDUIT_CONFIG: process.env.CONDUIT_CONFIG, CONDUIT_MODEL_FAMILY: 'opus', CLAUDE_CODE_SESSION_ID: 'not-a-uuid' }, encoding: 'utf8' });
    assert.match(send, /^REFUSED .*refusing to message as the shared legacy address/);
  });

  dpSrv.close(); cdSrv.close(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? `\n${failures} failing` : '\nall passing');
  process.exit(failures ? 1 : 0);
}));
