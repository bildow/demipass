#!/usr/bin/env node
/**
 * Device-login + credential lifecycle tests.
 *
 * Covers: token decoding (never leaks the token), the SDK deviceLogin orchestration
 * (start → show code → poll pending → approved → persist 0600 → bearer adopted),
 * bearer precedence (credentials file vs DEMIPASS_TOKEN env), automatic refresh
 * incl. the multi-process race on single-use refresh tokens, logout, and the MCP
 * server end-to-end over JSON-RPC (login tools present, login → wait → approved
 * hot-swaps the bearer without a restart, status, logout).
 *
 * Runs against a throwaway local HTTP server; no network, no real credentials.
 *   node test/device-login.test.js
 */
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { spawn } = require('child_process');

const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'demipass-devlogin-'));
const CRED = path.join(tmpdir, 'creds', 'credentials.json');
process.env.DEMIPASS_CREDENTIALS = CRED;
delete process.env.DEMIPASS_TOKEN;
const demipass = require('../index.js');

let failures = 0, passes = 0;
async function check(name, fn) {
  try { await fn(); passes++; console.log(`  ok    ${name}`); }
  catch (e) { failures++; console.log(`  FAIL  ${name}\n        ${(e.stack || e.message).split('\n').slice(0, 3).join('\n        ')}`); }
}
const jwt = (payload) => { const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url'); return `${b({ alg: 'EdDSA', typ: 'JWT' })}.${b(payload)}.sig`; };
const now = () => Math.floor(Date.now() / 1000);
const mint = (secondsLeft, extra = {}) => jwt({ sub: 'did:key:zTEST', scope: 'transact', iss: 'civitasvox', iat: now(), exp: now() + secondsLeft, jti: 'j' + Math.random().toString(16).slice(2, 8), email: 'op@dustforge.com', ...extra });

// ── Mock DemiPass server ──
const state = { pollsUntilApproved: 2, polls: 0, refreshCurrent: 'dpr_1', refreshCount: 0, lastAuth: null, log: [] };
const server = http.createServer((req, res) => {
  let raw = ''; req.on('data', (c) => (raw += c)); req.on('end', () => {
    let body = {}; try { body = JSON.parse(raw || '{}'); } catch {}
    state.log.push({ path: req.url, body, auth: req.headers.authorization || null });
    const send = (status, obj) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.url === '/api/identity/device/code') return send(200, { ok: true, device_code: 'dpd_test', user_code: 'ABCD-EFGH', verification_url: 'https://demipass.com/device', verification_url_complete: 'https://demipass.com/device?code=ABCD-EFGH', interval: 1, expires_in: 900 });
    if (req.url === '/api/identity/device/token') {
      if (body.device_code === 'dpd_denied') return send(403, { error: 'access_denied' });
      if (body.device_code === 'dpd_expired') return send(400, { error: 'expired_token' });
      if (body.device_code !== 'dpd_test') return send(400, { error: 'invalid device_code' });
      state.polls++;
      if (state.polls < state.pollsUntilApproved) return send(428, { error: 'authorization_pending' });
      return send(200, { ok: true, token: mint(86400, { auth_method: 'device', agent_label: 'test-agent@host' }), refresh_token: 'dpr_1', refresh_expires_at: new Date(Date.now() + 90 * 86400e3).toISOString(), did: 'did:key:zTEST', scope: 'transact', email: 'op@dustforge.com', auth_method: 'device', agent_label: 'test-agent@host' });
    }
    if (req.url === '/api/identity/refresh') {
      if (body.refresh_token !== state.refreshCurrent) return send(401, { error: 'invalid, expired, or revoked refresh token' });
      state.refreshCount++; state.refreshCurrent = 'dpr_' + (state.refreshCount + 1);
      return send(200, { ok: true, token: mint(86400, { auth_method: 'refresh' }), refresh_token: state.refreshCurrent, refresh_expires_at: new Date(Date.now() + 90 * 86400e3).toISOString(), did: 'did:key:zTEST', scope: 'transact', email: 'op@dustforge.com', auth_method: 'refresh' });
    }
    if (req.url === '/api/identity/refresh/revoke') return send(200, { ok: true, revoked: true });
    if (req.url === '/api/identity/tokens/revoke') return send(200, { ok: true });
    if (req.url === '/api/demipass/list') { state.lastAuth = req.headers.authorization || null; return send(200, { secrets: [], total: 0 }); }
    if (req.url.startsWith('/api/identity/trust')) return send(200, { did: 'did:key:zTEST', band: 'test' });
    send(404, { error: 'not found: ' + req.url });
  });
});

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  demipass.configure({ baseUrl: base });

  console.log('\ntokenInfo');
  await check('decodes lifecycle fields without exposing the token', () => {
    const t = mint(3600, { agent_label: 'x@y' });
    const i = demipass.tokenInfo(t);
    assert.strictEqual(i.did, 'did:key:zTEST'); assert.strictEqual(i.scope, 'transact'); assert.strictEqual(i.agent_label, 'x@y');
    assert.ok(i.seconds_remaining > 3500 && i.seconds_remaining <= 3600); assert.strictEqual(i.expired, false);
    assert.ok(!JSON.stringify(i).includes(t.split('.')[1]), 'must not carry the token payload');
  });
  await check('returns null for non-JWT input', () => { assert.strictEqual(demipass.tokenInfo('nope'), null); assert.strictEqual(demipass.tokenInfo(''), null); assert.strictEqual(demipass.tokenInfo(undefined), null); });
  await check('flags expired tokens', () => { assert.strictEqual(demipass.tokenInfo(mint(-10)).expired, true); });

  console.log('\ndeviceLogin (SDK)');
  await check('start → code shown → pending ×2 → approved → persisted 0600, bearer adopted, no token in result', async () => {
    state.polls = 0; state.pollsUntilApproved = 3;
    let shown = null;
    const res = await demipass.deviceLogin({ agentLabel: 'test-agent@host', scope: 'transact', intervalMs: 20, onCode: (c) => { shown = c; } });
    assert.strictEqual(shown.user_code, 'ABCD-EFGH'); assert.ok(shown.verification_url_complete.includes('ABCD-EFGH'));
    assert.strictEqual(state.polls, 3, 'two pending polls then the approved one');
    assert.strictEqual(res.ok, true); assert.strictEqual(res.did, 'did:key:zTEST'); assert.strictEqual(res.path, CRED);
    assert.ok(!('token' in res) && !('refresh_token' in res), 'result must not carry token values');
    assert.strictEqual(fs.statSync(CRED).mode & 0o777, 0o600);
    const rec = JSON.parse(fs.readFileSync(CRED, 'utf8'));
    assert.ok(rec.token && rec.refresh_token === 'dpr_1' && rec.base_url === base && rec.agent_label === 'test-agent@host');
    await demipass.list();
    assert.strictEqual(state.lastAuth, 'Bearer ' + rec.token, 'subsequent requests must use the new bearer');
  });
  await check('start sends agent_label + scope', () => { const s = state.log.find((l) => l.path === '/api/identity/device/code'); assert.strictEqual(s.body.agent_label, 'test-agent@host'); assert.strictEqual(s.body.scope, 'transact'); });
  await check('denied → clear error', async () => { await assert.rejects(demipass.deviceCodePoll({ deviceCode: 'dpd_denied' }), /denied/); });
  await check('expired → clear error', async () => { await assert.rejects(demipass.deviceCodePoll({ deviceCode: 'dpd_expired' }), /expired/); });

  console.log('\nloadBearerFromEnvironment precedence');
  await check('valid credentials file beats env token', () => {
    const r = demipass.loadBearerFromEnvironment({ envToken: mint(3600, { sub: 'did:key:zENV' }), file: CRED });
    assert.strictEqual(r.source, 'credentials_file'); assert.strictEqual(r.did, 'did:key:zTEST'); assert.ok(!('token' in r));
  });
  await check('expired file with no refresh token falls back to env', () => {
    const f = path.join(tmpdir, 'stale.json'); fs.writeFileSync(f, JSON.stringify({ token: mint(-5), refresh_token: null }));
    const r = demipass.loadBearerFromEnvironment({ envToken: mint(3600, { sub: 'did:key:zENV' }), file: f });
    assert.strictEqual(r.source, 'env'); assert.strictEqual(r.did, 'did:key:zENV');
  });
  await check('expired file with a live refresh token is still chosen (refreshable)', () => {
    const f = path.join(tmpdir, 'refreshable.json'); fs.writeFileSync(f, JSON.stringify({ token: mint(-5), refresh_token: 'dpr_x', refresh_expires_at: new Date(Date.now() + 86400e3).toISOString() }));
    assert.strictEqual(demipass.loadBearerFromEnvironment({ envToken: mint(3600), file: f }).source, 'credentials_file');
  });
  await check('DEMIPASS_URL env wins over the file base_url; file base_url used otherwise', () => {
    demipass.loadBearerFromEnvironment({ envToken: '', envBaseUrl: 'http://explicit.test', file: CRED });
    assert.strictEqual(demipass.loginStatus({ file: CRED }).base_url, base, 'explicit env must not be overridden');
    demipass.configure({ baseUrl: 'http://other.test' });
    demipass.loadBearerFromEnvironment({ envToken: '', envBaseUrl: '', file: CRED });
    assert.strictEqual(demipass.loginStatus({ file: CRED }).base_url, base, 'file base_url adopted when env unset');
  });
  await check('nothing anywhere → none', () => { assert.strictEqual(demipass.loadBearerFromEnvironment({ envToken: '', file: path.join(tmpdir, 'absent.json') }).source, 'none'); });

  console.log('\nensureFreshToken');
  await check('fresh token → no network call', async () => {
    demipass.configure({ bearerToken: mint(7200) }); const n = state.log.length;
    assert.strictEqual((await demipass.ensureFreshToken({ file: CRED })).reason, 'fresh'); assert.strictEqual(state.log.length, n);
  });
  await check('near-expiry token + refresh on file → refreshed, rotated refresh token persisted, label kept', async () => {
    const near = mint(600);
    fs.writeFileSync(CRED, JSON.stringify({ base_url: base, token: near, refresh_token: state.refreshCurrent, agent_label: 'test-agent@host' }));
    demipass.configure({ bearerToken: near });
    const r = await demipass.ensureFreshToken({ file: CRED });
    assert.strictEqual(r.refreshed, true);
    const rec = JSON.parse(fs.readFileSync(CRED, 'utf8'));
    assert.strictEqual(rec.refresh_token, state.refreshCurrent); assert.notStrictEqual(rec.token, near); assert.strictEqual(rec.agent_label, 'test-agent@host');
    await demipass.list(); assert.strictEqual(state.lastAuth, 'Bearer ' + rec.token);
    assert.strictEqual((await demipass.ensureFreshToken({ file: CRED })).reason, 'fresh');
  });
  await check('sibling process already refreshed → adopt from file instead of burning the refresh token', async () => {
    const near = mint(600), sibling = mint(80000);
    fs.writeFileSync(CRED, JSON.stringify({ base_url: base, token: sibling, refresh_token: 'dpr_sibling' }));
    demipass.configure({ bearerToken: near }); const n = state.log.length;
    assert.strictEqual((await demipass.ensureFreshToken({ file: CRED })).reason, 'adopted_from_file'); assert.strictEqual(state.log.length, n);
    await demipass.list(); assert.strictEqual(state.lastAuth, 'Bearer ' + sibling);
  });
  await check('stale refresh token (401) and no fresher file → clear error pointing at re-login', async () => {
    const near = mint(600);
    fs.writeFileSync(CRED, JSON.stringify({ base_url: base, token: near, refresh_token: 'dpr_stale' }));
    demipass.configure({ bearerToken: near });
    await assert.rejects(demipass.ensureFreshToken({ file: CRED }), /refresh failed.*demipass_login/);
  });
  await check('no token, no file → quiet no-op', async () => {
    // configure() ignores a falsy bearer by design; logout() is the way to drop one.
    const absent = path.join(tmpdir, 'absent.json');
    await demipass.logout({ file: absent, revoke: false });
    assert.strictEqual(demipass.loginStatus({ file: absent }).active, null);
    assert.strictEqual((await demipass.ensureFreshToken({ file: absent })).reason, 'no_token');
  });

  console.log('\nlogout');
  await check('revokes refresh + access, deletes file, drops bearer', async () => {
    const t = mint(600);
    fs.writeFileSync(CRED, JSON.stringify({ base_url: base, token: t, refresh_token: 'dpr_any' }));
    demipass.configure({ bearerToken: t });
    const r = await demipass.logout({ file: CRED });
    assert.strictEqual(r.refresh_revoked, true); assert.strictEqual(r.access_revoked, true); assert.strictEqual(fs.existsSync(CRED), false);
    assert.strictEqual(demipass.loginStatus({ file: CRED }).active, null);
  });

  console.log('\nMCP server (subprocess, JSON-RPC over stdio)');
  await check('tools/list has login tools; login → wait → approved hot-swaps bearer; status; logout', async () => {
    state.polls = 0; state.pollsUntilApproved = 2; state.lastAuth = null;
    const mcpCred = path.join(tmpdir, 'mcp', 'credentials.json');
    const env = { ...process.env, DEMIPASS_URL: base, DEMIPASS_CREDENTIALS: mcpCred }; delete env.DEMIPASS_TOKEN;
    const child = spawn(process.execPath, [path.join(__dirname, '..', 'mcp-server.js')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let buf = ''; const pending = new Map(); let nextId = 1;
    child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) !== -1) { const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (!line) continue; try { const m = JSON.parse(line); if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } } catch {} } });
    const rpc = (method, params) => new Promise((resolve, reject) => { const id = nextId++; pending.set(id, resolve); child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error('rpc timeout ' + method)); } }, 20000); });
    const call = async (name, args) => { const m = await rpc('tools/call', { name, arguments: args || {} }); const text = m.result?.content?.[0]?.text || ''; if (m.result?.isError) throw new Error(text); return JSON.parse(text); };
    try {
      await rpc('initialize', {});
      const names = (await rpc('tools/list', {})).result.tools.map((t) => t.name);
      for (const n of ['demipass_login', 'demipass_login_wait', 'demipass_login_status', 'demipass_logout']) assert.ok(names.includes(n), 'missing tool ' + n);
      assert.strictEqual((await call('demipass_login_status')).active, null);
      const start = await call('demipass_login', { agent_label: 'mcp-test@host', scope: 'transact' });
      assert.strictEqual(start.user_code, 'ABCD-EFGH'); assert.ok(!('device_code' in start), 'device_code must stay in-process'); assert.ok(start.verification_url.includes('ABCD-EFGH'));
      const done = await call('demipass_login_wait', { timeout_seconds: 10 });
      assert.strictEqual(done.status, 'approved'); assert.strictEqual(done.credentials_path, mcpCred);
      assert.ok(!JSON.stringify(done).includes('dpr_') && !JSON.stringify(done).includes('.sig'), 'no token values in output');
      assert.strictEqual(fs.statSync(mcpCred).mode & 0o777, 0o600);
      const rec = JSON.parse(fs.readFileSync(mcpCred, 'utf8'));
      await call('demipass_list');
      assert.strictEqual(state.lastAuth, 'Bearer ' + rec.token, 'MCP must use the freshly approved bearer without a restart');
      const st = await call('demipass_login_status'); assert.strictEqual(st.active_source, 'credentials_file'); assert.strictEqual(st.active.did, 'did:key:zTEST'); assert.strictEqual(st.bearer_source_at_startup, 'none');
      await assert.rejects(call('demipass_login_wait', {}), /no login in flight/);
      const out = await call('demipass_logout'); assert.strictEqual(out.credentials.removed, true); assert.strictEqual(fs.existsSync(mcpCred), false);
    } finally { child.kill(); }
  });

  server.close();
  fs.rmSync(tmpdir, { recursive: true, force: true });
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
