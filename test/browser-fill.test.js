#!/usr/bin/env node
/**
 * Agent browser fill (flight 3) — end-to-end against a mock DemiPass fill server and a local login site.
 *
 *   node test/browser-fill.test.js
 *
 * Real browsers, when present (each suite is reported as RUN or SKIPPED, never silently passed):
 *   Chromium     CHROMIUM_BIN, else Playwright's cache (~/.cache/ms-playwright/chromium_headless_shell-*, chromium-*)
 *   Lightpanda   LIGHTPANDA_BIN, else /home/flimflam/tmp/lightpanda-1.0.1/lightpanda-x86_64-linux
 *
 * The mock implements docs/browser-fill-api.md (dustforge feat/browser-fill). Nothing here talks to production:
 * DEMIPASS_URL points at the mock and DEMIPASS_CREDENTIALS at a file that does not exist.
 *
 * The leak assertion: every MCP tool result, every stderr line of the MCP processes, and every log line this test
 * writes are collected; none may contain the secret value or its URL / form / HTML encodings.
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { spawn } = require('child_process');
const { PassThrough } = require('stream');

const ROOT = path.join(__dirname, '..');
const { connect, fillOnSession, fillViaCdp, chooseCdpEndpoint } = require(path.join(ROOT, 'browser-fill/cdp-fill.js'));
const { Redactor, REDACTED, obtainFill, FillError, resolveFillToken } = require(path.join(ROOT, 'browser-fill/fill-core.js'));
const { createProxy, lineSplitter } = require(path.join(ROOT, 'browser-fill/lightpanda-mcp.js'));
const FAKE_LP = path.join(__dirname, 'fake-lightpanda-mcp.js');

// A value with characters that every encoding treats differently.
const SECRET = 'Tr0ub4dor&3 "zq9" <xk>+%v';
// Characters Lightpanda's markdown escapes, the URL serializer re-encodes ('), and HTML text leaves raw (" ').
const SECRET2 = "Ab~c*d!e'f(g)h-é q/?#&=+;x\"y<z>%41_[|]";
const ADMIN_KEY = 'test-admin-key-must-not-ride-on-fills';
const USERNAME = 'agent@example.test';
const SILICON = 'silicon:test-agent-token';
const CORPUS = [];          // everything an agent or a log could see
const results = { pass: 0, fail: 0, suites: [] };

function log(...a) { const line = a.join(' '); CORPUS.push(line); console.log(line); }
async function test(name, fn) {
  try { await fn(); results.pass++; log(`  ok    ${name}`); }
  catch (e) { results.fail++; log(`  FAIL  ${name}\n        ${String(e && e.message || e).split(SECRET).join('<<SECRET>>').split(SECRET2).join('<<SECRET2>>')}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The leak detector's own list of encodings (independent of the Redactor under test): what pages and Lightpanda echo.
function encodingsOf(v) {
  const amp = v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return [...new Set([v, encodeURIComponent(v), encodeURIComponent(v).replace(/'/g, '%27'), new URLSearchParams({ v }).toString().slice(2),
    JSON.stringify(v).slice(1, -1), amp, amp.replace(/"/g, '&quot;'), v.replace(/[\\`*_{}[\]()#+\-!|]/g, (c) => '\\' + c), v.replace(/ /g, '+')])];
}

// ── mock DemiPass ─────────────────────────────────────────────────────────────────────────────────────────────

function startMockDemipass() {
  const secrets = new Map();   // ref → { value, username, origins, grant, redeem: 'ok'|'pending'|'pending2'|'denied'|'expired'|'redeemed'|'wrong_origin' }
  const requests = new Map();
  const calls = [];
  let seq = 0;
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch (_) {}
      const send = (status, obj) => { calls.push({ path: u.pathname, status, adminKey: req.headers['x-admin-key'] !== undefined }); res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
      if (req.headers.authorization !== `Bearer ${SILICON}`) return send(401, { error: 'invalid silicon token' });
      if (req.method === 'GET' && u.pathname === '/api/blindkey/fill/candidates') {
        const origin = u.searchParams.get('origin');
        const c = [...secrets.entries()].filter(([, s]) => s.origins.includes(origin) && s.grant)
          .map(([ref, s]) => ({ ref, name: ref.toLowerCase(), username: s.username, secret_type: 'password' }));
        return send(200, { ok: true, origin, candidates: c });
      }
      if (req.method === 'POST' && u.pathname === '/api/blindkey/fill/request') {
        const s = secrets.get(body.ref);
        if (!s) return send(404, { error: 'secret not found or not owned by you' });
        if (!s.origins.includes(body.origin)) return send(403, { error: `this login is not bound to ${body.origin}`, bound_origins: s.origins });
        if (!s.grant) return send(403, { error: "silicon 'test-agent' holds no action:browser_fill grant for this secret" });
        const id = `dpf_${++seq}`;
        requests.set(id, { ref: body.ref, origin: body.origin, polls: 0, spent: false });
        return send(201, { ok: true, request_id: id, status: 'approved', expires_in: 120 });
      }
      if (req.method === 'POST' && u.pathname === '/api/blindkey/fill/redeem') {
        const r = requests.get(body.request_id);
        if (!r) return send(404, { error: 'fill request not found' });
        const s = secrets.get(r.ref);
        r.polls++;
        if (r.spent) return send(410, { error: 'already_redeemed' });
        if (s.redeem === 'pending') return send(428, { error: 'approval_pending' });
        if (s.redeem === 'pending2' && r.polls <= 2) return send(428, { error: 'approval_pending' });
        if (s.redeem === 'denied') return send(403, { error: 'denied' });
        if (s.redeem === 'expired') return send(410, { error: 'expired' });
        if (s.redeem === 'redeemed') return send(410, { error: 'already_redeemed' });
        r.spent = true;
        const origin = s.redeem === 'wrong_origin' ? 'https://evil.example' : r.origin;
        return send(200, { ok: true, value: s.value, username: s.username, origin, name: r.ref.toLowerCase(), ref: r.ref });
      }
      send(404, { error: 'no route' });
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, secrets, calls, url: `http://127.0.0.1:${server.address().port}` })));
}

// ── local login site ──────────────────────────────────────────────────────────────────────────────────────────

const PAGES = {
  '/login': `<!doctype html><html><head><title>Login</title></head><body>
    <form id="f" action="/done" method="post">
      <label>Email <input id="u" name="username" type="email" autocomplete="username"></label>
      <label>Password <input id="p" name="password" type="password" autocomplete="current-password"></label>
      <button type="submit">Sign in</button>
    </form></body></html>`,
  // Framework-style: values live in JS state updated only by input events; submit sends the state, not the DOM.
  '/login-react': `<!doctype html><html><head><title>App login</title></head><body>
    <form id="f"><input name="email" type="text"><input name="pw" type="password"><button>Log in</button></form>
    <script>
      var state = { u: '', p: '' };
      document.querySelector('[name=email]').addEventListener('input', function (e) { state.u = e.target.value; });
      document.querySelector('[name=pw]').addEventListener('input', function (e) { state.p = e.target.value; });
      document.getElementById('f').addEventListener('submit', function (e) {
        e.preventDefault();
        fetch('/done-json', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(state) })
          .then(function () { document.title = 'sent'; });
      });
    </script></body></html>`,
  '/login-get': `<!doctype html><html><head><title>GET login</title></head><body>
    <form action="/welcome" method="get"><input name="user" type="text"><input name="pass" type="password"><button type="submit">Go</button></form></body></html>`,
  '/login-two': `<!doctype html><html><head><title>Change password</title></head><body>
    <form><input name="user"><input name="new" type="password"><input name="confirm" type="password"></form></body></html>`,
  // A page script that keeps only 5 characters of whatever is typed (the effect a maxlength-style guard has).
  '/login-trunc': `<!doctype html><html><head><title>Short</title></head><body>
    <form action="/done" method="post"><input name="username" type="email"><input id="p" name="password" type="password"><button>Go</button></form>
    <script>document.querySelector('#p').addEventListener('input', function (e) { if (e.target.value.length > 5) e.target.value = e.target.value.slice(0, 5); });</script></body></html>`,
  '/nofields': '<!doctype html><html><head><title>Nothing</title></head><body><p>No form here.</p></body></html>',
  '/welcome': '<!doctype html><html><head><title>Welcome</title></head><body><p>Welcome.</p></body></html>',
};

function startSite() {
  const captured = [];
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      if (req.method === 'POST' && u.pathname === '/done') {
        const f = new URLSearchParams(raw);
        captured.push({ via: 'form', username: f.get('username'), password: f.get('password') });
        res.writeHead(200, { 'content-type': 'text/html' }); return res.end(PAGES['/welcome']);
      }
      if (req.method === 'POST' && u.pathname === '/done-json') {
        let j = {}; try { j = JSON.parse(raw); } catch (_) {}
        captured.push({ via: 'json', username: j.u, password: j.p });
        res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"ok":true}');
      }
      if (u.pathname === '/reflect') {
        // Echo the GET-form password back the ways pages do: text, title, link href, input value, console.
        const pv = u.searchParams.get('pass') || '';
        const esc = pv.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(`<!doctype html><html><head><title>Hi ${esc}</title></head><body><p>You sent ${esc}</p><a href="/x?p=${encodeURIComponent(pv)}">again</a><form><input type=text name=echo value="${esc}"></form><script>console.log('p=' + new URLSearchParams(location.search).get('pass'))</script></body></html>`);
      }
      if (u.pathname === '/login-reflect') {
        res.writeHead(200, { 'content-type': 'text/html' });
        return res.end('<!doctype html><html><head><title>L</title></head><body><form action="/reflect" method="get"><input name="user" type="text"><input name="pass" type="password"><button type="submit">Go</button></form></body></html>');
      }
      if (u.pathname === '/welcome' && u.search) captured.push({ via: 'get', username: u.searchParams.get('user'), password: u.searchParams.get('pass') });
      const page = PAGES[u.pathname];
      if (!page) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'content-type': 'text/html' }); res.end(page);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    resolve({ server, captured, port, origin: `http://127.0.0.1:${port}`, altOrigin: `http://localhost:${port}` });
  }));
}

// ── an MCP stdio client ───────────────────────────────────────────────────────────────────────────────────────

function startMcp(cmd, args, env, label) {
  const p = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'], env, cwd: os.tmpdir() });
  let buf = '';
  const pending = new Map();
  let id = 0;
  const stderr = [];
  p.stderr.setEncoding('utf8');
  p.stderr.on('data', (d) => { stderr.push(d); CORPUS.push(`[${label} stderr] ${d}`); });
  p.stdout.setEncoding('utf8');
  p.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      CORPUS.push(`[${label} stdout] ${line}`);   // every byte the agent receives
      let m; try { m = JSON.parse(line); } catch (_) { continue; }
      if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    }
  });
  const rpc = (method, params, timeoutMs = 45000) => new Promise((resolve, reject) => {
    const i = ++id;
    const t = setTimeout(() => { pending.delete(i); reject(new Error(`${label} ${method} timed out`)); }, timeoutMs);
    pending.set(i, (m) => { clearTimeout(t); resolve(m); });
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n');
  });
  const call = async (name, args, timeoutMs) => {
    const m = await rpc('tools/call', { name, arguments: args || {} }, timeoutMs);
    if (m.error) return { isError: true, text: m.error.message || '', json: null, raw: m };
    const text = (m.result.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
    let json = null;
    const jtext = text.startsWith('Error: ') ? text.slice(7) : text;
    try { json = JSON.parse(jtext); } catch (_) {}
    return { isError: Boolean(m.result.isError), text, json, raw: m };
  };
  const init = async () => {
    await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'browser-fill-test', version: '0' } });
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  };
  // Send a message with the caller's own id (any JSON-RPC id), resolve its reply.
  const sendRaw = (obj, timeoutMs = 45000) => new Promise((resolve, reject) => {
    const t = setTimeout(() => { pending.delete(obj.id); reject(new Error(`${label} raw ${obj.method} timed out`)); }, timeoutMs);
    pending.set(obj.id, (m) => { clearTimeout(t); resolve(m); });
    p.stdin.write(JSON.stringify(obj) + '\n');
  });
  return { p, rpc, call, init, sendRaw, stderr, close: () => { try { p.stdin.end(); } catch (_) {} setTimeout(() => { try { p.kill('SIGKILL'); } catch (_) {} }, 1500); } };
}

function baseEnv(mock) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith('DEMIPASS_') || k.startsWith('LP_')) delete env[k];
  return { ...env, DEMIPASS_URL: mock.url, DEMIPASS_FILL_TOKEN: SILICON, DEMIPASS_ADMIN_KEY: ADMIN_KEY,
           DEMIPASS_CREDENTIALS: path.join(os.tmpdir(), `no-such-demipass-creds-${process.pid}.json`) };
}

// ── browsers ──────────────────────────────────────────────────────────────────────────────────────────────────

function findChromium() {
  if (process.env.CHROMIUM_BIN) return process.env.CHROMIUM_BIN;
  const cache = path.join(os.homedir(), '.cache/ms-playwright');
  let dirs = [];
  try { dirs = fs.readdirSync(cache); } catch (_) { return null; }
  const cands = [];
  for (const d of dirs.sort().reverse()) {
    if (d.startsWith('chromium_headless_shell-')) cands.push(path.join(cache, d, 'chrome-headless-shell-linux64/chrome-headless-shell'));
    if (d.startsWith('chromium-')) cands.push(path.join(cache, d, 'chrome-linux64/chrome'));
  }
  return cands.find((c) => fs.existsSync(c)) || null;
}

async function launchChromium(bin) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpfill-chrome-'));
  const p = spawn(bin, ['--headless', '--remote-debugging-port=0', `--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check', '--disable-gpu', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const ws = await new Promise((resolve, reject) => {
    let e = '';
    const t = setTimeout(() => reject(new Error('chromium did not start')), 20000);
    p.stderr.on('data', (d) => { e += d; const m = e.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); resolve(m[1]); } });
    p.on('exit', (c) => reject(new Error(`chromium exited ${c}: ${e.slice(0, 300)}`)));
  });
  const port = new URL(ws).port;
  return { p, cdpUrl: `http://127.0.0.1:${port}`, close: () => { p.kill('SIGKILL'); setTimeout(() => fs.rmSync(dir, { recursive: true, force: true }), 500); } };
}

// The "agent's driver": a separate CDP client that navigates, the way Playwright would.
async function driver(cdpUrl) {
  const conn = await connect(cdpUrl);
  const { targetInfos } = await conn.send('Target.getTargets');
  const page = targetInfos.find((t) => t.type === 'page');
  const { sessionId } = await conn.send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
  await conn.send('Page.enable', {}, sessionId);
  const evalJs = async (expr) => (await conn.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId)).result.value;
  const goto = async (url) => {
    await conn.send('Page.navigate', { url }, sessionId);
    for (let i = 0; i < 100; i++) { await sleep(50); try { if (await evalJs(`location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`)) return; } catch (_) {} }
    throw new Error(`navigation to ${url} did not finish`);
  };
  return { targetId: page.targetId, goto, evalJs, close: () => conn.close() };
}

async function waitFor(fn, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = await fn(); if (v) return v; await sleep(100); }
  return null;
}

// ── suites ────────────────────────────────────────────────────────────────────────────────────────────────────

function seedSecrets(mock, site) {
  mock.secrets.clear();
  const s = (redeem, extra = {}) => ({ value: SECRET, username: USERNAME, origins: [site.origin], grant: true, redeem, ...extra });
  mock.secrets.set('DP-PWD-good', s('ok'));
  mock.secrets.set('DP-PWD-nogrant', s('ok', { grant: false }));
  mock.secrets.set('DP-PWD-pending', s('pending'));
  mock.secrets.set('DP-PWD-pending2', s('pending2'));
  mock.secrets.set('DP-PWD-denied', s('denied'));
  mock.secrets.set('DP-PWD-expired', s('expired'));
  mock.secrets.set('DP-PWD-redeemed', s('redeemed'));
  mock.secrets.set('DP-PWD-wrongorigin', s('wrong_origin'));
  mock.secrets.set('DP-PWD-punct', s('ok', { value: SECRET2 }));
}
const requestsMade = (mock) => mock.calls.filter((c) => c.path === '/api/blindkey/fill/request').length;

async function unitSuite(mock, site) {
  log('\nfill core (no browser)');
  seedSecrets(mock, site);
  const demipass = require(path.join(ROOT, 'index.js'));
  demipass.configure({ baseUrl: mock.url, adminKey: ADMIN_KEY }); // set on purpose: fill calls must not send it
  const api = demipass;

  await test('redactor scrubs raw, URL, form and HTML encodings', () => {
    const r = new Redactor(); r.add(SECRET);
    const s = r.scrub(`a ${SECRET} b ${encodeURIComponent(SECRET)} c ${new URLSearchParams({ x: SECRET }).toString()} d ${SECRET.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')}`);
    assert(!s.includes(SECRET) && !s.includes(encodeURIComponent(SECRET)), s);
    assert(!s.includes(new URLSearchParams({ x: SECRET }).toString().slice(2)));
    assert.strictEqual(s.split(REDACTED).length - 1, 4);
  });
  await test('redactor scrubs the encodings Lightpanda 1.0.1 really emits (markdown, href, html text, decoded query)', () => {
    // Literal strings captured from Lightpanda 1.0.1 output for this value (reviewer probe p1-encodings.js).
    const v = "Ab~c*d!e'f(g)h-é€ q/?#&=+;x\"y<z>%41";
    const seen = {
      markdown: String.raw`You sent Ab~c\*d\!e'f\(g\)h\-é€ q/?\#&=\+;x"y<z>%41 [again]`,
      href: 'http://127.0.0.1:1/x?p=Ab~c*d!e%27f(g)h-%C3%A9%E2%82%AC%20q%2F%3F%23%26%3D%2B%3Bx%22y%3Cz%3E%2541',
      htmlText: `<p>You sent Ab~c*d!e'f(g)h-é€ q/?#&amp;=+;x"y&lt;z&gt;%41</p>`,
      decodedSearch: `?user=agent@x.test&pass=Ab~c*d!e'f(g)h-é€+q/?#&=+;x"y<z>%41`,
      lowerHex: 'p=Ab~c*d!e%27f(g)h-%c3%a9%e2%82%ac%20q%2f%3f%23%26%3d%2b%3bx%22y%3cz%3e%2541',
    };
    const r = new Redactor(); r.add(v);
    for (const [k, line] of Object.entries(seen)) {
      const out = r.scrub(line);
      assert(out.includes(REDACTED), `${k} not redacted`);
      assert(!out.includes('Ab~c') && !out.includes('%2541') && !out.includes('%41'), `${k} left a piece: ${out.split(v).join('<<V>>')}`);
    }
    // And for the value the browser suites use (markdown escapes its '+', html text keeps its quotes raw).
    const r2 = new Redactor(); r2.add(SECRET);
    for (const line of [SECRET.replace(/[\\`*_{}[\]()#+\-!|]/g, (c) => '\\' + c), SECRET.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'), SECRET.replace(/ /g, '+')]) {
      assert.strictEqual(r2.scrub(line), REDACTED);
    }
  });
  await test('redactor evicts the oldest fill as a group (raw value never dropped before its encodings)', () => {
    const r = new Redactor({ max: 2 });
    const vals = ['first&value one', 'second&value two', 'third&value three'];
    for (const v of vals) r.add(v);
    assert.strictEqual(r.fills, 2);
    const forms = (v) => [v, encodeURIComponent(v), v.replace(/&/g, '&amp;'), new URLSearchParams({ x: v }).toString().slice(2)];
    for (const f of forms(vals[0])) assert.strictEqual(r.scrub(f), f, 'the evicted fill is gone entirely');
    for (const v of vals.slice(1)) for (const f of forms(v)) assert.strictEqual(r.scrub(f), REDACTED, `kept fill lost an encoding: ${f}`);
    // Re-adding a remembered value refreshes it instead of duplicating it.
    r.add(vals[1]); r.add('fourth&value four');
    for (const f of forms(vals[1])) assert.strictEqual(r.scrub(f), REDACTED);
    assert.strictEqual(r.scrub(vals[2]), vals[2]);
  });
  await test('line framing is linear: one 32 MiB line in 64 KiB chunks', () => {
    const lines = [];
    const feed = lineSplitter((l) => lines.push(l.length));
    const big = 'A'.repeat(32 * 1024 * 1024);
    const t0 = Date.now();
    for (let i = 0; i < big.length; i += 65536) feed(big.slice(i, i + 65536));
    feed('\nshort\n');
    const ms = Date.now() - t0;
    assert.deepStrictEqual(lines, [big.length, 5]);
    assert(ms < 2000, `framing took ${ms} ms (the quadratic version took ~5.4 s)`);
  });
  await test('obtainFill: 403 origin not bound carries bound_origins, no value', async () => {
    const e = await obtainFill(api, { ref: 'DP-PWD-good', origin: site.altOrigin, token: SILICON }).catch((x) => x);
    assert(e instanceof FillError && e.code === 'origin_not_bound', e.code);
    assert.deepStrictEqual(e.extra.bound_origins, [site.origin]);
  });
  await test('obtainFill: 403 without a grant → not_granted', async () => {
    const e = await obtainFill(api, { ref: 'DP-PWD-nogrant', origin: site.origin, token: SILICON }).catch((x) => x);
    assert.strictEqual(e.code, 'not_granted');
  });
  await test('obtainFill: 428 → approval_pending with request_id; resume after approval', async () => {
    const e = await obtainFill(api, { ref: 'DP-PWD-pending2', origin: site.origin, token: SILICON }).catch((x) => x);
    assert.strictEqual(e.code, 'approval_pending'); assert(/^dpf_/.test(e.extra.request_id));
    const got = await obtainFill(api, { requestId: e.extra.request_id, ref: 'DP-PWD-pending2', origin: site.origin, token: SILICON, waitSeconds: 10, sleep: () => sleep(10) });
    assert.strictEqual(got.origin, site.origin); assert.strictEqual(got.value.length, SECRET.length);
  });
  await test('obtainFill: 403 denied, 410 expired, 410 already_redeemed', async () => {
    for (const [ref, code] of [['DP-PWD-denied', 'denied'], ['DP-PWD-expired', 'expired'], ['DP-PWD-redeemed', 'already_redeemed']]) {
      const e = await obtainFill(api, { ref, origin: site.origin, token: SILICON }).catch((x) => x);
      assert.strictEqual(e.code, code, ref);
    }
  });
  await test('obtainFill: server approving another origin is refused', async () => {
    const e = await obtainFill(api, { ref: 'DP-PWD-wrongorigin', origin: site.origin, token: SILICON }).catch((x) => x);
    assert.strictEqual(e.code, 'origin_mismatch');
    assert(!JSON.stringify(e.toJSON()).includes(SECRET));
  });
  await test('fill identity: set but unusable (missing/empty file, blank env) refuses — never undefined/fallback', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpfill-tok-'));
    const f = path.join(dir, 'token');
    fs.writeFileSync(f, 'silicon:from-file\n', { mode: 0o600 });
    assert.strictEqual(resolveFillToken({ DEMIPASS_FILL_TOKEN_FILE: f }), 'silicon:from-file');
    assert.strictEqual(resolveFillToken({ DEMIPASS_FILL_TOKEN: 'silicon:env', DEMIPASS_FILL_TOKEN_FILE: f }), 'silicon:env');
    assert.strictEqual(resolveFillToken({}), undefined, 'neither set → the SDK bearer');
    const refuses = (env) => { try { resolveFillToken(env); return 'returned'; } catch (e) { return e.code; } };
    assert.strictEqual(refuses({ DEMIPASS_FILL_TOKEN_FILE: f + '.missing' }), 'no_fill_identity');
    assert.strictEqual(refuses({ DEMIPASS_FILL_TOKEN_FILE: dir }), 'no_fill_identity', 'unreadable (a directory)');
    fs.writeFileSync(f + '.empty', '\n  \n');
    assert.strictEqual(refuses({ DEMIPASS_FILL_TOKEN_FILE: f + '.empty' }), 'no_fill_identity');
    assert.strictEqual(refuses({ DEMIPASS_FILL_TOKEN: '   ' }), 'no_fill_identity');
    assert.strictEqual(refuses({ DEMIPASS_FILL_TOKEN: '', DEMIPASS_FILL_TOKEN_FILE: f }), 'no_fill_identity', 'a blank env token does not fall to the file either');
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await test('obtainFill: plain-http non-local origin refused before any request', async () => {
    const before = requestsMade(mock);
    const e = await obtainFill(api, { ref: 'DP-PWD-good', origin: 'http://example.com', token: SILICON }).catch((x) => x);
    assert.strictEqual(e.code, 'origin_not_fillable'); assert.strictEqual(requestsMade(mock), before);
  });
}

// ── the CDP endpoint is not the agent's to choose (no browser needed) ──────────────────────────────────────────

async function cdpPolicySuite(mock, site) {
  log('\nCDP endpoint policy (fake DevTools endpoints)');
  seedSecrets(mock, site);
  const demipass = require(path.join(ROOT, 'index.js'));
  let hits = 0;
  let mode = 'evilws';
  const fake = http.createServer((req, res) => {
    hits++;
    if (mode === 'redirect' && req.url === '/json/version') { res.writeHead(302, { location: '/json/version-moved' }); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ Browser: 'Chrome/1', webSocketDebuggerUrl: 'ws://evil.example:9222/devtools/browser/x' }));
  });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
  const fakeUrl = `http://127.0.0.1:${fake.address().port}`;
  const fill = (o) => fillViaCdp({ ref: 'DP-PWD-good', api: demipass, token: SILICON, ...o });
  try {
    await test('cdp_url on a non-loopback host is refused before any connection or request', async () => {
      const before = requestsMade(mock);
      for (const u of ['http://192.0.2.1:9222', 'ws://evil.example/devtools/browser/x', 'http://127.0.0.1.nip.io:9222', 'https://bank.example', 'http://[::2]:9222']) {
        const r = await fill({ cdpUrl: u });
        assert.strictEqual(r.error, 'cdp_not_loopback', `${u} → ${r.error}`);
      }
      assert.strictEqual(requestsMade(mock), before);
      for (const u of ['http://127.0.0.1:9222', 'http://localhost:9222', 'http://[::1]:9222', 'ws://127.0.0.5:1/x']) assert.strictEqual(chooseCdpEndpoint(u).url, u);
    });
    await test('a loopback endpoint advertising a WebSocket on another host is refused', async () => {
      mode = 'evilws'; hits = 0;
      const before = requestsMade(mock);
      const r = await fill({ cdpUrl: fakeUrl });
      assert.strictEqual(r.error, 'cdp_not_loopback'); assert.strictEqual(hits, 1); assert.strictEqual(requestsMade(mock), before);
    });
    await test('a redirecting /json/version is not followed', async () => {
      mode = 'redirect'; hits = 0;
      const r = await fill({ cdpUrl: fakeUrl });
      assert.strictEqual(r.error, 'cdp_unreachable');
      assert.strictEqual(hits, 1, 'the redirect was followed');
    });
    await test('operator DEMIPASS_CDP_URL set: an agent cdp_url that differs is refused', async () => {
      const r = await fill({ cdpUrl: 'http://127.0.0.1:9', configuredCdpUrl: fakeUrl });
      assert.strictEqual(r.error, 'cdp_url_not_allowed');
      assert.strictEqual(chooseCdpEndpoint(undefined, 'https://browser.internal:9222').url, 'https://browser.internal:9222');
    });
  } finally { fake.close(); }
}

// ── wrapper protocol, against a scripted Lightpanda (test/fake-lightpanda-mcp.js) ────────────────────────────

function fakeLightpandaShim() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpfill-fakelp-'));
  const f = path.join(dir, 'lightpanda');
  fs.writeFileSync(f, `#!/bin/sh\nexec "${process.execPath}" "${FAKE_LP}" "$@"\n`, { mode: 0o755 });
  return f;
}
function cleanEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith('DEMIPASS_') || k.startsWith('LP_') || k.startsWith('FAKE_')) delete env[k];
  return { ...env, ...extra };
}
function fakeApi(value) {
  const calls = []; let n = 0;
  return {
    calls,
    async fillCandidates() { calls.push('candidates'); return { status: 200, data: { candidates: [] } }; },
    async fillRequest() { calls.push('request'); return { status: 201, data: { request_id: `r${++n}` } }; },
    async fillRedeem() { calls.push('redeem'); return { status: 200, data: { value, username: USERNAME, origin: 'http://127.0.0.1:9', ref: 'DP-PWD-fake' } }; },
  };
}
// createProxy in this process, on PassThrough streams; every line the "agent" receives goes into CORPUS.
function inProcessProxy({ lightpanda, env, api, label, ...rest }) {
  const io = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() };
  const pending = new Map();
  const lines = [];
  const errs = [];
  io.stdout.setEncoding('utf8');
  io.stdout.on('data', lineSplitter((line) => {
    lines.push(line);
    CORPUS.push(`[${label} stdout] ${line.length > 1e6 ? line.slice(0, 1e6) : line}`);
    let m; try { m = JSON.parse(line); } catch (_) { return; }
    if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  }));
  io.stderr.setEncoding('utf8');
  io.stderr.on('data', (d) => { errs.push(d); CORPUS.push(`[${label} stderr] ${d}`); });
  const { child } = createProxy({ lightpanda, env, api, io, clientLabel: 'test', ...rest });
  const send = (obj, timeoutMs = 20000) => new Promise((resolve, reject) => {
    const t = setTimeout(() => { pending.delete(obj.id); reject(new Error(`${label} ${obj.method} id=${JSON.stringify(obj.id)} timed out`)); }, timeoutMs);
    pending.set(obj.id, (m) => { clearTimeout(t); resolve(m); });
    io.stdin.write(JSON.stringify(obj) + '\n');
  });
  const call = (id, name, args, timeoutMs) => send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args || {} } }, timeoutMs);
  const textOf = (m) => (m.result && m.result.content || []).map((c) => c.text).join('');
  return { io, child, send, call, textOf, lines, errs, close: () => { io.stdin.end(); setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} }, 500); } };
}

async function wrapperProtocolSuite() {
  log('\nLightpanda wrapper protocol (scripted Lightpanda)');
  const lp = fakeLightpandaShim();
  const mk = (extraEnv, opts = {}) => {
    const api = fakeApi(SECRET2);
    const px = inProcessProxy({ lightpanda: lp, env: cleanEnv(extraEnv), api, label: 'fake-lp-wrapper', token: SILICON, ...opts });
    return { px, api };
  };

  await test('tools/list: fill tools on the first page only; nameless tool tolerated; a child demipass_* tool dropped', async () => {
    const { px } = mk();
    try {
      await px.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
      const p1 = await px.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
      const n1 = p1.result.tools.map((t) => t.name);
      assert.strictEqual(n1.filter((n) => n === 'demipass_browser_fill').length, 1);
      assert(!p1.result.tools.some((t) => t.description === 'shadow'), 'the child shadowed our tool');
      assert(n1.includes('demipass_browser_fill_candidates') && n1.includes(undefined), 'nameless tool must pass through');
      assert.strictEqual(p1.result.nextCursor, 'p2');
      const p2 = await px.send({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: { cursor: 'p2' } });
      assert.deepStrictEqual(p2.result.tools.map((t) => t.name), ['evaluate', 'fill', 'big']);
    } finally { px.close(); }
  });

  await test('agent JSON-RPC ids are rewritten: ids colliding with internal ones get their own replies', async () => {
    const { px, api } = mk();
    try {
      // One write: five agent requests, then a fill. A fresh proxy mints child ids 1..5 for those and 6, 7, 8, 9 for
      // the fill's getUrl / evaluate / getUrl / fill — so these agent ids are exactly the internal ones, were agent
      // ids passed through. Their replies claim another origin, as a hostile page's script would.
      const ids = [6, 7, 8, 9, 'demipass-internal-1'];
      const replies = ids.map((id) => new Promise((resolve) => { px.send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo', arguments: { text: `https://victim.example/for-${id}` } } }).then(resolve); }));
      const f = px.call('fill-1', 'demipass_browser_fill', { ref: 'DP-PWD-fake' });
      const got = await Promise.all(replies);
      got.forEach((m, i) => assert.strictEqual(px.textOf(m), `https://victim.example/for-${ids[i]}`, `reply for ${ids[i]}`));
      const fr = JSON.parse(px.textOf(await f));
      assert.strictEqual(fr.filled, true, JSON.stringify(fr)); assert.strictEqual(fr.origin, 'http://127.0.0.1:9');
      assert.deepStrictEqual(api.calls, ['request', 'redeem']);
      assert(!px.lines.some((l) => l.includes('Filled element')), 'an internal fill reply reached the agent');
    } finally { px.close(); }
  });

  await test('internal call timeout: agent requests stay held until Lightpanda answers; the late reply is swallowed', async () => {
    const { px } = mk({ FAKE_FILL_DELAY_MS: '1500' }, { internalTimeoutMs: 300 });
    try {
      const t0 = Date.now();
      const fr = await px.call('f', 'demipass_browser_fill', { ref: 'DP-PWD-fake' });
      const tErr = Date.now();
      assert.strictEqual(JSON.parse(px.textOf(fr)).error, 'browser_timeout');
      const e = await px.call('after', 'echo', { text: 'next' });
      const tEcho = Date.now();
      assert.strictEqual(px.textOf(e), 'next');
      assert(tEcho - t0 >= 1400, `agent request ran ${tEcho - t0} ms after the fill began — before Lightpanda finished`);
      assert(tEcho - tErr >= 900, 'agent request was not held after the timeout');
      await sleep(200);
      const seenIds = px.lines.map((l) => { try { return JSON.parse(l).id; } catch (_) { return '?'; } });
      assert.deepStrictEqual(seenIds, ['f', 'after'], 'the agent got a reply it did not ask for (the late internal one)');
      assert(!px.lines.some((l) => l.includes('Filled element')), 'late internal fill reply reached the agent');
    } finally { px.close(); }
  });

  await test('the field keeps fewer characters than the value → value_not_accepted and the field is cleared', async () => {
    const { px } = mk({ FAKE_MAXLEN: '5' });
    try {
      const fr = JSON.parse(px.textOf(await px.call('f', 'demipass_browser_fill', { ref: 'DP-PWD-fake' })));
      assert.strictEqual(fr.filled, false); assert.strictEqual(fr.error, 'value_not_accepted');
      await sleep(100);
      const log2 = px.errs.join('');
      assert(/fake fill p len=5\n[^]*fake fill p len=0\n/.test(log2), `field not cleared: ${log2}`);
    } finally { px.close(); }
  });

  await test('a 32 MiB child reply passes through intact after a fill (scrubbed, framed linearly)', async () => {
    const { px } = mk();
    try {
      await px.call('f', 'demipass_browser_fill', { ref: 'DP-PWD-fake' });
      const t0 = Date.now();
      const m = await px.call('big', 'big', { bytes: 32 * 1024 * 1024 }, 30000);
      const ms = Date.now() - t0;
      assert.strictEqual(px.textOf(m).length, 32 * 1024 * 1024);
      assert(ms < 10000, `32 MiB took ${ms} ms`);
      log(`        (32 MiB round trip ${ms} ms)`);
    } finally { px.close(); }
  });

  await test('no fill identity: fill tools refuse with no_fill_identity, nothing requested, Lightpanda tools still work', async () => {
    const api = fakeApi(SECRET2);
    const px = inProcessProxy({ lightpanda: lp, env: cleanEnv(), api, label: 'fake-lp-wrapper',
      getToken: () => resolveFillToken({ DEMIPASS_FILL_TOKEN_FILE: '/etc/agent-fill/does-not-exist.token' }) });
    try {
      const fr = JSON.parse(px.textOf(await px.call('f', 'demipass_browser_fill', { ref: 'DP-PWD-fake' })));
      assert.strictEqual(fr.error, 'no_fill_identity'); assert(/no fill identity provisioned/.test(fr.message));
      const cr = JSON.parse(px.textOf(await px.call('c', 'demipass_browser_fill_candidates', { origin: 'https://example.com' })));
      assert.strictEqual(cr.error, 'no_fill_identity');
      assert.deepStrictEqual(api.calls, []);
      assert.strictEqual(px.textOf(await px.call('e', 'echo', { text: 'alive' })), 'alive');
    } finally { px.close(); }
  });
}

// ── process-level: the shipped entry points ───────────────────────────────────────────────────────────────────

async function processSuite(mock, site) {
  log('\nentry points (mcp-server, demipass-lightpanda-mcp)');
  seedSecrets(mock, site);
  await test('mcp-server: fill token file missing → no_fill_identity, never the DEMIPASS_TOKEN bearer', async () => {
    const env = baseEnv(mock);
    delete env.DEMIPASS_FILL_TOKEN;
    env.DEMIPASS_FILL_TOKEN_FILE = path.join(os.tmpdir(), `no-such-fill-token-${process.pid}`);
    env.DEMIPASS_TOKEN = SILICON; // would be accepted by the mock: a fallback would succeed
    const before = mock.calls.length;
    const mcp = startMcp(process.execPath, [path.join(ROOT, 'mcp-server.js')], env, 'demipass-mcp-noid');
    try {
      await mcp.init();
      const c = await mcp.call('demipass_browser_fill_candidates', { origin: site.origin });
      assert(c.isError); assert.strictEqual(c.json.error, 'no_fill_identity', c.text);
      const f = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: 'http://127.0.0.1:9' });
      assert(f.isError); assert.strictEqual(f.json.error, 'no_fill_identity', f.text);
      assert.strictEqual(mock.calls.slice(before).filter((x) => x.path.startsWith('/api/blindkey/fill')).length, 0);
    } finally { mcp.close(); }
  });
  await test('demipass-lightpanda-mcp loads no dotenv (a planted ~/.node_modules/dotenv never runs)', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dpfill-home-'));
    const marker = path.join(home, 'PLANTED-CODE-RAN');
    fs.mkdirSync(path.join(home, '.node_modules', 'dotenv'), { recursive: true });
    fs.writeFileSync(path.join(home, '.node_modules', 'dotenv', 'index.js'), `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x'); module.exports = { config() {} };\n`);
    const env = cleanEnv({ HOME: home, DEMIPASS_URL: mock.url, DEMIPASS_CREDENTIALS: path.join(home, 'none.json') });
    // Control: the plant is reachable from the wrapper's directory, so an optional require('dotenv') would run it.
    await new Promise((r) => spawn(process.execPath, ['-e', "try { require('dotenv') } catch (_) {}"], { cwd: path.join(ROOT, 'browser-fill'), env, stdio: 'ignore' }).on('exit', r));
    assert(fs.existsSync(marker), 'control failed: planted dotenv not reachable');
    fs.rmSync(marker);
    const w = startMcp(process.execPath, [path.join(ROOT, 'browser-fill/lightpanda-mcp.js'), '--lightpanda', fakeLightpandaShim()], env, 'lp-wrapper-dotenv');
    try {
      await w.init();
      await sleep(200);
      assert(!fs.existsSync(marker), 'the wrapper ran planted dotenv code');
    } finally { w.close(); fs.rmSync(home, { recursive: true, force: true }); }
  });
}

async function chromiumSuite(mock, site, bin) {
  log(`\nChromium over CDP (${bin})`);
  const chrome = await launchChromium(bin);
  const drv = await driver(chrome.cdpUrl);
  const mcp = startMcp(process.execPath, [path.join(ROOT, 'mcp-server.js')], baseEnv(mock), 'demipass-mcp');
  try {
    await mcp.init();
    const tl = await mcp.rpc('tools/list', {});
    await test('mcp-server lists both browser-fill tools', () => {
      const names = tl.result.tools.map((t) => t.name);
      assert(names.includes('demipass_browser_fill') && names.includes('demipass_browser_fill_candidates'));
    });

    seedSecrets(mock, site);
    await drv.goto(`${site.origin}/login`);
    await test('candidates for the open page (no values)', async () => {
      const r = await mcp.call('demipass_browser_fill_candidates', { cdp_url: chrome.cdpUrl });
      assert(!r.isError, r.text);
      assert.strictEqual(r.json.origin, site.origin);
      assert(r.json.candidates.some((c) => c.ref === 'DP-PWD-good' && c.username === USERNAME));
      assert(!r.json.candidates.some((c) => c.ref === 'DP-PWD-nogrant'), 'ungranted secret must not be listed');
    });

    await test('fill + submit lands in the right fields (server receives exact values)', async () => {
      site.captured.length = 0;
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl, submit: true });
      assert(!r.isError, r.text);
      assert.strictEqual(r.json.filled, true); assert.strictEqual(r.json.chars, SECRET.length); assert.strictEqual(r.json.origin, site.origin);
      assert.strictEqual(r.json.username_filled, true); assert.strictEqual(r.json.submitted, true);
      const got = await waitFor(() => site.captured.find((c) => c.via === 'form'));
      assert(got, 'form never posted');
      assert.strictEqual(got.username, USERNAME); assert(got.password === SECRET, 'posted password differs');
    });

    await test('framework page: input events update JS state (fetch body carries values)', async () => {
      await drv.goto(`${site.origin}/login-react`);
      site.captured.length = 0;
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl, submit: true });
      assert(!r.isError, r.text);
      const got = await waitFor(() => site.captured.find((c) => c.via === 'json'));
      assert(got, 'framework submit never sent');
      assert.strictEqual(got.username, USERNAME); assert(got.password === SECRET, 'state password differs');
    });

    await test('origin mismatch (localhost vs 127.0.0.1) → 403 origin_not_bound, field stays empty', async () => {
      await drv.goto(`${site.altOrigin}/login`);
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl });
      assert(r.isError); assert.strictEqual(r.json.error, 'origin_not_bound'); assert.strictEqual(r.json.origin, site.altOrigin);
      assert.strictEqual(await drv.evalJs('document.querySelector("#p").value'), '');
    });

    await test('server approving a different origin → refused client-side, field stays empty', async () => {
      await drv.goto(`${site.origin}/login`);
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-wrongorigin', cdp_url: chrome.cdpUrl });
      assert(r.isError); assert.strictEqual(r.json.error, 'origin_mismatch');
      assert.strictEqual(await drv.evalJs('document.querySelector("#p").value'), '');
    });

    for (const [ref, code] of [['DP-PWD-nogrant', 'not_granted'], ['DP-PWD-denied', 'denied'], ['DP-PWD-expired', 'expired'], ['DP-PWD-redeemed', 'already_redeemed']]) {
      await test(`${ref} → ${code}`, async () => {
        const r = await mcp.call('demipass_browser_fill', { ref, cdp_url: chrome.cdpUrl });
        assert(r.isError); assert.strictEqual(r.json.error, code);
      });
    }

    await test('428 approval_pending returns request_id; resume with wait_seconds fills', async () => {
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-pending', cdp_url: chrome.cdpUrl });
      assert(r.isError); assert.strictEqual(r.json.error, 'approval_pending'); assert(r.json.request_id);
      const r2 = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-pending2', cdp_url: chrome.cdpUrl, wait_seconds: 10 }, 30000);
      assert(!r2.isError, r2.text); assert.strictEqual(r2.json.filled, true);
    });

    await test('no password field / two password fields → refused before any request is spent', async () => {
      const before = requestsMade(mock);
      await drv.goto(`${site.origin}/nofields`);
      const a = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl });
      assert.strictEqual(a.json.error, 'no_password_field');
      await drv.goto(`${site.origin}/login-two`);
      const b = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl });
      assert.strictEqual(b.json.error, 'ambiguous_password_field');
      assert.strictEqual(requestsMade(mock), before);
      const c = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl, password_selector: '[name=confirm]', username_selector: '[name=user]' });
      assert(!c.isError, c.text);
      assert.strictEqual(await drv.evalJs('document.querySelector("[name=confirm]").value.length'), SECRET.length);
      assert.strictEqual(await drv.evalJs('document.querySelector("[name=new]").value'), '');
    });

    await test('several pages open → ambiguous_page lists targets; target_id picks one', async () => {
      const c2 = await connect(chrome.cdpUrl);
      const { targetId } = await c2.send('Target.createTarget', { url: `${site.origin}/login` });
      await sleep(800);
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl });
      assert.strictEqual(r.json.error, 'ambiguous_page'); assert(r.json.pages.length >= 2);
      const r2 = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl, target_id: targetId });
      assert(!r2.isError, r2.text); assert.strictEqual(r2.json.target_id, targetId);
      await c2.send('Target.closeTarget', { targetId }); c2.close();
    });

    await test('page keeps fewer characters → value_not_accepted, the field is cleared', async () => {
      await drv.goto(`${site.origin}/login-trunc`);
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl });
      assert(r.isError); assert.strictEqual(r.json.error, 'value_not_accepted', r.text);
      assert.strictEqual(await drv.evalJs('document.querySelector("#p").value.length'), 0);
    });

    await test('cdp_url off loopback is refused through the MCP tool (no request spent)', async () => {
      const before = requestsMade(mock);
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: 'http://192.0.2.10:9222' });
      assert(r.isError); assert.strictEqual(r.json.error, 'cdp_not_loopback');
      assert.strictEqual(requestsMade(mock), before);
    });

    await test('operator DEMIPASS_CDP_URL: fill without cdp_url works; a different cdp_url is refused', async () => {
      await drv.goto(`${site.origin}/login`);
      const mcp2 = startMcp(process.execPath, [path.join(ROOT, 'mcp-server.js')], { ...baseEnv(mock), DEMIPASS_CDP_URL: chrome.cdpUrl }, 'demipass-mcp-cdpenv');
      try {
        await mcp2.init();
        const ok = await mcp2.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
        assert(!ok.isError, ok.text); assert.strictEqual(ok.json.filled, true);
        const other = await connect(chrome.cdpUrl); const ws = await other.send('Browser.getVersion'); other.close(); assert(ws);
        const bad = await mcp2.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: 'http://127.0.0.1:9' });
        assert(bad.isError); assert.strictEqual(bad.json.error, 'cdp_url_not_allowed');
      } finally { mcp2.close(); }
    });

    await test('LIMIT (documented): the agent\'s own driver can still read a filled field', async () => {
      await drv.goto(`${site.origin}/login`);
      await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', cdp_url: chrome.cdpUrl });
      const len = await drv.evalJs('document.querySelector("#p").value.length'); // length only: never pull the value into the test log
      assert.strictEqual(len, SECRET.length);
    });
    results.suites.push('chromium: RUN');
  } finally {
    mcp.close(); drv.close(); chrome.close();
  }
}

function findLightpanda() {
  const c = process.env.LIGHTPANDA_BIN || '/home/flimflam/tmp/lightpanda-1.0.1/lightpanda-x86_64-linux';
  return fs.existsSync(c) ? c : null;
}

async function lightpandaSuite(mock, site, bin) {
  log(`\nLightpanda via demipass-lightpanda-mcp (${bin})`);
  const mcp = startMcp(process.execPath, [path.join(ROOT, 'browser-fill/lightpanda-mcp.js'), '--lightpanda', bin], baseEnv(mock), 'lightpanda-wrapper');
  try {
    await mcp.init();
    const tl = await mcp.rpc('tools/list', {});
    await test('wrapper passes Lightpanda tools through and adds the fill tools', () => {
      const names = tl.result.tools.map((t) => t.name);
      for (const n of ['goto', 'tree', 'evaluate', 'fill', 'click', 'demipass_browser_fill', 'demipass_browser_fill_candidates']) assert(names.includes(n), n);
    });
    seedSecrets(mock, site);
    const goto = async (p, o = site.origin) => { const r = await mcp.call('goto', { url: `${o}${p}` }); assert(!r.isError, r.text); };

    await test('candidates for the current page', async () => {
      await goto('/login');
      const r = await mcp.call('demipass_browser_fill_candidates', {});
      assert(!r.isError, r.text); assert.strictEqual(r.json.origin, site.origin);
      assert(r.json.candidates.some((c) => c.ref === 'DP-PWD-good'));
    });

    await test('fill + submit lands in the right fields (server receives exact values)', async () => {
      await goto('/login');
      site.captured.length = 0;
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', submit: true });
      assert(!r.isError, r.text);
      assert.strictEqual(r.json.filled, true); assert.strictEqual(r.json.chars, SECRET.length); assert.strictEqual(r.json.submitted, true);
      const got = await waitFor(() => site.captured.find((c) => c.via === 'form'));
      assert(got, 'form never posted');
      assert.strictEqual(got.username, USERNAME); assert(got.password === SECRET, 'posted password differs');
    });

    await test('after a fill, the agent reading the field gets [demipass:redacted]', async () => {
      await goto('/login');
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
      assert(!r.isError, r.text);
      const ev = await mcp.call('evaluate', { script: 'document.querySelector("#p").value' });
      assert(ev.text.includes(REDACTED), 'evaluate result not redacted');
      const tree = await mcp.call('tree', {});
      assert(!tree.text.includes(SECRET));
      const html = await mcp.call('evaluate', { script: 'encodeURIComponent(document.querySelector("#p").value)' });
      assert(html.text.includes(REDACTED), 'URL-encoded read not redacted');
    });

    await test('GET form puts the password in the URL — getUrl is redacted', async () => {
      await goto('/login-get');
      site.captured.length = 0;
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', username_selector: '[name=user]', submit: true });
      assert(!r.isError, r.text);
      const got = await waitFor(() => site.captured.find((c) => c.via === 'get'));
      assert(got && got.password === SECRET, 'GET submit did not carry the value');
      const u = await mcp.call('getUrl', {});
      assert(u.text.includes(REDACTED), 'URL not redacted');
    });

    await test('framework page: input events update JS state', async () => {
      await goto('/login-react');
      site.captured.length = 0;
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good', submit: true });
      assert(!r.isError, r.text);
      await mcp.call('waitForState', { state: 'networkidle', timeout: 3000 }).catch(() => {});
      const got = await waitFor(() => site.captured.find((c) => c.via === 'json'));
      assert(got, 'framework submit never sent');
      assert.strictEqual(got.username, USERNAME); assert(got.password === SECRET, 'state password differs');
    });

    await test('origin mismatch (localhost vs 127.0.0.1) → origin_not_bound, field stays empty', async () => {
      await goto('/login', site.altOrigin);
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
      assert(r.isError); assert.strictEqual(r.json.error, 'origin_not_bound');
      const ev = await mcp.call('evaluate', { script: 'String(document.querySelector("#p").value.length)' });
      assert.strictEqual(ev.text.trim(), '0');
    });

    await test('server approving a different origin → refused', async () => {
      await goto('/login');
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-wrongorigin' });
      assert(r.isError); assert.strictEqual(r.json.error, 'origin_mismatch');
    });

    for (const [ref, code] of [['DP-PWD-nogrant', 'not_granted'], ['DP-PWD-denied', 'denied'], ['DP-PWD-expired', 'expired'], ['DP-PWD-pending', 'approval_pending']]) {
      await test(`${ref} → ${code}`, async () => {
        const r = await mcp.call('demipass_browser_fill', { ref });
        assert(r.isError); assert.strictEqual(r.json.error, code);
      });
    }

    await test('an agent id "demipass-internal-1" in flight when a fill starts gets its own reply (no id collision)', async () => {
      await goto('/login');
      const before = mock.calls.length;
      const ev = mcp.sendRaw({ jsonrpc: '2.0', id: 'demipass-internal-1', method: 'tools/call', params: { name: 'evaluate', arguments: { script: '"https://victim.example"' } } });
      const fill = mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
      const [e, f] = await Promise.all([ev, fill]);
      assert.strictEqual(e.result.content[0].text, 'https://victim.example');
      assert(!f.isError, f.text); assert.strictEqual(f.json.origin, site.origin);
      assert.deepStrictEqual(mock.calls.slice(before).map((c) => c.status), [201, 200], 'one request, one redeem, for the real page');
    });

    await test('values the page echoes come back redacted in markdown / links / interactiveElements / extract / html / evaluate', async () => {
      await goto('/login-reflect');
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-punct', username_selector: '[name=user]', submit: true });
      assert(!r.isError, r.text);
      await mcp.call('waitForState', { state: 'networkidle', timeout: 3000 }).catch(() => {});
      const reads = {};
      for (const [n, a] of [['markdown', {}], ['links', {}], ['interactiveElements', {}], ['html', {}], ['tree', {}], ['consoleLogs', {}], ['getUrl', {}],
        ['evaluate', { script: 'decodeURIComponent(location.search)' }], ['evaluate', { script: 'document.title' }],
        ['extract', { schema: JSON.stringify({ t: 'title', a: { selector: 'a', attr: 'href' }, e: { selector: 'input[name=echo]', attr: 'value' } }) }]]) {
        reads[`${n} ${JSON.stringify(a).slice(0, 40)}`] = (await mcp.call(n, a)).text;
      }
      assert(/You sent/.test(reads['markdown {}']), 'the reflect page did not load');
      for (const [k, t] of Object.entries(reads)) {
        const hit = encodingsOf(SECRET2).find((n) => t.includes(n));
        assert(!hit, `${k} leaks the value (an encoding of it)`);
        if (!/^(tree|consoleLogs)/.test(k)) assert(t.includes(REDACTED), `${k} shows no redaction — did the page echo it?`);
      }
    });

    await test('page keeps fewer characters → value_not_accepted, the field is cleared', async () => {
      await goto('/login-trunc');
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
      assert(r.isError); assert.strictEqual(r.json.error, 'value_not_accepted', r.text);
      const ev = await mcp.call('evaluate', { script: 'String(document.querySelector("#p").value.length)' });
      assert.strictEqual(ev.text.trim(), '0');
    });

    await test('no fill identity provisioned: token file absent → no_fill_identity (Lightpanda still works); provisioned later → fills', async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpfill-prov-'));
      const tokenFile = path.join(dir, 'demipass-fill.token');
      const env = baseEnv(mock);
      delete env.DEMIPASS_FILL_TOKEN;
      Object.assign(env, { DEMIPASS_FILL_TOKEN_FILE: tokenFile, DEMIPASS_TOKEN: SILICON }); // the bearer would work: it must not be used
      const w = startMcp(process.execPath, [path.join(ROOT, 'browser-fill/lightpanda-mcp.js'), '--lightpanda', bin], env, 'lightpanda-wrapper-noid');
      try {
        await w.init();
        const g = await w.call('goto', { url: `${site.origin}/login` }); assert(!g.isError, g.text);
        const before = requestsMade(mock);
        const f = await w.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
        assert(f.isError); assert.strictEqual(f.json.error, 'no_fill_identity', f.text);
        const c = await w.call('demipass_browser_fill_candidates', {});
        assert.strictEqual(c.json.error, 'no_fill_identity');
        assert.strictEqual(requestsMade(mock), before);
        fs.writeFileSync(tokenFile, `${SILICON}\n`, { mode: 0o600 }); // provisioning
        const f2 = await w.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
        assert(!f2.isError, f2.text); assert.strictEqual(f2.json.filled, true);
      } finally { w.close(); fs.rmSync(dir, { recursive: true, force: true }); }
    });

    await test('no password field → refused before any request is spent', async () => {
      const before = requestsMade(mock);
      await goto('/nofields');
      const r = await mcp.call('demipass_browser_fill', { ref: 'DP-PWD-good' });
      assert.strictEqual(r.json.error, 'no_password_field'); assert.strictEqual(requestsMade(mock), before);
    });
    results.suites.push('lightpanda mcp wrapper: RUN');
  } finally {
    mcp.close();
  }
}

// `lightpanda serve`: a second CDP connection sees no pages, so the fill rides the driver's own connection.
async function lightpandaServeSuite(mock, site, bin) {
  log(`\nLightpanda serve — fill on the driver's own CDP session (${bin})`);
  const port = 19000 + (process.pid % 500);
  const lp = spawn(bin, ['serve', '--port', String(port)], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, LIGHTPANDA_DISABLE_TELEMETRY: 'true' } });
  lp.stderr.on('data', (d) => CORPUS.push(`[lightpanda serve stderr] ${d}`));
  await sleep(800);
  const demipass = require(path.join(ROOT, 'index.js'));
  demipass.configure({ baseUrl: mock.url });
  try {
    const conn = await connect(`http://127.0.0.1:${port}`);
    const { browserContextId } = await conn.send('Target.createBrowserContext');
    const { targetId } = await conn.send('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId } = await conn.send('Target.attachToTarget', { targetId, flatten: true });
    const send = (m, p) => conn.send(m, p, sessionId);
    await send('Page.navigate', { url: `${site.origin}/login` });
    await sleep(500);

    await test('a second CDP client sees no pages (per-connection browser)', async () => {
      const other = await connect(`http://127.0.0.1:${port}`);
      const { targetInfos } = await other.send('Target.getTargets');
      other.close();
      assert.strictEqual(targetInfos.length, 0);
    });
    seedSecrets(mock, site);
    await test('fillOnSession on the driver\'s own session lands the values', async () => {
      site.captured.length = 0;
      const out = await fillOnSession(send, { ref: 'DP-PWD-good', submit: true, api: demipass, token: SILICON });
      CORPUS.push(JSON.stringify(out));
      assert.strictEqual(out.filled, true); assert.strictEqual(out.chars, SECRET.length);
      const got = await waitFor(() => site.captured.find((c) => c.via === 'form'));
      assert(got && got.username === USERNAME && got.password === SECRET, 'serve-mode form did not post the values');
    });
    await test('origin mismatch on serve → origin_not_bound', async () => {
      await send('Page.navigate', { url: `${site.altOrigin}/login` });
      await sleep(500);
      const e = await fillOnSession(send, { ref: 'DP-PWD-good', api: demipass, token: SILICON }).catch((x) => x);
      CORPUS.push(JSON.stringify(e.toJSON ? e.toJSON() : String(e)));
      assert.strictEqual(e.code, 'origin_not_bound');
    });
    conn.close();
    results.suites.push('lightpanda serve (library path): RUN');
  } finally {
    lp.kill('SIGKILL');
  }
}

(async () => {
  const mock = await startMockDemipass();
  const site = await startSite();
  try {
    await unitSuite(mock, site);
    await cdpPolicySuite(mock, site).catch((e) => { results.fail++; log(`  FAIL  cdp policy suite crashed: ${e.message}`); });
    await wrapperProtocolSuite().catch((e) => { results.fail++; log(`  FAIL  wrapper protocol suite crashed: ${e.message}`); });
    await processSuite(mock, site).catch((e) => { results.fail++; log(`  FAIL  entry point suite crashed: ${e.message}`); });

    const chromium = findChromium();
    if (chromium) await chromiumSuite(mock, site, chromium).catch((e) => { results.fail++; log(`  FAIL  chromium suite crashed: ${e.message}`); });
    else { results.suites.push('chromium: SKIPPED (no binary)'); log('\nChromium: SKIPPED — no binary (set CHROMIUM_BIN)'); }

    const lp = findLightpanda();
    if (lp) {
      await lightpandaSuite(mock, site, lp).catch((e) => { results.fail++; log(`  FAIL  lightpanda suite crashed: ${e.message}`); });
      await lightpandaServeSuite(mock, site, lp).catch((e) => { results.fail++; log(`  FAIL  lightpanda serve suite crashed: ${e.message}`); });
    } else { results.suites.push('lightpanda: SKIPPED (no binary)'); log('\nLightpanda: SKIPPED — no binary (set LIGHTPANDA_BIN)'); }

    await sleep(300);
    log('\nleak check');
    await test(`no tool result or log line contains the value or its encodings (${CORPUS.length} entries searched)`, () => {
      const needles = [...encodingsOf(SECRET), ...encodingsOf(SECRET2)];
      const leaks = (line) => needles.some((n) => line.includes(n));
      // Controls: the detector catches each encoding, and the corpus really holds what the agents received.
      for (const n of needles) assert(leaks(`planted ${n} control`), 'detector misses an encoding');
      const agentLines = CORPUS.filter((l) => / stdout\] /.test(l)).length;
      if (results.suites.some((s) => s.endsWith('RUN'))) assert(agentLines >= 20, `only ${agentLines} agent-facing lines captured`);
      const hits = CORPUS.filter(leaks);
      assert.strictEqual(hits.length, 0, `${hits.length} entries leak the value: ${hits.map((h) => h.slice(0, 60).split(SECRET).join('<<SECRET>>').split(SECRET2).join('<<SECRET2>>')).join(' | ')}`);
    });
    await test('no fill call carried X-Admin-Key (the SDK and mcp-server had one configured)', () => {
      const fills = mock.calls.filter((c) => c.path.startsWith('/api/blindkey/fill'));
      assert(fills.length >= 10, `only ${fills.length} fill calls observed`);
      assert.strictEqual(fills.filter((c) => c.adminKey).length, 0);
    });
  } finally {
    mock.server.close(); site.server.close();
  }
  console.log(`\n${results.pass} passed, ${results.fail} failed — ${results.suites.join('; ')}`);
  process.exit(results.fail ? 1 : 0);
})();
