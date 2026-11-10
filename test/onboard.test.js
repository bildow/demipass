'use strict';
// demipass-onboard: registry lookup → consent (filed, waited for, approved) → MCP server registered once in the config,
// with the session copied (never printed), a .bak kept, and nothing re-registered. Mock DemiPass only.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SESSION = 'eyJhbGciOiJFZERTQSJ9.' + Buffer.from(JSON.stringify({ sub: 'did:key:zPaneWallet' })).toString('base64url') + '.c2ln';
const st = { consents: [], approveAfter: 2, polls: 0, posts: [] };
const tenants = {
  kodiak: { slug: 'kodiak', name: 'Not Kodiak', endpoint: 'https://k.example', mcp_server: 'demipass#demipass-onboard', actions: [{ action: 'x', open: true, price_dd: 5 }] },
  evil: { slug: 'evil', name: 'Evil', endpoint: 'https://e.example', mcp_server: 'evilpkg#x', actions: [{ action: 'x', open: true, price_dd: 5 }] },
  pricey: { slug: 'pricey', name: 'Pricey', endpoint: 'https://p.example', mcp_server: null, actions: [{ action: 'x', open: true, price_dd: 999999, max_price_dd: 999999 }] },
  fleetgate: { slug: 'fleetgate', name: 'FLEETGATE', endpoint: 'https://repo.example/-/fleetgate/door', mcp_server: 'demipass#fleetgate-mcp',
    actions: [{ action: 'submit', open: true, price_dd: 696, max_price_dd: 696 }, { action: 'sign-charter', open: false, price_dd: 12 }] },
  conduit: { slug: 'conduit', name: 'Conduit', endpoint: 'http://phasewhip.example.ts.net:8080', mcp_server: 'demipass#demipass-mcp', actions: [{ action: 'post', open: true, price_dd: 3 }] },
  bare: { slug: 'bare', name: 'Bare', endpoint: null, mcp_server: null, actions: [] },
};
const srv = http.createServer((req, res) => {
  let b = ''; req.on('data', c => { b += c; }); req.on('end', () => {
    const body = b ? JSON.parse(b) : {};
    const j = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    const m = /^\/api\/services\/([a-z-]+)$/.exec(req.url);
    if (req.method === 'GET' && req.url === '/api/services') return j(200, { tenants: Object.values(tenants) });
    if (req.method === 'GET' && m && !['consents'].includes(m[1])) return tenants[m[1]] ? j(200, tenants[m[1]]) : j(404, { error: 'no such service' });
    if (req.headers.authorization !== 'Bearer ' + SESSION) return j(401, { error: 'bad session' });
    if (req.method === 'GET' && req.url === '/api/services/consents') return j(200, { ok: true, mine: st.consents });
    if (req.method === 'POST' && req.url === '/api/services/consent') {
      st.posts.push(body);
      if (body.approval_id && ++st.polls >= st.approveAfter) { const c = { id: st.consents.length + 1, service: body.service, daily_cap_dd: body.daily_cap_dd, status: 'active' }; st.consents.push(c); return j(201, { ok: true, consent_id: c.id, service: c.service, daily_cap_dd: c.daily_cap_dd }); }
      return j(202, { status: 'approval_pending', approval_id: 41 });
    }
    j(404, { error: 'no route' });
  });
});

let ob, dir, cfg;
test.before(async () => {
  await new Promise(ok => srv.listen(0, '127.0.0.1', ok));
  process.env.DEMIPASS_URL = `http://127.0.0.1:${srv.address().port}`;
  delete process.env.DEMIPASS_TOKEN;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'onboard-test-'));
  cfg = path.join(dir, 'mcp.json');
  fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { demipass: { command: 'node', args: [path.join(__dirname, '..', 'mcp-server.js')], env: { DEMIPASS_TOKEN: SESSION } }, other: { command: 'x' },
    kodiak: { command: 'node', args: ['/opt/kodiak/mcp.js'], env: { KODIAK_KEY: 'k' } } } }), { mode: 0o644 });
  ob = require('../onboard.js');
});
test.after(() => { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); });

test('fleetgate: consent filed and waited for, then the MCP server is registered with the session copied', async () => {
  const logs = [];
  const r = await ob.onboardService({ service: 'fleetgate', mcpConfig: cfg, waitMs: 30000, log: m => logs.push(m) });
  assert.strictEqual(r.ok, true, JSON.stringify(r));
  assert.strictEqual(st.posts[0].daily_cap_dd, 3480, 'default cap: five of the dearest open action');
  assert.match(logs[0], /Approve .* in the DemiPass app/);
  assert.ok(!JSON.stringify(r).includes(SESSION), 'the session never appears in the answer');
  assert.strictEqual(r.mcp.attached, true); assert.strictEqual(r.mcp.changed, true); assert.strictEqual(r.endpoint, 'https://repo.example/-/fleetgate/door');
  const c = JSON.parse(fs.readFileSync(cfg, 'utf8'));
  assert.deepStrictEqual(c.mcpServers.fleetgate.args, [path.resolve(__dirname, '..', 'fleetgate-mcp.js')]);
  assert.strictEqual(c.mcpServers.fleetgate.env.DEMIPASS_TOKEN, undefined, 'no session copy in the entry: the server reads the live one');
  assert.strictEqual(c.mcpServers.fleetgate.env.DEMIPASS_EXPECT_DID, 'did:key:zPaneWallet', 'pinned to the wallet that onboarded it');
  assert.strictEqual(c.mcpServers.fleetgate.env.DEMIPASS_MCP_CONFIG, fs.realpathSync(cfg));
  assert.ok(c.mcpServers.other && c.mcpServers.demipass, 'other entries kept');
  assert.ok(fs.existsSync(cfg + '.bak')); assert.strictEqual(fs.statSync(cfg + '.bak').mode & 0o077, 0, '.bak is 0600 too');
  assert.strictEqual(fs.statSync(cfg).mode & 0o077, 0, 'config is 0600');
});

test('fleetgate again: existing consent reused, config untouched', async () => {
  const n = st.posts.length, before = fs.readFileSync(cfg, 'utf8');
  const r = await ob.onboardService({ service: 'fleetgate', mcpConfig: cfg });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.consent.existing, true); assert.strictEqual(r.mcp.changed, false);
  assert.strictEqual(st.posts.length, n); assert.strictEqual(fs.readFileSync(cfg, 'utf8'), before);
});

test('conduit: its tools live in the demipass server already: recognised, no second entry', async () => {
  st.polls = 0; st.approveAfter = 1;
  const r = await ob.onboardService({ service: 'conduit', mcpConfig: cfg, waitMs: 30000 });
  assert.strictEqual(r.ok, true, JSON.stringify(r)); assert.strictEqual(r.mcp.entry, 'demipass'); assert.strictEqual(r.mcp.changed, false);
  assert.strictEqual(r.consent.daily_cap_dd, 300, 'small prices → the 300 DD floor');
  assert.ok(!JSON.parse(fs.readFileSync(cfg, 'utf8')).mcpServers.conduit);
});

test('--no-wait returns the approval id and the command to finish with', async () => {
  st.polls = 0; st.approveAfter = 99;
  const r = await ob.onboardService({ service: 'bare', mcpConfig: cfg, wait: false });
  assert.strictEqual(r.status, 'approval_pending'); assert.strictEqual(r.approval_id, 41); assert.match(r.next, /--approval 41/);
});

test('unknown service and bad slugs are refused before any session use', async () => {
  const n = st.posts.length;
  assert.match((await ob.onboardService({ service: 'nope', mcpConfig: cfg })).error, /no service "nope"/);
  assert.match((await ob.onboardService({ service: '../x', mcpConfig: cfg })).error, /slug/);
  assert.strictEqual(st.posts.length, n);
});

test('resolveMcpServer: only local, known bins', () => {
  assert.ok(ob.resolveMcpServer('demipass#fleetgate-mcp').file.endsWith('fleetgate-mcp.js'));
  assert.match(ob.resolveMcpServer('demipass#nope').error, /not one of its MCP servers/);
  assert.match(ob.resolveMcpServer('left-pad-zzz-not-here#x').error, /not a first-party/);
  assert.match(ob.resolveMcpServer('npm#npm').error, /not a first-party/, 'never resolves another installed package');
  assert.strictEqual(ob.resolveMcpServer('rm -rf /'), null);
});

test('a tenant naming a third-party server gets consent but no MCP entry; no install hint', async () => {
  st.polls = 0; st.approveAfter = 1;
  const r = await ob.onboardService({ service: 'evil', mcpConfig: cfg, waitMs: 30000 });
  assert.strictEqual(r.ok, true); assert.strictEqual(r.mcp.attached, false); assert.match(r.mcp.reason, /first-party/); assert.ok(!/npm i/.test(JSON.stringify(r)));
  assert.ok(!JSON.parse(fs.readFileSync(cfg, 'utf8')).mcpServers.evil);
});

test('a CLI bin is not an MCP server: a tenant naming one gets no entry', async () => {
  st.polls = 0; st.approveAfter = 1;
  const r = await ob.onboardService({ service: 'kodiak', mcpConfig: cfg, waitMs: 30000 });
  assert.strictEqual(r.mcp.attached, false); assert.match(r.mcp.reason, /not one of its MCP servers/);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(cfg, 'utf8')).mcpServers.kodiak.args, ['/opt/kodiak/mcp.js']);
  assert.match(ob.resolveMcpServer('demipass#constructor').error, /not one of its MCP servers/);
});

test('registerMcp: a name clash never replaces; an old entry\'s copied session is stripped and pinned', () => {
  const c2 = path.join(dir, 'clash.json'); const f = ob.resolveMcpServer('demipass#fleetgate-mcp').file;
  fs.writeFileSync(c2, JSON.stringify({ mcpServers: { brain: { command: 'node', args: ['/opt/brain.js'] } } }));
  const r = ob.registerMcp({ slug: 'brain', file: f, mcpConfig: c2, did: 'did:key:zW' });
  assert.match(r.error, /already exists/); assert.deepStrictEqual(JSON.parse(fs.readFileSync(c2, 'utf8')).mcpServers.brain.args, ['/opt/brain.js']);
  fs.writeFileSync(c2, JSON.stringify({ mcpServers: { fg: { command: 'node', args: [f], env: { DEMIPASS_TOKEN: 'old-copy' } } } }));
  const r2 = ob.registerMcp({ slug: 'fleetgate', file: f, mcpConfig: c2, did: 'did:key:zW' });
  const e = JSON.parse(fs.readFileSync(c2, 'utf8')).mcpServers.fg.env;
  assert.strictEqual(r2.stripped_session_copy, true); assert.strictEqual(e.DEMIPASS_TOKEN, undefined); assert.strictEqual(e.DEMIPASS_EXPECT_DID, 'did:key:zW');
});

test('sessionToken: pinned to the onboarded wallet; another wallet\'s session is refused', () => {
  process.env.DEMIPASS_TOKEN = SESSION;
  process.env.DEMIPASS_EXPECT_DID = 'did:key:zPaneWallet'; assert.strictEqual(ob.sessionToken(cfg), SESSION);
  process.env.DEMIPASS_EXPECT_DID = 'did:key:zSomeoneElse'; assert.strictEqual(ob.sessionToken(cfg), '');
  delete process.env.DEMIPASS_EXPECT_DID; delete process.env.DEMIPASS_TOKEN;
});

test('a tenant\'s huge prices never make the default cap huge (10,000 DD at most)', async () => {
  st.polls = 0; st.approveAfter = 99; const n = st.posts.length;
  await ob.onboardService({ service: 'pricey', mcpConfig: cfg, wait: false });
  assert.strictEqual(st.posts[n].daily_cap_dd, 10000);
});

test('an explicit higher cap than the existing consent files a replacement for approval', async () => {
  st.polls = 0; st.approveAfter = 99;
  const r = await ob.onboardService({ service: 'fleetgate', capDd: 9000, mcpConfig: cfg, wait: false });
  assert.strictEqual(r.status, 'approval_pending'); assert.match(r.next, /daily_cap_dd 9000/);
  assert.strictEqual(st.posts.at(-1).daily_cap_dd, 9000);
});

test('list', async () => {
  const l = await ob.listServices();
  assert.deepStrictEqual(l.find(x => x.service === 'fleetgate').prices, { submit: 696 });
});
