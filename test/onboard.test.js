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
const admission = {ok:true,protocol:1,release_authorized:false,charter_sha256:'a'.repeat(64),lanes:[{name:'intake',repos:['boltcluster'],paths:['docs/**'],add_only:[],deny:[]}]};
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
    if(req.url==='/door/v1/onboard') {
      if(req.headers.authorization!=='Bearer service-admission-probe')return j(401,{error:'wrong scoped token'});
      return st.refuseAdmission?j(403,{ok:false,error:'no lane'}):j(200,{ok:true,wallet:'did:key:zPaneWallet',admission});
    }
    if (req.headers.authorization !== 'Bearer ' + SESSION) return j(401, { error: 'bad session' });
    if(req.url==='/api/services/token' && req.method==='POST')return j(201,{token:'service-admission-probe',token_id:'probe',expires_at:new Date(Date.now()+300000).toISOString()});
    if (req.method === 'GET' && req.url === '/api/identity/pane-rules') return j(200, { ok: true, enabled: st.rulesEnabled !== false, person: 'you', ...(st.rulesEnabled === false ? { next: 'Enable "Write agent instruction files" in the DemiPass app (Settings → Agents).' } : {}) });
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
  tenants.fleetgate.endpoint=process.env.DEMIPASS_URL+'/door';
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
  assert.strictEqual(st.posts[0].daily_cap_dd, 3000, 'fleetgate: the one default shared with its MCP (fleetgate-admission.js), not five of the dearest action');
  assert.match(logs[0], /Approve .* in the DemiPass app/);
  assert.ok(!JSON.stringify(r).includes(SESSION), 'the session never appears in the answer');
  assert.strictEqual(r.mcp.attached, true); assert.strictEqual(r.mcp.changed, true); assert.strictEqual(r.endpoint, tenants.fleetgate.endpoint);
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

test('registerMcp: an entry pinned to another wallet is not "attached" for this one, and is not re-pinned (#17 review round 4)', () => {
  const c3 = path.join(dir, 'pinned.json'); const f = ob.resolveMcpServer('demipass#fleetgate-mcp').file;
  fs.writeFileSync(c3, JSON.stringify({ mcpServers: { fleetgate: { command: 'node', args: [f], env: { DEMIPASS_EXPECT_DID: 'did:key:zWalletA' } } } }));
  const r = ob.registerMcp({ slug: 'fleetgate', file: f, mcpConfig: c3, did: 'did:key:zWalletB' });
  assert.strictEqual(r.changed, false); assert.match(r.error, /pinned to wallet did:key:zWalletA, not did:key:zWalletB/);
  assert.strictEqual(JSON.parse(fs.readFileSync(c3, 'utf8')).mcpServers.fleetgate.env.DEMIPASS_EXPECT_DID, 'did:key:zWalletA', 'not re-pinned');
  const same = ob.registerMcp({ slug: 'fleetgate', file: f, mcpConfig: c3, did: 'did:key:zWalletA' });
  assert.strictEqual(same.error, undefined); assert.strictEqual(same.changed, false);
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

test('generic onboarding checks live admission for an already-consented wallet and fails closed',async()=>{
 st.refuseAdmission=true;const before=st.posts.length;
 let r=await ob.onboardService({service:'fleetgate',mcpConfig:cfg,wait:false});
 assert.strictEqual(r.ok,false);assert.strictEqual(r.status,'admission_required');assert.strictEqual(r.mcp.attached,true);
 st.refuseAdmission=false;r=await ob.onboardService({service:'fleetgate',mcpConfig:cfg,wait:false});
 assert.strictEqual(r.ok,true);assert.strictEqual(r.admission.protocol,1);assert.strictEqual(st.posts.length,before);
});

// ── the pane rules (Aaron 2026-11-18): one marked block in AGENTS.md and CLAUDE.md, replaced in place, never doubled ─
test('installPaneRules writes one marked block into AGENTS.md and CLAUDE.md, keeps what was there, and is idempotent', () => {
  const { installPaneRules, PANE_RULES } = require('../onboard.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-rules-'));
  fs.writeFileSync(path.join(dir, 'CLAUDE.md'), '# My project\n\nKeep this line.\n');
  let r = installPaneRules(dir);
  assert.deepStrictEqual(r.map(x => [path.basename(x.file), x.changed, !!x.created]), [['AGENTS.md', true, true], ['CLAUDE.md', true, false]]);
  const claude = fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8'), agents = fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8');
  assert.ok(claude.startsWith('# My project\n\nKeep this line.\n'), 'existing text kept');
  assert.ok(claude.includes(PANE_RULES) && agents.includes(PANE_RULES));
  assert.strictEqual((claude.match(/demipass-pane-rules:begin/g) || []).length, 1);
  r = installPaneRules(dir);
  assert.ok(r.every(x => x.changed === false), 'a second run changes nothing');
  assert.strictEqual(fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8'), claude);
  // an older block (another version's text) is replaced in place, text after it kept
  fs.writeFileSync(path.join(dir, 'AGENTS.md'), 'before\n<!-- demipass-pane-rules:begin -->\nold rules\n<!-- demipass-pane-rules:end -->\nafter\n');
  r = installPaneRules(dir, { files: ['AGENTS.md'] });
  const a2 = fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8');
  assert.ok(r[0].changed && a2.startsWith('before\n') && a2.endsWith('after\n') && !a2.includes('old rules') && a2.includes(PANE_RULES));
  assert.strictEqual((a2.match(/demipass-pane-rules:begin/g) || []).length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the demipass MCP server sends the pane rules as its instructions at initialize', async () => {
  const { spawn } = require('child_process');
  const p = spawn(process.execPath, [path.join(__dirname, '..', 'mcp-server.js')], { env: { ...process.env, DEMIPASS_TOKEN: SESSION, DEMIPASS_URL: 'http://127.0.0.1:9' }, stdio: ['pipe', 'pipe', 'pipe'] });
  let out = ''; p.stdout.on('data', d => { out += d; });
  p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
  await new Promise(ok => { const t = setInterval(() => { if (out.includes('\n')) { clearInterval(t); ok(); } }, 20); setTimeout(() => { clearInterval(t); ok(); }, 5000); });
  p.kill();
  const r = JSON.parse(out.split('\n')[0]);
  assert.ok(String(r.result.instructions).includes('never asked in chat'), JSON.stringify(r).slice(0, 300));
  assert.ok(!JSON.stringify(r).includes(SESSION), 'no session in the reply');
});

test('installPaneRules: never the home directory, never through a symlink twice, never over a directory, no temp file left', () => {
  const { installPaneRules, PANE_RULES } = require('../onboard.js');
  const r0 = installPaneRules(os.homedir());
  assert.ok(r0.length === 1 && r0[0].skipped && !fs.existsSync(path.join(os.homedir(), 'AGENTS.md.tmp-' + process.pid)), 'home is skipped');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-rules2-'));
  fs.writeFileSync(path.join(dir, 'CLAUDE.md'), 'shared\n'); fs.symlinkSync('CLAUDE.md', path.join(dir, 'AGENTS.md'));
  const r = installPaneRules(dir);
  assert.ok(fs.lstatSync(path.join(dir, 'AGENTS.md')).isSymbolicLink(), 'the symlink survives');
  const c = fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8');
  assert.strictEqual((c.match(/demipass-pane-rules:begin/g) || []).length, 1, 'the shared target is written once');
  assert.ok(r.some(x => x.same_as) && c.startsWith('shared\n') && c.includes(PANE_RULES));
  const d3 = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-rules4-')), outside = path.join(d3, 'elsewhere.md');
  fs.writeFileSync(outside, 'home file\n'); const d4 = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-rules5-'));
  fs.symlinkSync(outside, path.join(d4, 'CLAUDE.md'));
  const r3 = installPaneRules(d4);
  assert.ok(r3.find(x => x.skipped === 'a symlink out of the project'), JSON.stringify(r3));
  assert.strictEqual(fs.readFileSync(outside, 'utf8'), 'home file\n', 'a symlink out of the project is not followed');
  assert.ok(fs.existsSync(path.join(d4, 'AGENTS.md')));
  fs.rmSync(d3, { recursive: true, force: true }); fs.rmSync(d4, { recursive: true, force: true });
  const d2 = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-rules3-'));
  fs.mkdirSync(path.join(d2, 'CLAUDE.md'));
  const r2 = installPaneRules(d2);
  assert.ok(r2.find(x => /CLAUDE\.md$/.test(x.file)).skipped && fs.existsSync(path.join(d2, 'AGENTS.md')));
  assert.ok(!fs.readdirSync(d2).some(f => f.includes('.tmp-')), 'no temp file left');
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(d2, { recursive: true, force: true });
});


test('onboarding refuses to attach a pane or agent until "Write agent instruction files" is enabled; --rules checks it too; tracked files are skipped; the block carries the hash', async () => {
  const { onboardService, installPaneRulesWithPermission, installPaneRules, PANE_RULES_SHA256 } = require('../onboard.js');
  const cfg = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'dp-perm-')), 'mcp.json');
  st.rulesEnabled = false; st.consents = [{ id: 1, service: 'fleetgate', daily_cap_dd: 5000, status: 'active' }];
  // Supply the fixture identity explicitly: an absent config otherwise falls back
  // to the developer's real credentials, and fails before this gate in clean CI.
  const previousToken = process.env.DEMIPASS_TOKEN;
  process.env.DEMIPASS_TOKEN = SESSION;
  let r;
  try { r = await onboardService({ service: 'fleetgate', wait: false, mcpConfig: cfg, log: () => {} }); }
  finally { if (previousToken === undefined) delete process.env.DEMIPASS_TOKEN; else process.env.DEMIPASS_TOKEN = previousToken; }
  assert.strictEqual(r.ok, false); assert.strictEqual(r.status, 'needs_permission'); assert.match(r.error, /Write agent instruction files/);
  assert.ok(!fs.existsSync(cfg), 'nothing attached without the permission');
  r = await installPaneRulesWithPermission(fs.mkdtempSync(path.join(os.tmpdir(), 'dp-perm2-')), SESSION);
  assert.strictEqual(r.written, false); assert.match(r.next, /DemiPass app/);
  r = await installPaneRulesWithPermission(fs.mkdtempSync(path.join(os.tmpdir(), 'dp-perm3-')), null);
  assert.strictEqual(r.written, false, 'no session: not enabled');
  st.rulesEnabled = true;
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-perm4-'));
  r = await installPaneRulesWithPermission(d, SESSION);
  assert.strictEqual(r.written, true); assert.strictEqual(r.sha256, PANE_RULES_SHA256);
  const a = fs.readFileSync(path.join(d, 'AGENTS.md'), 'utf8');
  assert.ok(a.includes('sha256 ' + PANE_RULES_SHA256.slice(0, 16)) && a.includes('with the owner\'s permission'), 'the block names its version and hash');
  // a git-tracked instruction file (someone's tree, e.g. Brain's) is skipped unless asked for
  const g = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-perm5-'));
  const { execFileSync } = require('child_process');
  execFileSync('git', ['-C', g, 'init', '-q']); fs.writeFileSync(path.join(g, 'CLAUDE.md'), 'tracked tree\n'); execFileSync('git', ['-C', g, 'add', 'CLAUDE.md']);
  let rr = installPaneRules(g);
  assert.ok(rr.find(x => /CLAUDE\.md$/.test(x.file) && /tracked by git/.test(x.skipped || '')), JSON.stringify(rr));
  assert.strictEqual(fs.readFileSync(path.join(g, 'CLAUDE.md'), 'utf8'), 'tracked tree\n');
  assert.ok(fs.existsSync(path.join(g, 'AGENTS.md')), 'an untracked file is still written');
  rr = installPaneRules(g, { tracked: true });
  assert.ok(rr.find(x => /CLAUDE\.md$/.test(x.file) && x.changed), 'asked for: written');
  for (const x of [d, g, path.dirname(cfg)]) fs.rmSync(x, { recursive: true, force: true });
  delete st.rulesEnabled;
});
