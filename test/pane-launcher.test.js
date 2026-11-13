'use strict';
// bin/install-pane-launcher.sh + bin/demipass-pane-mcp.js in a throwaway HOME. Fake agent runtimes are node binaries
// reached through symlinks named `claude` / `codex` (so /proc/<pid>/cmdline names them); the pinned "release" is a stub
// mcp-server.js that prints the identity env it was started with.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..');
const SHA = 'e2689a1bf4b1b806a83ca780570e326dad7e2bec';
const OUTER = '11111111-2222-4333-8444-555555555555';
const INNER = '66666666-7777-4888-9999-aaaaaaaaaaaa';
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const TOKEN = `${b64({ alg: 'EdDSA' })}.${b64({ sub: 'did:key:zPaneWallet' })}.c2lnLXNlY3JldA`;

let home, bin, launcher;
const sh = (args, env = {}) => spawnSync('bash', [path.join(REPO, 'bin/install-pane-launcher.sh'), ...args], { env: { PATH: process.env.PATH, HOME: home, ...env }, encoding: 'utf8' });

test.before(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-launcher-'));
  bin = path.join(home, 'fakebin'); fs.mkdirSync(bin);
  for (const n of ['claude', 'codex']) fs.symlinkSync(process.execPath, path.join(bin, n));
  fs.writeFileSync(path.join(home, '.mcp.json'), JSON.stringify({ mcpServers: {
    demipass: { command: 'node', env: { DEMIPASS_TOKEN: TOKEN, DEMIPASS_URL: 'http://127.0.0.1:9' } },
    buoy: { command: 'node', env: { BUOY_TOKEN: TOKEN } } } }));
  fs.mkdirSync(path.join(home, '.config/demipass'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, '.config/demipass/conduit.json'), JSON.stringify({ wallet: 'did:key:zPaneWallet', name: 'legacy' }), { mode: 0o600 });
  const rel = path.join(home, '.local/share/demipass/releases', SHA); fs.mkdirSync(rel, { recursive: true });
  const stub = `const e=process.env;process.stdout.write(JSON.stringify({role:ROLE,family:e.CONDUIT_MODEL_FAMILY||null,session:e.CONDUIT_SESSION_ID||null,
    autobind:e.CONDUIT_AUTOBIND||null,sname:e.CONDUIT_SESSION_NAME||null,ssrc:e.CONDUIT_SESSION_NAME_SOURCE||null,require_pane:e.CONDUIT_REQUIRE_PANE||null,has_token:!!(e.DEMIPASS_TOKEN||e.BUOY_TOKEN),pid:process.pid})+'\\n');`;
  fs.writeFileSync(path.join(rel, 'mcp-server.js'), stub.replace('ROLE', '"demipass"'));
  fs.writeFileSync(path.join(rel, 'buoy-mcp.js'), stub.replace('ROLE', '"buoy"'));
  // chain.js: one hop of a process chain. argv = the remaining hops; CHAIN_BIND=1 records this process in pane-bindings.
  fs.writeFileSync(path.join(home, 'chain.js'), `
    const fs=require('fs'),path=require('path'),{spawnSync}=require('child_process');
    const [,, next, ...rest]=process.argv; const env={...process.env};
    if (env.CHAIN_BIND==='1') { const s=fs.readFileSync('/proc/self/stat','utf8'); const f=s.slice(s.lastIndexOf(') ')+2).trim().split(/\\s+/);
      fs.writeFileSync(path.join(env.HOME,'.config/demipass/pane-bindings.json'),JSON.stringify({bindings:[{pane:'%1',pid:process.pid,start_ticks:Number(f[19]),model_family:'opus',session_id:${JSON.stringify(OUTER)},session_name:'audit | brain'}]})); }
    delete env.CHAIN_BIND;
    let cmd, args;
    if (next.startsWith('launcher')) { cmd=${JSON.stringify(process.execPath)}; args=[env.LAUNCHER, ...(next==='launcher-buoy'?['--buoy']:[])];
      if (env.CHAIN_MCP_SID) env.CLAUDE_CODE_SESSION_ID=env.CHAIN_MCP_SID; }
    else { const [name,flag]=next.split('+'); cmd=name==='node'?${JSON.stringify(process.execPath)}:path.join(${JSON.stringify(bin)},name); args=[__filename,...rest]; if(flag==='bind')env.CHAIN_BIND='1'; }
    const r=spawnSync(cmd,args,{env,stdio:['ignore','inherit','inherit']}); process.exitCode=r.status;`);
});
test.after(() => { fs.rmSync(home, { recursive: true, force: true }); });

// Run a chain of hops ending at the launcher; returns the stub's env report, the receipt and stderr.
const chain = (hops, env = {}) => {
  fs.rmSync(path.join(home, '.config/demipass/pane-bindings.json'), { force: true });
  const r = spawnSync(process.execPath, [path.join(home, 'chain.js'), ...hops], { env: { PATH: process.env.PATH, HOME: home, LAUNCHER: launcher, ...env }, encoding: 'utf8', timeout: 15000 });
  assert.strictEqual(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').pop());
  const receipt = JSON.parse(fs.readFileSync(path.join(home, '.config/demipass/runtime', `pid-${out.pid}.json`), 'utf8'));
  return { out, receipt, stderr: r.stderr };
};

test('installer: refuses a bad sha or a missing release; installs 0700, pinned, prints no credential; keeps .bak', () => {
  let r = sh(['abc']); assert.strictEqual(r.status, 2); assert.match(r.stderr, /usage/);
  r = sh(['f'.repeat(40)]); assert.strictEqual(r.status, 1); assert.match(r.stderr, /no release/);
  r = sh([SHA]); assert.strictEqual(r.status, 0, r.stderr);
  launcher = path.join(home, '.local/bin/demipass-pane-mcp.js');
  assert.strictEqual(fs.statSync(launcher).mode & 0o777, 0o700);
  const text = fs.readFileSync(launcher, 'utf8');
  assert.ok(text.includes(`const RELEASE = '${SHA}';`)); assert.ok(!text.includes('@@DEMIPASS_RELEASE_SHA@@'));
  for (const o of [r.stdout, r.stderr]) { assert.ok(!o.includes('c2lnLXNlY3JldA') && !o.includes(TOKEN), 'credential printed'); }
  assert.match(r.stdout, /launcher source: this checkout/);
  r = sh([SHA]); assert.strictEqual(r.status, 0); assert.ok(fs.existsSync(launcher + '.bak'));
});

test('installer: a symlinked .bak is replaced, never written through', () => {
  const victim = path.join(home, 'victim.txt'); fs.writeFileSync(victim, 'untouched');
  fs.rmSync(launcher + '.bak', { force: true }); fs.symlinkSync(victim, launcher + '.bak');
  const r = sh([SHA]); assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(fs.readFileSync(victim, 'utf8'), 'untouched');
  assert.ok(fs.lstatSync(launcher + '.bak').isFile(), '.bak is a regular file now');
});

test('installer: a release that ships the launcher is installed from that release', () => {
  const relBin = path.join(home, '.local/share/demipass/releases', SHA, 'bin'); fs.mkdirSync(relBin);
  fs.writeFileSync(path.join(relBin, 'demipass-pane-mcp.js'), fs.readFileSync(path.join(REPO, 'bin/demipass-pane-mcp.js'), 'utf8').replace('// demipass-pane-mcp:', '// from-release demipass-pane-mcp:'));
  const r = sh([SHA]); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, new RegExp(`launcher source: release ${SHA}`));
  assert.ok(fs.readFileSync(launcher, 'utf8').includes('// from-release'));
  fs.rmSync(relBin, { recursive: true });
  assert.strictEqual(sh([SHA]).status, 0);
});

test('the repository copy (unpinned) refuses to start', () => {
  const r = spawnSync(process.execPath, [path.join(REPO, 'bin/demipass-pane-mcp.js')], { env: { PATH: process.env.PATH, HOME: home }, encoding: 'utf8' });
  assert.notStrictEqual(r.status, 0); assert.match(r.stderr, /not pinned to a release/); assert.strictEqual(r.stdout, '');
});

test('a malformed ~/.mcp.json is reported without quoting any of it', () => {
  const f = path.join(home, '.mcp.json'); const saved = fs.readFileSync(f);
  try {
    fs.writeFileSync(f, `{"mcpServers":{"demipass":{"env":{"DEMIPASS_TOKEN":"${TOKEN}"}}},,}`);
    const r = spawnSync(process.execPath, [launcher], { env: { PATH: process.env.PATH, HOME: home }, encoding: 'utf8' });
    assert.strictEqual(r.status, 1); assert.match(r.stderr, /~\/\.mcp\.json is not valid JSON/);
    for (const frag of [TOKEN, 'c2lnLXNlY3JldA', 'mcpServers', 'DEMIPASS_TOKEN']) assert.ok(!r.stderr.includes(frag) && !r.stdout.includes(frag), `stderr quotes ${frag}`);
  } finally { fs.writeFileSync(f, saved); }
});

test('an explicit binding wins over autobind (pid + start time of the nearest agent)', () => {
  const { out, receipt } = chain(['claude+bind', 'launcher'], { CHAIN_MCP_SID: INNER });
  assert.deepStrictEqual([out.family, out.session, out.autobind, out.require_pane, out.has_token], ['opus', OUTER, null, '1', true]);
  assert.strictEqual(out.sname, 'audit | brain', 'the binding\'s stable role is passed on'); assert.strictEqual(out.ssrc, 'binding'); assert.strictEqual(receipt.session_name, 'audit | brain');
  assert.strictEqual(receipt.source, 'pane-binding-process-start-checked'); assert.strictEqual(receipt.release, SHA);
  assert.ok(!JSON.stringify(receipt).includes(TOKEN), 'credential in the receipt');
  const st = fs.statSync(path.join(home, '.config/demipass/runtime', `pid-${out.pid}.json`)); assert.strictEqual(st.mode & 0o777, 0o600);
});

test('an unbound Claude Code parent sets CONDUIT_AUTOBIND=claude and no family (also through a non-agent hop)', () => {
  for (const hops of [['claude', 'launcher'], ['claude', 'node', 'launcher']]) {
    const { out, receipt } = chain(hops, { CHAIN_MCP_SID: INNER });
    assert.deepStrictEqual([out.family, out.session, out.autobind, out.require_pane], [null, null, 'claude', '1'], hops.join('>'));
    assert.strictEqual(receipt.source, 'autobind-claude-session'); assert.strictEqual(receipt.runtime, 'claude');
  }
});

test('a nested agent gets nothing from its parent pane: Codex inside a bound pane is unbound', () => {
  const { out, receipt } = chain(['claude+bind', 'codex', 'launcher'], { CHAIN_MCP_SID: INNER });
  assert.deepStrictEqual([out.family, out.session, out.autobind, out.require_pane], [null, null, null, '1']);
  assert.strictEqual(receipt.unbound_reason, 'codex_no_session_id');
});

test('a nested Claude inside a bound pane autobinds to its own session only, never the parent\'s binding', () => {
  const { out } = chain(['claude+bind', 'claude', 'launcher'], { CHAIN_MCP_SID: INNER });
  assert.deepStrictEqual([out.family, out.session, out.autobind, out.sname], [null, null, 'claude', null], 'nor its stable role');
});

test('a session id the Claude process itself inherited is not autobound', () => {
  const { out, receipt } = chain(['claude', 'launcher'], { CLAUDE_CODE_SESSION_ID: OUTER });
  assert.strictEqual(out.autobind, null); assert.strictEqual(receipt.unbound_reason, 'claude_session_id_inherited');
});

test('inherited CONDUIT_* identity variables are discarded', () => {
  const { out } = chain(['codex', 'launcher'], { CONDUIT_MODEL_FAMILY: 'opus', CONDUIT_SESSION_ID: OUTER, CONDUIT_AUTOBIND: 'claude', CONDUIT_SESSION_NAME: 'audit | brain', CONDUIT_SESSION_NAME_SOURCE: 'binding' });
  assert.deepStrictEqual([out.family, out.session, out.autobind, out.sname, out.ssrc], [null, null, null, null, null]);
  assert.strictEqual(chain(['claude', 'launcher'], { CHAIN_MCP_SID: INNER, CONDUIT_SESSION_NAME: 'audit | brain' }).out.sname, null, 'an autobound pane gets no inherited role');
});

test('a missing conduit.json disables Conduit only: the MCP still starts, fail-closed, no binding or autobind', () => {
  const f = path.join(home, '.config/demipass/conduit.json'); const saved = fs.readFileSync(f);
  fs.rmSync(f);
  try {
    const { out, receipt, stderr } = chain(['claude+bind', 'launcher'], { CHAIN_MCP_SID: INNER });
    assert.match(stderr, /Conduit disabled: conduit.json missing/);
    assert.deepStrictEqual([out.family, out.session, out.autobind, out.require_pane, out.has_token], [null, null, null, '1', true]);
    assert.strictEqual(receipt.unbound_reason, 'conduit_disabled');
    fs.writeFileSync(f, JSON.stringify({ wallet: 'did:key:zSomeoneElse' }));
    assert.match(chain(['claude', 'launcher'], { CHAIN_MCP_SID: INNER }).stderr, /for another wallet/);
  } finally { fs.writeFileSync(f, saved, { mode: 0o600 }); }
});

test('--buoy loads the pinned buoy server with no Conduit identity', () => {
  const { out, receipt } = chain(['claude', 'launcher-buoy'], { CHAIN_MCP_SID: INNER });
  assert.deepStrictEqual([out.role, out.autobind, out.require_pane, out.has_token], ['buoy', null, null, true]);
  assert.strictEqual(receipt.role, 'buoy');
});
