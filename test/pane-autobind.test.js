'use strict';
// Pane autobind (CONDUIT_AUTOBIND=claude): the model family comes from this Claude Code session's own transcript, read
// lazily, tail-bounded, symlinks refused, only the model string taken. Fixture transcripts in a throwaway HOME.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const sdk = require('../index.js');

const SID = '0f8e2c1a-1b2c-4d5e-8f90-a1b2c3d4e5f6';
const OTHER = '7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d';
let home;
const projects = () => path.join(home, '.claude', 'projects');
const line = (o) => JSON.stringify(o) + '\n';
const asst = (model, extra = {}) => line({ type: 'assistant', sessionId: SID, message: { role: 'assistant', model, content: [{ type: 'text', text: 'secret-looking content sk-live-123' }] }, ...extra });
const user = (text) => line({ type: 'user', sessionId: SID, message: { role: 'user', content: text } });
const transcript = (body, { slug = '-home-x', sid = SID } = {}) => {
  const dir = path.join(projects(), slug); fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, sid + '.jsonl'); fs.writeFileSync(f, body, { mode: 0o600 }); return f;
};
const family = (sid = SID, opts = {}) => sdk._conduitClaudeFamily(sid, { home, ...opts });

test.beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'dp-autobind-')); });
test.afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

test('opus: the last assistant model maps to its family; synthetic records are skipped', () => {
  transcript(user('hi') + asst('claude-opus-5-5') + asst('<synthetic>') + line({ type: 'system', content: 'x' }));
  const r = family();
  assert.strictEqual(r.family, 'opus'); assert.strictEqual(r.model, 'claude-opus-5-5');
  assert.ok(!JSON.stringify(r).includes('secret-looking'), 'nothing but the model string is returned');
});

test('fable: the LAST assistant record wins (an earlier opus turn does not)', () => {
  transcript(asst('claude-opus-5-5') + user('/model') + asst('claude-fable-5-2'));
  assert.strictEqual(family().family, 'fable');
});

test('a brand-new session: no transcript yet, or no assistant record yet', () => {
  assert.match(family().error, /no transcript for this session yet/);
  transcript(user('first prompt') + line({ type: 'permission-mode', mode: 'default' }));
  assert.match(family().error, /no model recorded for this session/);
});

test('malformed lines, an "assistant" string inside user text, sidechain and non-claude models are all skipped', () => {
  transcript(asst('claude-opus-5-5') + '{"type":"assistant","message":{"model":"claude-haiku-4' + '\n' + 'not json at all "assistant" "model"\n' +
    user('please type "assistant" and "model": "claude-sonnet-9"') + asst('claude-haiku-4-5', { isSidechain: true }) +
    asst('gpt-6-sol') + asst('claude-3-5-sonnet-20241022') + asst('claude-' + 'x'.repeat(20) + '-1') + line({ type: 'assistant', message: { model: 42 } }) + '\n\n');
  assert.strictEqual(family().family, 'opus');
});

test('a huge transcript: only the bounded tail is read', () => {
  const pad = user('y'.repeat(1000));
  const fill = pad.repeat(Math.ceil((5 * 1024 * 1024) / pad.length));
  const f = transcript(asst('claude-opus-5-5') + fill);
  assert.ok(fs.statSync(f).size > 5 * 1024 * 1024);
  let r = family();
  assert.match(r.error, /no model recorded/, 'the opus record at the head is outside even the widened window');
  assert.strictEqual(r.bytes_read, 4 * 1024 * 1024, 'one widened read, capped at 4 MiB, never the whole file');
  fs.appendFileSync(f, asst('claude-fable-5-2'));
  r = family();
  assert.strictEqual(r.family, 'fable'); assert.strictEqual(r.bytes_read, 512 * 1024);
  assert.strictEqual(family(SID, { maxBytes: 4096 }).family, 'fable', 'a cut first line is dropped, not parsed');
});

test('the newest assistant line longer than the tail: the read widens once (capped) and finds it, not an older record', () => {
  const big = asst('claude-fable-5-2').replace('secret-looking content', 'z'.repeat(700 * 1024));
  const f = transcript(asst('claude-opus-5-5') + big + user('after'));
  let r = family();
  assert.strictEqual(r.family, 'fable', JSON.stringify(r)); assert.ok(r.bytes_read <= 4 * 1024 * 1024 && r.bytes_read > 512 * 1024);
  // newer than anything the cap can reach: fail closed rather than fall back to the older opus record
  fs.writeFileSync(f, asst('claude-opus-5-5') + asst('claude-fable-5-2').replace('secret-looking content', 'z'.repeat(5 * 1024 * 1024)));
  r = family();
  assert.match(r.error, /no model recorded/); assert.strictEqual(r.bytes_read, 4 * 1024 * 1024);
});

test('old model ids (claude-3-5-sonnet-…) do not resolve: fail closed', () => {
  transcript(asst('claude-3-5-sonnet-20241022') + asst('claude-3-opus-20240229') + asst('<synthetic>'));
  assert.match(family().error, /no model recorded/);
});

test('symlinks are refused: a symlinked transcript file and a symlinked project directory', () => {
  const real = path.join(home, 'elsewhere'); fs.mkdirSync(real);
  fs.writeFileSync(path.join(real, SID + '.jsonl'), asst('claude-opus-5-5'));
  fs.mkdirSync(path.join(projects(), '-home-x'), { recursive: true });
  fs.symlinkSync(path.join(real, SID + '.jsonl'), path.join(projects(), '-home-x', SID + '.jsonl'));
  assert.match(family().error, /refused/);
  fs.rmSync(path.join(projects(), '-home-x'), { recursive: true });
  fs.symlinkSync(real, path.join(projects(), '-linked'));
  assert.match(family().error, /no transcript/, 'a symlinked project directory is not searched');
});

test('an invalid session id never builds a path', () => {
  transcript(asst('claude-opus-5-5'));
  for (const bad of ['', '../../../etc/passwd', '*', SID.toUpperCase(), SID.slice(0, 8), SID + '/../' + SID, `${SID}\0`])
    assert.match(family(bad).error, /not a full lowercase UUID/, JSON.stringify(bad));
});

test('the session id selects the file: another session\'s transcript is not used', () => {
  transcript(asst('claude-opus-5-5'), { sid: OTHER });
  assert.match(family().error, /no transcript/);
});

// The SDK end to end, each in a fresh process (the resolved pane is cached per process).
const sdkPath = require.resolve('../index.js');
const run = (code, env) => JSON.parse(execFileSync(process.execPath, ['-e', `const d=require(${JSON.stringify(sdkPath)});(async()=>{${code}})().then(r=>console.log(JSON.stringify(r)),e=>console.log(JSON.stringify({thrown:e.message})))`],
  { env: { PATH: process.env.PATH, HOME: home, CONDUIT_REQUIRE_PANE: '1', ...env }, encoding: 'utf8', timeout: 10000 }));
const AUTO = { CONDUIT_AUTOBIND: 'claude', CLAUDE_CODE_SESSION_ID: SID };
const writeT = (body) => `require('fs').mkdirSync(${JSON.stringify(path.join('@H', '.claude/projects/-p'))}.replace('@H',process.env.HOME),{recursive:true});require('fs').writeFileSync(${JSON.stringify(path.join('@H', '.claude/projects/-p', SID + '.jsonl'))}.replace('@H',process.env.HOME),${JSON.stringify(body)});`;

test('SDK: resolved lazily at the first Conduit call, then cached (a later /model does not move the address)', () => {
  const r = run(`${writeT(asst('claude-opus-5-5'))} const a=d.conduitConfig(); ${writeT(asst('claude-opus-5-5') + asst('claude-fable-5-2'))}
    const b=d.conduitConfig(); return {a:a.pane_address,src:a.pane_source,b:b.pane_address,err:a.pane_error||null};`, AUTO);
  assert.deepStrictEqual(r, { a: `opus-${SID}`, src: 'autobind', b: `opus-${SID}`, err: null });
});

test('SDK: not resolvable yet → clear pane_error, messaging refused, explicit conduit_onboard still binds', () => {
  const r = run(`const c=d.conduitConfig(); let send; try{await d.conduitSend({to:'x',body:'no'});send='SENT'}catch(e){send=e.message}
    const o=await d.conduitOnboard({model_family:'fable',session_id:${JSON.stringify(SID)},url:'http://127.0.0.1:9'});
    const c2=d.conduitConfig(); return {addr:c.pane_address,err:c.pane_error,send,step:o.step,after:c2.pane_address,src:c2.pane_source,err2:c2.pane_error||null};`, AUTO);
  assert.strictEqual(r.addr, null);
  assert.match(r.err, /^pane identity not resolvable yet: no model recorded for this session/);
  assert.match(r.send, /not resolvable yet.*refusing to message as the shared legacy address/);
  assert.strictEqual(r.step, 'health', 'onboarding went on to the relay (unreachable here)');
  assert.strictEqual(r.after, `fable-${SID}`); assert.strictEqual(r.src, 'onboard'); assert.strictEqual(r.err2, null);
});

test('SDK: a session with no model yet resolves once its first reply is recorded', () => {
  const r = run(`${writeT(user('hello'))} const a=d.conduitConfig().pane_address; ${writeT(user('hello') + asst('claude-sonnet-5-0'))}
    await new Promise(ok=>setTimeout(ok,2100)); return {a,b:d.conduitConfig().pane_address};`, AUTO);
  assert.deepStrictEqual(r, { a: null, b: `sonnet-${SID}` });
});

test('SDK: explicit env identity outranks autobind; the transcript is not consulted', () => {
  const r = run(`${writeT(asst('claude-opus-5-5'))} const c=d.conduitConfig(); return {a:c.pane_address,src:c.pane_source};`,
    { ...AUTO, CONDUIT_MODEL_FAMILY: 'astra', CONDUIT_SESSION_ID: OTHER });
  assert.deepStrictEqual(r, { a: `astra-${OTHER}`, src: 'env' });
});

test('SDK: an explicit conduit_onboard made before any Conduit call outranks a resolvable autobind', () => {
  const r = run(`${writeT(asst('claude-opus-5-5'))} await d.conduitOnboard({model_family:'astra',session_id:${JSON.stringify(SID)},url:'http://127.0.0.1:9'});
    return {a:d.conduitConfig().pane_address};`, AUTO);
  assert.deepStrictEqual(r, { a: `astra-${SID}` });
});

test('SDK: invalid session id, unsupported autobind kind (Codex) → unbound with a reason, never the legacy name', () => {
  let r = run(`const c=d.conduitConfig(); return {a:c.pane_address,e:c.pane_error,n:c.name};`, { CONDUIT_AUTOBIND: 'claude', CLAUDE_CODE_SESSION_ID: '../../etc/passwd' });
  assert.strictEqual(r.a, null); assert.match(r.e, /not a full lowercase UUID/); assert.strictEqual(r.n, '');
  r = run(`const c=d.conduitConfig(); return {a:c.pane_address,e:c.pane_error};`, { CONDUIT_AUTOBIND: 'codex', CODEX_THREAD_ID: SID });
  assert.strictEqual(r.a, null); assert.match(r.e, /not supported \(only claude\).*conduit_onboard/);
  r = run(`try{await d.conduitSend({to:'x',body:'no'});return 'SENT'}catch(e){return e.message}`, {});
  assert.match(r, /Pane identity required.*Codex/);
});
