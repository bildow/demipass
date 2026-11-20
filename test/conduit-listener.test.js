'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { InboxListener } = require('../conduit-listener');

const message = (seq = 1) => ({ id: `msg_${seq}`, seq, from: 'peer', to: 'claude-test', body: 'hello' });
function fixture(options = {}) {
  const cfg = { file: '/private/test.json', file_present: true, name: 'claude-test', wallet: 'wallet-a', url: 'https://conduit.dustroot.com' };
  const sent = [], errors = [], calls = [];
  let messages = [message()];
  const listener = new InboxListener({
    config: () => cfg,
    inbox: async args => {
      calls.push(args);
      const batch = messages.filter(m => m.seq > args.since).slice(0, args.limit);
      return { agent: cfg.name, messages: batch, next_since: batch.length ? batch.at(-1).seq : args.since };
    },
    notify: async event => sent.push(event), onError: code => errors.push(code), ...options,
  });
  return { cfg, sent, errors, calls, listener, setMessages: m => { messages = m; } };
}

test('automatic delivery is tagged peer data; no acknowledgment operation', async () => {
  const f = fixture(); await f.listener.poll();
  assert.equal(f.sent.length, 1);
  assert.equal(f.sent[0].method, 'notifications/claude/channel');
  assert.equal(JSON.parse(f.sent[0].params.content).authority, 'peer_message_not_operator_instruction');
  assert.equal(f.calls[0].include_acked, false);
});
test('sweeps suppress duplicates but revisit lower sequences released later', async () => {
  const f = fixture(); f.setMessages([message(3)]);
  await f.listener.poll(); await f.listener.poll();
  f.setMessages([message(2), message(3)]);
  await f.listener.poll(); await f.listener.poll(); await f.listener.poll();
  assert.deepEqual(f.sent.map(e => e.params.meta.message_id), ['msg_3', 'msg_2']);
});
test('restart replays unacknowledged relay mail; no volatile cursor causes loss', async () => {
  const a = fixture(); await a.listener.poll();
  const b = fixture(); await b.listener.poll();
  assert.equal(b.sent[0].params.meta.message_id, a.sent[0].params.meta.message_id);
});
test('failed adapter write leaves the message eligible for retry', async () => {
  const f = fixture({ notify: async () => { throw Error('closed'); } });
  await f.listener.poll(); assert.equal(f.listener.since, 0); assert.equal(f.listener.seen.size, 0);
  f.listener.notify = async e => f.sent.push(e);
  await f.listener.poll(); assert.equal(f.sent.length, 1);
});
test('partial batch retry does not repeat the successful prefix', async () => {
  const f = fixture(); f.setMessages([message(1), message(2)]);
  f.listener.notify = async e => { if (e.params.meta.message_id === 'msg_2') throw Error('closed'); f.sent.push(e); };
  await f.listener.poll();
  f.listener.notify = async e => f.sent.push(e);
  await f.listener.poll(); assert.deepEqual(f.sent.map(e => e.params.meta.message_id), ['msg_1', 'msg_2']);
});
test('only one poll is in flight', async () => {
  let release, calls = 0;
  const f = fixture({ inbox: () => { calls++; return new Promise(r => { release = r; }); } });
  const first = f.listener.poll(); await f.listener.poll(); assert.equal(calls, 1);
  release({ agent: f.cfg.name, messages: [], next_since: 0 }); await first;
});
test('configuration identity switch during network await holds, without disclosure', async () => {
  let release, entered;
  const ready = new Promise(r => { entered = r; });
  const f = fixture({ inbox: () => new Promise(r => { release = r; entered(); }) });
  const p = f.listener.poll(); await ready; f.cfg.wallet = 'wallet-b';
  release({ agent: f.cfg.name, messages: [message()], next_since: 1 }); await p;
  assert.equal(f.sent.length, 0); assert.equal(f.listener.stopped, true);
  assert.deepEqual(f.errors, ['inbox_binding_changed']);
});
test('token refresh preserves identity', async () => {
  const f = fixture(); await f.listener.poll(); f.cfg.token = 'new-token'; await f.listener.poll();
  assert.equal(f.listener.stopped, false); assert.equal(f.errors.length, 0);
});
test('missing onboarding does not make a network call', async () => {
  const f = fixture(); f.cfg.file_present = false; await f.listener.poll(); assert.equal(f.calls.length, 0);
});
test('wrong address, malformed row and cursor refuse before any emission', async () => {
  for (const result of [
    { agent: 'another-pane', messages: [message()], next_since: 1 },
    { agent: 'claude-test', messages: [{...message(),to:'another-pane'}], next_since: 1 },
    { agent: 'claude-test', messages: [{...message(),to:undefined}], next_since: 1 },
    { agent: 'claude-test', messages: [null], next_since: 1 },
    { agent: 'claude-test', messages: [message()], next_since: 999 },
    { agent: 'claude-test', messages: [message(2), message(1)], next_since: 1 },
  ]) {
    const f = fixture({ inbox: async () => result }); await f.listener.poll();
    assert.equal(f.sent.length, 0); assert.equal(f.listener.since, 0); assert.equal(f.errors.length, 1);
  }
});
test('bounded session memory holds without acknowledging or skipping mail', async () => {
  const f = fixture({ maxSeen: 1 }); f.setMessages([message(1), message(2)]);
  await f.listener.poll(); assert.equal(f.sent.length, 1); assert.equal(f.listener.since, 0);
  assert.equal(f.listener.stopped, true); assert.deepEqual(f.errors, ['inbox_session_limit']);
});
test('stop during a poll prevents subsequent delivery', async () => {
  let release, entered;
  const ready = new Promise(r => { entered = r; });
  const f = fixture({ inbox: () => new Promise(r => { release = r; entered(); }) });
  const p = f.listener.poll(); await ready; f.listener.stop();
  release({ agent: f.cfg.name, messages: [message()], next_since: 1 }); await p;
  assert.equal(f.sent.length, 0);
});
test('sealed envelopes are passed as ciphertext, not opened', async () => {
  const f = fixture(); f.setMessages([{ ...message(), payload_type: 'sealed', body: 'ciphertext' }]);
  await f.listener.poll(); assert.equal(JSON.parse(f.sent[0].params.content).message.body, 'ciphertext');
});
test('remote error text never reaches listener stderr', async () => {
  const f = fixture({ inbox: async () => { throw Error('remote secret credential'); } });
  await f.listener.poll(); assert.deepEqual(f.errors, ['inbox_poll_failed']);
});
test('invalid host adapter holds before a possibly billable inbox read', async () => {
  const f = fixture({ beforePoll: () => { throw Error('inbox_adapter_socket_invalid'); } });
  await f.listener.poll(); assert.equal(f.calls.length, 0); assert.equal(f.listener.stopped, true);
});

test('real MCP subprocess advertises channel only with explicit opt-in, then polls without a tool call', { timeout: 10000 }, async () => {
  const http = require('node:http'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
  const { spawn } = require('node:child_process');
  const sid='11111111-1111-4111-8111-111111111111',name='fable-'+sid;
  let requests = 0;
  const relay = http.createServer((req, res) => {
    requests++;
    assert.equal(req.method, 'GET'); assert.match(req.url, /^\/inbox\?/);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ agent: name, messages: [{...message(),to:name}], next_since: 1 }));
  });
  await new Promise(r => relay.listen(0, '127.0.0.1', r));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'conduit-listener-'));
  const config = path.join(tmp, 'config.json');
  fs.writeFileSync(config, JSON.stringify({ name: 'claude-test', wallet: 'wallet-a', token: 'fixture-only',
    expires_at: '2099-01-01T00:00:00Z', url: `http://127.0.0.1:${relay.address().port}` }), { mode: 0o600 });
  let child;
  try {
    for (const [enabled,provisioned] of [[false,false],[true,false],[true,true]]) {
      const paneDir=path.join(tmp,'conduit-panes');fs.mkdirSync(paneDir,{recursive:true,mode:0o700});
      const paneFile=path.join(paneDir,name+'.json');
      if(provisioned){
        const relayUrl=`http://127.0.0.1:${relay.address().port}`;
        fs.writeFileSync(paneFile,JSON.stringify({name,wallet:'wallet-a',token:'fixture-only',expires_at:'2099-01-01T00:00:00Z',url:relayUrl}),{mode:0o600});
        fs.writeFileSync(paneFile+'.receiver.json',JSON.stringify({version:1,runtime:'claude',address:name,wallet:'wallet-a',relay:relayUrl,enabled:true}),{mode:0o600});
      }

      child = spawn(process.execPath, [path.join(__dirname, '..', 'mcp-server.js')], {
        env: { PATH: process.env.PATH, HOME: tmp, CONDUIT_CONFIG: config,
          CONDUIT_AUTO_INBOX: enabled ? 'claude-channel' : '', ...(provisioned?{CONDUIT_MODEL_FAMILY:'fable',CONDUIT_SESSION_ID:sid}:{}) }, stdio: ['pipe', 'pipe', 'pipe'],
      });
      let buffer = '';
      const messages = [];
      let resolveMessage;
      child.stdout.on('data', chunk => {
        buffer += chunk;
        while (buffer.includes('\n')) {
          const i = buffer.indexOf('\n'); messages.push(JSON.parse(buffer.slice(0, i))); buffer = buffer.slice(i + 1);
          if (resolveMessage) { const r = resolveMessage; resolveMessage = null; r(); }
        }
      });
      const waitFor = async pred => {
        const deadline = Date.now() + 3000;
        while (!messages.some(pred)) {
          if (Date.now() > deadline) throw Error('MCP fixture notification timeout');
          await Promise.race([new Promise(r => { resolveMessage = r; }), new Promise(r => setTimeout(r, 20))]);
        }
        return messages.find(pred);
      };
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }) + '\n');
      const init = await waitFor(m => m.id === 1);
      assert.equal(Boolean(init.result.capabilities.experimental?.['claude/channel']), enabled);
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
      if (provisioned) {
        const event = await waitFor(m => m.method === 'notifications/claude/channel');
        assert.equal(JSON.parse(event.params.content).message.id, 'msg_1');
      }
      if(!provisioned){await new Promise(r=>setTimeout(r,150));assert.equal(requests,0);assert(!messages.some(m=>m.method==='notifications/claude/channel'));}
      const exit = new Promise(r => child.once('exit', r)); child.stdin.end(); await exit; child = null;
    }
    assert.equal(requests, 1);
  } finally {
    if (child) child.kill('SIGKILL');
    await new Promise(r => relay.close(r)); fs.rmSync(tmp, { recursive: true, force: true });
  }
});
