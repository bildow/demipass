'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http');
const { WebSocketServer } = require('ws');
const { deliverCodex } = require('../conduit-codex-adapter');
const { InboxListener } = require('../conduit-listener');
const threadId = '11111111-2222-3333-4444-555555555555';
const address = 'gpt-' + threadId;
const notification = { params: { content: JSON.stringify({ authority: 'peer_message_not_operator_instruction', message: { id: 'msg_1', body: 'hello' } }) } };
async function fixture(run, mode = 'ok') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-codex-')); fs.chmodSync(dir, 0o700);
  const socketPath = path.join(dir, 'server.sock'), requests = [];
  const httpServer = http.createServer(), wss = new WebSocketServer({ server: httpServer });
  wss.on('connection', ws => ws.on('message', raw => {
    const m = JSON.parse(raw); requests.push(m);
    if (!m.id) return;
    if (m.method === 'initialize') ws.send(JSON.stringify({ id: m.id, result: { userAgent: 'test-only' } }));
    else if (m.method === 'thread/read') ws.send(JSON.stringify({ id: m.id, result: { thread: { id: mode === 'wrong' ? 'other-thread' : threadId } } }));
    else if (m.method === 'turn/start' && mode !== 'uncertain') ws.send(JSON.stringify({ id: m.id, result: { turn: { id: 'fixture-turn' } } }));
  }));
  await new Promise(r => httpServer.listen(socketPath, r));
  try { await run({ socketPath, requests, dir }); }
  finally { for (const c of wss.clients) c.terminate(); await new Promise(r => wss.close(r)); await new Promise(r => httpServer.close(r)); fs.rmSync(dir, { recursive: true, force: true }); }
}
test('native Unix WebSocket delivery uses tool output and preserves host authority/model', async () => {
  await fixture(async ({ socketPath, requests }) => {
    const r = await deliverCodex({ socketPath, threadId, address, notification });
    assert.equal(r.turnId, 'fixture-turn');
    const start = requests.find(m => m.method === 'turn/start');
    assert.deepEqual(start.params, { threadId, input: [], toolOutput: { name: 'conduit_inbox', namespace: 'demipass', output: notification.params.content } });
    assert.equal(requests.some(m => /resume|approval|config/.test(m.method)), false);
  });
});
test('target session must match the mailbox and daemon thread metadata', async () => {
  await fixture(async ({ socketPath, requests }) => {
    await assert.rejects(deliverCodex({ socketPath, threadId, address: 'another-mailbox', notification }), /binding_invalid/);
    assert.equal(requests.length, 0);
  });
  await fixture(async ({ socketPath, requests }) => {
    await assert.rejects(deliverCodex({ socketPath, threadId, address, notification }), /binding_invalid/);
    assert.equal(requests.some(m => m.method === 'turn/start'), false);
  }, 'wrong');
});
test('world-accessible socket parent refuses before connection', async () => {
  await fixture(async ({ socketPath, requests, dir }) => {
    fs.chmodSync(dir, 0o755);
    await assert.rejects(deliverCodex({ socketPath, threadId, address, notification }), /socket_invalid/);
    assert.equal(requests.length, 0);
  });
});
test('uncertain native admission stops automatic retries; message remains unacknowledged', async () => {
  await fixture(async ({ socketPath, requests }) => {
    const errors = [];
    const listener = new InboxListener({
      config: () => ({ name: address, wallet: 'w', file: '/fixture', file_present: true, url: 'https://conduit.dustroot.com' }),
      inbox: async () => ({ agent: address, messages: [{ id: 'msg_1', seq: 1, from: 'peer', body: 'hello' }], next_since: 1 }),
      notify: event => deliverCodex({ socketPath, threadId, address, notification: event, timeoutMs: 100 }),
      onError: e => errors.push(e),
    });
    await listener.poll(); await listener.poll();
    assert.equal(listener.stopped, true); assert.equal(listener.seen.size, 0);
    assert.deepEqual(errors, ['inbox_delivery_uncertain']);
    assert.equal(requests.filter(m => m.method === 'turn/start').length, 1);
  }, 'uncertain');
});
