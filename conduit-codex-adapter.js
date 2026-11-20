'use strict';
const fs = require('fs');
const path = require('path');
const net = require('net');
const WebSocket = require('ws');

// Uses the running daemon, never starts/restarts it, resumes a saved session,
// changes its model/permissions, or writes peer text as a user prompt.
function validateCodexBinding({ socketPath, threadId, address }) {
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(threadId || '')
      || !address.endsWith('-' + threadId) || !path.isAbsolute(socketPath || '')) {
    throw Error('inbox_adapter_binding_invalid');
  }
  let socket, parent;
  try { socket = fs.lstatSync(socketPath); parent = fs.lstatSync(path.dirname(socketPath)); }
  catch { throw Error('inbox_adapter_socket_invalid'); }
  if (!socket.isSocket() || !parent.isDirectory() || socket.uid !== process.getuid()
      || parent.uid !== process.getuid() || (parent.mode & 0o077)) throw Error('inbox_adapter_socket_invalid');
}
async function deliverCodex({ socketPath, threadId, address, notification, timeoutMs = 8000 }) {
  validateCodexBinding({ socketPath, threadId, address });
  let submitted = false, finished = false, nextId = 1;
  const pending = new Map();
  const ws = new WebSocket('ws://localhost/rpc', {
    createConnection: () => net.createConnection(socketPath),
    handshakeTimeout: timeoutMs, perMessageDeflate: false, maxPayload: 1024 * 1024,
  });
  let rejectSession;
  const failure = new Promise((_, reject) => { rejectSession = reject; });
  const fail = () => { if (!finished) rejectSession(Error(submitted ? 'inbox_delivery_uncertain' : 'inbox_adapter_unavailable')); };
  ws.on('error', fail); ws.on('close', fail);
  ws.on('message', raw => {
    let value; try { value = JSON.parse(raw.toString()); } catch { fail(); return; }
    const waiter = pending.get(value.id);
    if (!waiter) return; // Never approve a server permission request.
    pending.delete(value.id);
    if (value.error || !value.result) waiter.reject(Error(submitted ? 'inbox_delivery_uncertain' : 'inbox_adapter_refused'));
    else waiter.resolve(value.result);
  });
  const call = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++; pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }), error => { if (error) fail(); });
  });
  const timer = setTimeout(fail, timeoutMs);
  try {
    return await Promise.race([failure, (async () => {
      await new Promise(resolve => ws.once('open', resolve));
      await call('initialize', { clientInfo: { name: 'conduit-inbox', version: '0.1' }, capabilities: { experimentalApi: true } });
      ws.send(JSON.stringify({ method: 'initialized' }));
      const info = await call('thread/read', { threadId, includeTurns: false });
      if (info.thread?.id !== threadId || info.thread.archived === true) throw Error('inbox_adapter_binding_invalid');
      submitted = true;
      const result = await call('turn/start', {
        threadId, input: [],
        toolOutput: { name: 'conduit_inbox', namespace: 'demipass', output: notification.params.content },
      });
      if (!result.turn || typeof result.turn.id !== 'string') throw Error('inbox_delivery_uncertain');
      return { accepted: true, turnId: result.turn.id };
    })()]);
  } finally { finished = true; clearTimeout(timer); ws.terminate(); }
}

module.exports = { deliverCodex, validateCodexBinding };
