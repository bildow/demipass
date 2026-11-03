#!/usr/bin/env node
/**
 * Every SDK request settles: it resolves with the whole response or rejects with
 * the cause. Regression for 2026-11-02: a ~300 kB /use response cut on its way to
 * the client left use() pending forever, and the FLEETGATE reviewer process exited
 * 0 with no output and no error.
 *
 * Local throwaway servers only; no network, no credentials.
 *   node test/request-settles.test.js
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { spawnSync } = require('child_process');
const path = require('path');
const dp = require('../index.js');

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}
const close = (s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); });

// The two-step use(): request-token answers normally, then /use behaves as `useHandler` says.
function demipassStandIn(useHandler) {
  return serve((req, res) => {
    let b = ''; req.on('data', (c) => b += c); req.on('end', () => {
      if (req.url.startsWith('/api/demipass/request-token')) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"use_token":"ut_1"}'); }
      if (req.url.startsWith('/api/demipass/use')) return useHandler(req, res);
      res.writeHead(404); res.end();
    });
  });
}
const callUse = () => dp.use({ ref: 'DP-API-test-0001', action: 'http_header', target_url: 'https://repo.dustroot.com/x.diff', params: { header_prefix: 'token ' } });

test('a response cut mid-body (Content-Length) rejects with ECONNRESET and the byte counts', async () => {
  const { server, base } = await demipassStandIn((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '304587' });
    res.write('{"ok":true,"result":{"body":"' + 'x'.repeat(100000));
    setTimeout(() => res.socket.destroy(), 20);
  });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 5000 });
  try {
    await assert.rejects(callUse(), (e) => e.code === 'ECONNRESET' && /POST \/api\/demipass\/use/.test(e.message) && /of 304587 bytes/.test(e.message));
  } finally { await close(server); }
});

test('a chunked response cut mid-body rejects too', async () => {
  const { server, base } = await demipassStandIn((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });   // no Content-Length: chunked
    res.write('{"ok":true,"result":{"body":"' + 'x'.repeat(200000));
    setTimeout(() => res.socket.destroy(), 20);
  });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 5000 });
  try {
    await assert.rejects(callUse(), (e) => e.code === 'ECONNRESET' && /bytes/.test(e.message));
  } finally { await close(server); }
});

test('a server that never answers rejects on the configured timeout', async () => {
  const { server, base } = await demipassStandIn(() => { /* never responds */ });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 400 });
  const t0 = Date.now();
  try {
    await assert.rejects(callUse(), (e) => e.code === 'ETIMEDOUT' && /within 400 ms/.test(e.message));
    assert.ok(Date.now() - t0 < 3000);
  } finally { await close(server); }
});

test('a server that sends headers then stalls also times out (the timer covers the whole response)', async () => {
  const { server, base } = await demipassStandIn((req, res) => { res.writeHead(200, { 'content-length': '1000' }); res.write('{"ok":'); });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 400 });
  try {
    await assert.rejects(callUse(), (e) => e.code === 'ETIMEDOUT' && /6 bytes received/.test(e.message));
  } finally { await close(server); }
});

test('nothing listening: rejects with the socket error', async () => {
  const { server, base } = await serve(() => {});
  await close(server);                                   // port now closed
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 5000 });
  await assert.rejects(callUse(), (e) => e.code === 'ECONNREFUSED' && /network error/.test(e.message));
});

test('an HTTP error carries the status and the server message', async () => {
  const msg = 'upstream response too large: it declares 3000000 bytes, over the 2097152-byte (2 MiB) limit for /use';
  const { server, base } = await demipassStandIn((req, res) => { res.writeHead(413, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: msg, limit_bytes: 2097152 })); });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 5000 });
  try {
    await assert.rejects(callUse(), (e) => e.status === 413 && e.message === `POST /api/demipass/use failed: HTTP 413: ${msg}` && e.data.limit_bytes === 2097152);
  } finally { await close(server); }
});

test('a non-JSON error page still names the status', async () => {
  const { server, base } = await demipassStandIn((req, res) => { res.writeHead(502, { 'content-type': 'text/html' }); res.end('<html>502 Bad Gateway</html>'); });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 5000 });
  try {
    await assert.rejects(callUse(), (e) => e.status === 502 && /HTTP 502: <html>502 Bad Gateway/.test(e.message));
  } finally { await close(server); }
});

test('a 2 MiB response arrives whole', async () => {
  const body = 'd'.repeat(2 * 1024 * 1024);
  const { server, base } = await demipassStandIn((req, res) => {
    const out = JSON.stringify({ ok: true, result: { status: 200, body } });
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out) }); res.end(out);
  });
  dp.configure({ baseUrl: base, bearerToken: 't', timeoutMs: 5000 });
  try {
    const r = await callUse();
    assert.equal(r.result.body.length, body.length);
  } finally { await close(server); }
});

test('timeoutMs must be positive', () => {
  assert.throws(() => dp.configure({ timeoutMs: 0 }), /positive/);
});

test('the original symptom: a process awaiting a cut response now fails loudly instead of exiting 0 in silence', async () => {
  const { server, base } = await demipassStandIn((req, res) => {
    res.writeHead(200, { 'content-length': '304587' }); res.write('{"ok":true'); setTimeout(() => res.socket.destroy(), 20);
  });
  try {
    // Same shape as FLEETGATE review.js: top-level await on use(), no catch, nothing else keeping the loop alive.
    const script = `const dp = require(${JSON.stringify(path.join(__dirname, '..', 'index.js'))});
      dp.configure({ baseUrl: ${JSON.stringify(base)}, bearerToken: 't' });
      (async () => { const r = await dp.use({ ref: 'DP-API-test-0001', action: 'http_header', target_url: 'https://repo.dustroot.com/x.diff' }); console.log('resolved', typeof r); })();`;
    const child = await new Promise((resolve) => {
      const { spawn } = require('child_process');
      const p = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '', err = '';
      p.stdout.on('data', (c) => out += c); p.stderr.on('data', (c) => err += c);
      p.on('exit', (code) => resolve({ code, out, err }));
    });
    assert.notEqual(child.code, 0, `child exited 0 — stdout: ${child.out} stderr: ${child.err}`);
    assert.match(child.err, /ECONNRESET|connection closed|aborted/);
  } finally { await close(server); }
});

test('HEAD and 304 replies that declare a Content-Length and send no body resolve', async () => {
  const { server, base } = await serve((req, res) => {
    if (req.method === 'HEAD') { res.writeHead(200, { 'content-length': '5000' }); return res.end(); }
    res.writeHead(304, { 'content-length': '5000' }); res.end();
  });
  try {
    const { request } = require('../http-request');
    const u = new URL(base);
    for (const method of ['HEAD', 'GET']) {
      const r = await request(http, { method, hostname: u.hostname, port: u.port, path: '/' }, null, { timeoutMs: 2000 });
      assert.equal(r.body.length, 0);
    }
  } finally { await close(server); }
});
