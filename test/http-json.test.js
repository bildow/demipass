'use strict';
// node --test test/http-json.test.js — the bins' JSON client on Node's own http (no global fetch: #17 review).
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { requestJson } = require('../http-json');

const srv = http.createServer((req, res) => {
  if (req.url === '/redirect') { res.writeHead(302, { location: 'http://example.invalid/' }); return res.end(); }
  if (req.url === '/slow') return;   // never answers
  let raw = ''; req.on('data', (c) => (raw += c)); req.on('end', () => {
    res.writeHead(req.url === '/err' ? 409 : 201, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ method: req.method, got: raw ? JSON.parse(raw) : null, ct: req.headers['content-type'] || null }));
  });
});
let base;
test.before(() => new Promise((r) => srv.listen(0, '127.0.0.1', () => { base = `http://127.0.0.1:${srv.address().port}`; r(); })));
test.after(() => srv.close());

test('JSON in and out, status kept', async () => {
  const r = await requestJson('POST', base + '/x', { body: { a: 1 } });
  assert.equal(r.status, 201); assert.equal(r.ok, true); assert.deepEqual(r.data, { method: 'POST', got: { a: 1 }, ct: 'application/json' });
  const e = await requestJson('GET', base + '/err');
  assert.equal(e.status, 409); assert.equal(e.ok, false); assert.equal(e.data.got, null);
});
test('a redirect is refused, never followed', async () => {
  await assert.rejects(requestJson('GET', base + '/redirect'), (e) => e.name === 'RedirectError' && e.status === 302);
});
test('past the timeout: TimeoutError (what fleetgate_submit reports as "the door timed out")', async () => {
  await assert.rejects(requestJson('GET', base + '/slow', { timeoutMs: 200 }), (e) => e.name === 'TimeoutError');
});
