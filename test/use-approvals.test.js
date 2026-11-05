#!/usr/bin/env node
// use() on an elevated/critical secret: the 202 approval_pending reply comes back as data (no throw, no retry), and
// approval_id / approval_code / purpose reach /use top-level, outside `params` (the server leaves them out of what an
// approval binds). Throwaway local server; no network.   node test/use-approvals.test.js
const http = require('http');
const assert = require('assert');
const demipass = require('../index.js');
let failures = 0;
const check = (n, fn) => { try { fn(); console.log(`  ok    ${n}`); } catch (e) { failures++; console.log(`  FAIL  ${n}\n        ${e.message}`); } };
(async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = ''; req.on('data', c => (raw += c)); req.on('end', () => {
      const body = JSON.parse(raw || '{}'); seen.push({ path: req.url, body });
      if (req.url.includes('request-token')) { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ use_token: 'tok', expires_in_seconds: 30 })); }
      if (!body.approval_id) { res.writeHead(202, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ ok: false, status: 'approval_pending', approval_id: 7, next: 'Park this task.' })); }
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true, result: { stdout: 'web1\n', exit_code: 0 } }));
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  demipass.configure({ baseUrl: `http://127.0.0.1:${server.address().port}`, bearerToken: 'test.token.x' });
  const first = await demipass.ssh({ ref: 'DP-PWD-x-1', target_host: '192.0.2.1', target_user: 'root', command: 'hostname', purpose: 'check the box' });
  check('a parked call returns approval_pending as data, not an error', () => { assert.equal(first.status, 'approval_pending'); assert.equal(first.approval_id, 7); });
  check('exactly one /use was sent for it (no retry loop)', () => assert.equal(seen.filter(s => s.path.endsWith('/use')).length, 1));
  check('purpose goes top-level', () => assert.equal(seen.at(-1).body.purpose, 'check the box'));
  const second = await demipass.ssh({ ref: 'DP-PWD-x-1', target_host: '192.0.2.1', target_user: 'root', command: 'hostname', approval_id: 7, approval_code: 123456 });
  const b = seen.at(-1).body;
  check('the resumed call acts', () => assert.equal(second.result.stdout, 'web1\n'));
  check('approval_id and approval_code (as a string) go top-level, not in params', () => {
    assert.equal(b.approval_id, 7); assert.equal(b.approval_code, '123456');
    assert.equal(b.params.approval_id, undefined); assert.equal(b.params.approval_code, undefined);
  });
  check('the command is unchanged between the two calls (the approval binds it)', () => assert.equal(b.command, 'hostname'));
  server.close();
  console.log(failures ? `\n${failures} FAILED` : '\nall ok');
  process.exit(failures ? 1 : 0);
})();
