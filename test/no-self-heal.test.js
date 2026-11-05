#!/usr/bin/env node
// Red team item 13: the SDK never creates or widens a scope. A "context not found" refusal comes back as an error and
// no context/add (or any other write) is sent.   node test/no-self-heal.test.js
const http = require('http'); const assert = require('assert'); const demipass = require('../index.js');
(async () => {
  const seen = [];
  const server = http.createServer((req, res) => { let raw = ''; req.on('data', c => raw += c); req.on('end', () => {
    seen.push(req.url); res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: "context 'default' not found for this secret" })); }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  demipass.configure({ baseUrl: `http://127.0.0.1:${server.address().port}`, bearerToken: 'test.token.x' });
  let threw = false;
  try { await demipass.ssh({ ref: 'DP-PWD-x-1', target_host: '192.0.2.1', target_user: 'root', command: 'id' }); } catch (e) { threw = /not found/.test(e.message); }
  server.close();
  try {
    assert.ok(threw, 'the refusal is returned as an error');
    assert.deepEqual(seen.filter(u => !u.includes('request-token')), [], 'no other call (no context/add) was made: ' + JSON.stringify(seen));
    console.log('  ok    a missing scope is refused, the SDK creates none\n\nall ok'); process.exit(0);
  } catch (e) { console.log('  FAIL  ' + e.message); process.exit(1); }
})();
