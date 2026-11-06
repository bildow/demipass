#!/usr/bin/env node
// A use token is for one target, checked against the owner's scope when it is issued (dustforge #43): use() puts the
// target in the token request — from target_url/target_host, or from params.url / params.repo_url / params.smtp_host.
//   node test/use-target.test.js
const http = require('http'); const assert = require('assert'); const demipass = require('../index.js');
(async () => {
  const asked = [];
  const server = http.createServer((req, res) => { let raw = ''; req.on('data', c => raw += c); req.on('end', () => {
    const body = raw ? JSON.parse(raw) : {};
    if (req.url.endsWith('/request-token')) { asked.push(body); res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ use_token: 't' + asked.length })); }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}'); }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  demipass.configure({ baseUrl: `http://127.0.0.1:${server.address().port}`, bearerToken: 'test.token.x' });
  await demipass.use({ ref: 'DP-API-a-1', action: 'http_header', params: { url: 'https://api.github.com/x' } });
  await demipass.use({ ref: 'DP-API-a-1', action: 'git_clone', params: { repo_url: 'https://github.com/bildow/x' } });
  await demipass.use({ ref: 'DP-PWD-m-1', action: 'smtp_auth', params: { smtp_host: 'smtp.gmail.com', to: 'a@b', subject: 's' } });
  await demipass.use({ ref: 'DP-API-a-1', action: 'http_header', target_url: 'https://api.github.com/explicit', params: { url: 'https://api.github.com/other' } });
  server.close();
  try {
    assert.equal(asked[0].target_url, 'https://api.github.com/x', 'params.url → target_url');
    assert.equal(asked[1].target_url, 'https://github.com/bildow/x', 'params.repo_url → target_url');
    assert.equal(asked[2].target_host, 'smtp.gmail.com', 'params.smtp_host → target_host');
    assert.equal(asked[3].target_url, 'https://api.github.com/explicit', 'an explicit target_url wins');
    console.log('  ok    use() asks for a token bound to the call\'s target (url, repo_url, smtp_host)\n\nall ok'); process.exit(0);
  } catch (e) { console.log('  FAIL  ' + e.message + ' ' + JSON.stringify(asked)); process.exit(1); }
})();
