'use strict';
// One JSON request over Node's own http/https — no global fetch, so the package's declared runtime (Node ≥ 14) runs
// every bin (#17 review: fetch and AbortSignal.timeout are missing before Node 18). A redirect is an error, as with
// fetch's redirect: 'error'; past timeoutMs the request is cut and the error is named TimeoutError.
const http = require('http');
const https = require('https');

function requestJson(method, url, { headers = {}, body, timeoutMs = 15000 } = {}) {
  const u = new URL(url);
  const mod = u.protocol === 'https:' ? https : u.protocol === 'http:' ? http : null;
  if (!mod) return Promise.reject(new Error(`unsupported URL: ${u.protocol}`));
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (f, v) => { if (!done) { done = true; clearTimeout(timer); f(v); } };
    const req = mod.request(u, { method, headers: { ...headers, ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}) } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400) { res.resume(); return finish(reject, Object.assign(new Error(`redirected (${res.statusCode}) — not followed`), { name: 'RedirectError', status: res.statusCode })); }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let data; try { data = JSON.parse(text); } catch (_) { data = null; }
        finish(resolve, { status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, text, data });
      });
      res.on('error', (e) => finish(reject, e));
    });
    const timer = setTimeout(() => { const e = new Error('timed out'); e.name = 'TimeoutError'; req.destroy(e); finish(reject, e); }, timeoutMs);
    req.on('error', (e) => finish(reject, e));
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { requestJson };
