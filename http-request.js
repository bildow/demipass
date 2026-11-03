/**
 * One HTTP request that always settles: it resolves with the whole response or
 * rejects with an error naming the cause. Used by every raw request the SDK and
 * the MCP servers make.
 *
 * Listening only for a response's 'end' is not enough. A connection cut
 * mid-response (by a proxy, a sandbox, a network switch) emits 'aborted' and
 * 'close' but no 'end', and an idle-socket timeout never fires on a socket that
 * is already gone, so the promise stayed pending forever. A process with nothing
 * else to wait for then exited 0 without a word.
 *
 *   request(transport, opts, payload, { timeoutMs, label })
 *     → Promise<{ status, headers, body: Buffer }>
 * Rejections carry .code: ETIMEDOUT (no complete response in timeoutMs),
 * ECONNRESET (cut before the end), or the socket's own code (ECONNREFUSED, …).
 */
function request(transport, opts, payload, { timeoutMs, label } = {}) {
  const what = label || `${opts.method || 'GET'} ${opts.path || '/'}`;
  return new Promise((resolve, reject) => {
    let settled = false, received = 0, timer = null, req = null;
    const fail = (msg, code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (req) req.destroy();
      reject(Object.assign(new Error(`${what}: ${msg}`), { code }));
    };
    req = transport.request(opts, (res) => {
      const chunks = [];
      const declared = Number(res.headers['content-length']);
      const of = Number.isFinite(declared) ? `of ${declared} ` : '';
      res.on('data', (c) => { chunks.push(c); received += c.length; });
      res.on('end', () => {
        if (settled) return;
        if (!res.complete || (Number.isFinite(declared) && received !== declared)) {
          return fail(`connection closed after ${received} ${of}bytes (HTTP ${res.statusCode})`, 'ECONNRESET');
        }
        settled = true; clearTimeout(timer);
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
      res.on('aborted', () => fail(`response aborted after ${received} ${of}bytes (HTTP ${res.statusCode})`, 'ECONNRESET'));
      res.on('error', (err) => fail(`response failed after ${received} ${of}bytes: ${err.message}`, err.code || 'ECONNRESET'));
      res.on('close', () => fail(`connection closed after ${received} ${of}bytes, before the response ended (HTTP ${res.statusCode})`, 'ECONNRESET'));
    });
    if (timeoutMs > 0) {
      timer = setTimeout(() => fail(`no complete response within ${timeoutMs} ms (${received} bytes received)`, 'ETIMEDOUT'), timeoutMs);
    }
    req.on('error', (err) => fail(`network error: ${err.message}`, err.code));
    req.on('close', () => { if (!req.res) fail('connection closed before any response', 'ECONNRESET'); });
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { request };
