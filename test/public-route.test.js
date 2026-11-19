'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('node:dns');
const { assertPublicRoute, publicLookup } = require('../public-route');

test('refuse private, tailnet, disguised IP and plaintext remote service endpoints', () => {
  for (const u of ['http://example.com', 'https://phasewhip.taildb5a42.ts.net',
    'https://PHASEWHIP.TAILDB5A42.TS.NET./', 'https://100.83.112.88',
    'https://100.64.0.2', 'https://100.127.255.254', 'https://1683198040',
    'https://0x64537058', 'https://[fd7a:115c:a1e0::1]',
    'https://[::ffff:100.83.112.88]', 'https://10.225.75.1',
    'https://192.168.0.205', 'https://[fec0::1]', 'https://[febf::1]', 'https://[64:ff9b::6453:7058]', 'https://[2002:6453:7058::1]', 'https://198.18.0.1', 'https://phasewhip', 'https://user:pass@example.com']) {
    assert.throws(() => assertPublicRoute(u), { code: 'PRIVATE_SERVICE_ROUTE' }, u);
  }
});
test('public HTTPS and explicit loopback fixtures remain usable', () => {
  for (const u of ['https://conduit.dustroot.com', 'https://repo.dustroot.com/-/fleetgate/door',
    'https://api.dustforge.com', 'http://127.0.0.1:1234', 'http://[::1]:1234'])
    assert.equal(assertPublicRoute(u).href, new URL(u).href);
});
test('connection DNS refuses private answers including mixed answer sets', async () => {
  const original = dns.lookup;
  try {
    for (const addresses of [[{ address: '100.83.112.88', family: 4 }],
      [{ address: '107.173.41.159', family: 4 }, { address: '100.64.0.2', family: 4 }],
      [{ address: 'fd7a:115c:a1e0::1', family: 6 }]]) {
      dns.lookup = (_h, _o, cb) => cb(null, addresses);
      await assert.rejects(new Promise((ok, no) => publicLookup('api.example.com', { all: true }, (e,a) => e ? no(e) : ok(a))), { code: 'PRIVATE_SERVICE_ROUTE' });
    }
    dns.lookup = (_h, _o, cb) => cb(null, '100.83.112.88', 4);
    await assert.rejects(new Promise((ok,no) => publicLookup('localhost', {}, (e,a) => e ? no(e) : ok(a))), { code: 'PRIVATE_SERVICE_ROUTE' });
    dns.lookup = (_h, _o, cb) => cb(null, '107.173.41.159', 4);
    assert.equal(await new Promise((ok,no) => publicLookup('api.example.com', {}, (e,a) => e ? no(e) : ok(a))), '107.173.41.159');
  } finally { dns.lookup = original; }
});
test('actual transport rejects a tailnet URL before a socket is made', async () => {
  const { requestJson } = require('../http-json');
  await assert.rejects(async () => requestJson('GET', 'https://100.83.112.88:8080/health'), { code: 'PRIVATE_SERVICE_ROUTE' });
  const dp = require('../index');
  dp.configure({ baseUrl: 'https://100.64.0.2' });
  await assert.rejects(dp.whoami(), { code: 'PRIVATE_SERVICE_ROUTE' });
});
