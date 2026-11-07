#!/usr/bin/env node
/**
 * services.js: the request each call sends, ServiceError on non-2xx (402/202 kept with their body), metered() order
 * (verify → charge → work; no work after a 402), and offline receipt verification from the issuer did:key.
 * Local HTTP stand-in only.   node test/services.test.js
 */
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');
const { services, ServiceError, verifyReceipt } = require('../services.js');

let failures = 0;
const check = async (name, fn) => { try { await fn(); console.log(`  ok    ${name}`); } catch (e) { failures++; console.log(`  FAIL  ${name}\n        ${e.message}`); } };

const seen = []; let next = [];
const srv = http.createServer((req, res) => {
  let raw = ''; req.on('data', c => (raw += c)); req.on('end', () => {
    seen.push({ method: req.method, path: req.url, auth: req.headers.authorization, body: raw ? JSON.parse(raw) : null });
    const [status, body] = next.shift() || [200, { ok: true }];
    res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body));
  });
});

// A did:key for an Ed25519 key, as the server makes it (multicodec 0xed01, base58btc, 'z').
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(buf) { let n = BigInt('0x' + buf.toString('hex')); let s = ''; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } for (const b of buf) { if (b) break; s = '1' + s; } return s; }

srv.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${srv.address().port}`;
  const dp = services({ token: 'tenant-tok', baseUrl: base });

  await check('verify posts the caller token and action with the tenant bearer', async () => {
    next = [[200, { ok: true, wallet: 'did:key:zA', token_id: 'ab12cd34' }]];
    const w = await dp.verify({ token: 'caller', action: 'post', call: { a: 1 }, approvalId: 7 });
    const r = seen.pop();
    assert.strictEqual(r.path, '/api/services/verify'); assert.strictEqual(r.auth, 'Bearer tenant-tok');
    assert.deepStrictEqual(r.body, { token: 'caller', action: 'post', call: { a: 1 }, approval_id: 7 });
    assert.strictEqual(w.token_id, 'ab12cd34');
  });
  await check('charge sends snake_case fields', async () => {
    next = [[201, { ok: true, charge_id: 'sc_1' }]];
    await dp.charge({ action: 'post', costDd: 2, tokenId: 'ab12cd34', idempotencyKey: 'msg:1' });
    assert.deepStrictEqual(seen.pop().body, { action: 'post', cost_dd: 2, token_id: 'ab12cd34', idempotency_key: 'msg:1' });
  });
  await check('a 402 throws ServiceError with status and body (pass it on)', async () => {
    next = [[402, { error: 'the caller\'s wallet cannot cover this call', required_dd: 3 }]];
    await assert.rejects(dp.charge({ action: 'post', costDd: 2, tokenId: 'ab12cd34', idempotencyKey: 'msg:2' }),
      e => e instanceof ServiceError && e.status === 402 && e.body.required_dd === 3);
  });
  await check('a 202 from verify throws with pending + approval_id', async () => {
    next = [[202, { ok: false, status: 'approval_pending', approval_id: 41 }]];
    await assert.rejects(dp.verify({ token: 'c', action: 'broadcast' }), e => e.pending === true && e.body.approval_id === 41);
  });
  await check('metered: verify → charge → work; a 402 stops before the work', async () => {
    let worked = 0;
    next = [[200, { token_id: 'ab12cd34', wallet: 'did:key:zA' }], [201, { charge_id: 'sc_2' }]];
    const out = await dp.metered({ token: 'c', action: 'post', costDd: 2, idempotencyKey: 'msg:3' }, async () => { worked++; return 'posted'; });
    assert.strictEqual(out.result, 'posted'); assert.strictEqual(worked, 1);
    assert.deepStrictEqual(seen.slice(-2).map(r => r.path), ['/api/services/verify', '/api/services/charge']);
    next = [[200, { token_id: 'ab12cd34' }], [402, { error: 'no' }]];
    await assert.rejects(dp.metered({ token: 'c', action: 'post', costDd: 2, idempotencyKey: 'msg:4' }, async () => { worked++; }), e => e.status === 402);
    assert.strictEqual(worked, 1);
  });
  await check('caller side: mintToken, delegate, revokeDelegation, revokeToken', async () => {
    const me = services({ token: 'person', baseUrl: base });
    next = [[201, {}], [201, {}], [200, {}], [200, {}]];
    await me.mintToken({ service: 'conduit', ttl: '1h', capDd: 200 });
    await me.delegate({ service: 'conduit', scope: 'post', delegateDid: 'did:key:zAg' });
    await me.revokeDelegation({ delegationId: 9 });
    await me.revokeToken({ tokenId: 'ab12cd34' });
    const last = seen.slice(-4);
    assert.deepStrictEqual(last.map(r => r.path), ['/api/services/token', '/api/services/delegate', '/api/services/delegations/9/revoke', '/api/services/token/revoke']);
    assert.deepStrictEqual(last[0].body, { service: 'conduit', ttl: '1h', cap_dd: 200 });
    assert.deepStrictEqual(last[1].body, { service: 'conduit', scope: 'post', delegate_did: 'did:key:zAg' });
  });
  await check('verifyReceipt: valid from the issuer did:key; tamper and wrong pin refused', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const issuer = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
    const receipt = JSON.stringify({ v: 1, type: 'dustforge_service_charge', charge_id: 'sc_x', issuer, dd: 3, token_id: 'ab12cd34' });
    const sig = crypto.sign(null, Buffer.from(receipt), privateKey).toString('base64url');
    assert.strictEqual(verifyReceipt({ receipt, sig }, { issuer }).valid, true);
    assert.strictEqual(verifyReceipt({ receipt: receipt.replace('"dd":3', '"dd":1'), sig }).valid, false);
    assert.strictEqual(verifyReceipt({ receipt, sig }, { issuer: 'did:key:zOther' }).valid, false);
  });
  srv.close();
  console.log(failures ? `${failures} failure(s)` : 'all ok');
  process.exit(failures ? 1 : 0);
});
