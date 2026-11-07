/**
 * demipass/services — DemiPass as the identity and metering layer for an agent service (a "tenant").
 * Zero dependencies. Server side: dustforge `service_tenants.js`, `docs/service-tenants.md`. Guide: docs/services.md.
 *
 *   const { services } = require('demipass');
 *   const dp = services({ token: process.env.DEMIPASS_TENANT_TOKEN });   // the tenant wallet's own token
 *
 *   // the four calls a tenant needs
 *   const who = await dp.verify({ token: callerToken, action: 'post' });            // wallet, token_id, scope, depth
 *   const c   = await dp.charge({ action: 'post', costDd: 2, tokenId: who.token_id, idempotencyKey: msgId });
 *   await dp.delegate({ service: 'conduit', scope: 'post', delegateDid: agentDid });  // caller side (a person)
 *   await dp.revokeDelegation({ delegationId });                                     // caller side
 *
 * Every non-2xx answer throws ServiceError { status, body }: pass status and body on to your caller unchanged (402 =
 * the caller's wallet can't cover it, 401 = bad token, 403 = no authority). verify's 202 (an elevated action waiting on
 * a person's phone) also throws, with err.pending === true and err.body.approval_id.
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const DEFAULT_BASE = 'https://api.dustforge.com';

class ServiceError extends Error {
  constructor(status, body, method, path) {
    super(`${method} ${path}: ${status} ${(body && body.error) || (body && body.status) || ''}`.trim());
    this.name = 'ServiceError';
    this.status = status;
    this.body = body;
    this.pending = status === 202;
  }
}

function call(baseUrl, token, method, path, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(baseUrl + path);
    const t = u.protocol === 'https:' ? https : http;
    const payload = body === undefined ? null : JSON.stringify(body);
    const headers = { Accept: 'application/json', 'X-DemiPass-Agent': 'demipass-sdk/services' };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (payload) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(payload); }
    const req = t.request({ method, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, headers, timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let data; try { data = raw ? JSON.parse(raw) : {}; } catch { data = { error: raw.slice(0, 300) }; }
        if (res.statusCode === 200 || res.statusCode === 201) return resolve(data);
        reject(new ServiceError(res.statusCode, data, method, path));
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => reject(new ServiceError(0, { error: `network: ${e.message}` }, method, path)));
    if (payload) req.write(payload);
    req.end();
  });
}

const opt = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

/**
 * services({ token, baseUrl?, timeoutMs? }) → a client bound to one DemiPass token.
 * A tenant binds its own wallet's token; a caller (or a person delegating) binds theirs.
 */
function services({ token, baseUrl = DEFAULT_BASE, timeoutMs = 15000 } = {}) {
  const req = (method, path, body) => call(baseUrl.replace(/\/+$/, ''), token, method, path, body, timeoutMs);
  const api = {
    // ── tenant side ──────────────────────────────────────────────────────────────────────────────────────────────
    /** 1. verify: is this caller's service token good for `action`? → {wallet, token_id, scope, depth, via, principal?, price, cap_dd, spent_dd} */
    verify({ token: callerToken, action, call: boundCall, approvalId, approvalCode } = {}) {
      if (!callerToken || !action) throw new Error('verify() needs the caller\'s token and an action');
      return req('POST', '/api/services/verify', opt({ token: callerToken, action, call: boundCall, approval_id: approvalId, approval_code: approvalCode }));
    },
    /** 2. charge: bill one call. costDd = this call's measured cost (≤ the action's max_cost_dd); DemiPass adds the margin. */
    charge({ action, costDd, tokenId, idempotencyKey } = {}) {
      if (!action || !tokenId || !idempotencyKey) throw new Error('charge() needs action, tokenId (from verify) and idempotencyKey');
      return req('POST', '/api/services/charge', opt({ action, cost_dd: costDd, token_id: tokenId, idempotency_key: idempotencyKey }));
    },
    /** Your price list: [{action, scope, measured_cost_dd, max_cost_dd?, depth?, open?, retired?}] */
    setActions(slug, actions) { return req('PUT', `/api/services/${encodeURIComponent(slug)}/actions`, { actions }); },
    register({ slug, name, serviceDid } = {}) { return req('POST', '/api/services/register', opt({ slug, name, service_did: serviceDid })); },

    /**
     * verify → charge → work, for a fixed-price call. Charging first means a caller who can't pay gets the 402 before
     * any work is done; the idempotency key makes a retried request free (same key → the first charge, replayed).
     * Throws ServiceError (pass it on). Returns { who, charge, result }.
     */
    async metered({ token: callerToken, action, call: boundCall, approvalId, approvalCode, costDd, idempotencyKey }, work) {
      const who = await api.verify({ token: callerToken, action, call: boundCall, approvalId, approvalCode });
      const charge = await api.charge({ action, costDd, tokenId: who.token_id, idempotencyKey });
      const result = await work(who, charge);
      return { who, charge, result };
    },

    // ── caller side ──────────────────────────────────────────────────────────────────────────────────────────────
    /** A service token for one tenant: send it to the service as `Authorization: Bearer …`. It opens nothing at DemiPass. */
    mintToken({ service, ttl, scopes, capDd } = {}) { return req('POST', '/api/services/token', opt({ service, ttl, scopes, cap_dd: capDd })); },
    revokeToken({ tokenId } = {}) { return req('POST', '/api/services/token/revoke', { token_id: tokenId }); },
    /** 3. delegate: a person lets one of their agents use a service scope (use-only). Another fleet's agent → 403 + PIN intent. */
    delegate({ service, scope, delegateDid, expiresIn } = {}) {
      return req('POST', '/api/services/delegate', opt({ service, scope, delegate_did: delegateDid, expires_in: expiresIn }));
    },
    /** 4. revoke: end a delegation you granted. */
    revokeDelegation({ delegationId } = {}) { return req('POST', `/api/services/delegations/${Number(delegationId)}/revoke`, {}); },
    delegations() { return req('GET', '/api/services/delegations'); },
    charges({ limit } = {}) { return req('GET', `/api/services/charges${limit ? `?limit=${Number(limit)}` : ''}`); },

    // ── public ───────────────────────────────────────────────────────────────────────────────────────────────────
    info(slug) { return req('GET', `/api/services/${encodeURIComponent(slug)}`); },
    list() { return req('GET', '/api/services'); },
    verifyReceiptOnline({ receipt, sig }) { return req('POST', '/api/services/receipts/verify', { receipt, sig }); },
  };
  return api;
}

// ── offline receipt check: Ed25519 over the receipt's UTF-8 bytes, key from its issuer did:key ─────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  let n = 0n; for (const ch of s) { const i = B58.indexOf(ch); if (i < 0) throw new Error('bad base58'); n = n * 58n + BigInt(i); }
  const bytes = []; while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const ch of s) { if (ch !== '1') break; bytes.unshift(0); }
  return Buffer.from(bytes);
}
function ed25519FromDidKey(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(String(did || ''));
  if (!m) throw new Error('issuer must be a did:key (z…)');
  const raw = b58decode(m[1]);
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error('issuer is not an Ed25519 did:key');
  return crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw.subarray(2)]), format: 'der', type: 'spki' });
}
/** verifyReceipt({receipt, sig}, {issuer?}) → {valid, charge}. Pin `issuer` (from GET /api/meter/key) to refuse others. */
function verifyReceipt({ receipt, sig }, { issuer } = {}) {
  let charge; try { charge = JSON.parse(receipt); } catch { return { valid: false, error: 'receipt is not JSON' }; }
  if (issuer && charge.issuer !== issuer) return { valid: false, error: 'issuer is not the pinned one', charge };
  let ok = false;
  try { ok = crypto.verify(null, Buffer.from(receipt, 'utf8'), ed25519FromDidKey(charge.issuer), Buffer.from(sig, 'base64url')); } catch (e) { return { valid: false, error: e.message, charge }; }
  return ok ? { valid: true, charge } : { valid: false, error: 'signature does not verify', charge };
}

module.exports = { services, ServiceError, verifyReceipt };
