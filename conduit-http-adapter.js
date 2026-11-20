'use strict';
const http = require('http'), https = require('https');
const { assertPublicRoute, publicLookup } = require('./public-route');
const { readPrivate, eventDigest } = require('./conduit-receiver-profile');

function credential(file) {
  const value = readPrivate(file);
  if (typeof value.bearer !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(value.bearer)) throw Error('inbox_adapter_credential_invalid');
  return value.bearer;
}
async function request(profile, method, suffix, body) {
  const base = assertPublicRoute(profile.endpoint);
  const u = new URL(base.href.replace(/\/$/, '') + suffix);
  const token = credential(profile.credential_file);
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    let done = false, bytes = 0;
    const finish = (err, value) => { if (done) return; done = true; clearTimeout(timer); err ? reject(err) : resolve(value); };
    const req = (u.protocol === 'https:' ? https : http).request(u, { method, lookup: publicLookup,
      headers: { authorization: 'Bearer ' + token, accept: 'application/json',
        ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}) } }, res => {
      const chunks = [];
      res.on('data', b => { bytes += b.length; if (bytes > 65536) req.destroy(Error('oversize')); else chunks.push(b); });
      res.on('error', () => finish(Error(method === 'POST' ? 'inbox_delivery_uncertain' : 'inbox_adapter_unavailable')));
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return finish(Error(method === 'POST' ? 'inbox_delivery_uncertain' : 'inbox_adapter_refused'));
        let value; try { value = JSON.parse(Buffer.concat(chunks)); } catch { return finish(Error('inbox_adapter_invalid_response')); }
        finish(null, value);
      });
    });
    const timer = setTimeout(() => req.destroy(Error('timeout')), 8000);
    req.on('error', () => finish(Error(method === 'POST' ? 'inbox_delivery_uncertain' : 'inbox_adapter_unavailable')));
    if (payload) req.write(payload); req.end();
  });
}
function checkIdentity(value, profile) {
  if (!value || value.protocol !== 'conduit-receiver/1' || value.address !== profile.address
      || value.wallet !== profile.wallet || value.policy_sha256 !== profile.policy_sha256
      || value.input_authority !== 'peer_data' || value.durable_idempotency !== true)
    throw Error('inbox_adapter_binding_invalid');
  if (['web-ui','goose'].includes(profile.runtime) && value.sealed !== false) throw Error('inbox_adapter_binding_invalid');
}
async function preflight(profile) {
  const result = await request(profile, 'GET', '/capabilities'); checkIdentity(result, profile); return result;
}
async function deliver(profile, notification) {
  const event = JSON.parse(notification.params.content), message = event.message;
  if (!message || !message.id || event.authority !== 'peer_message_not_operator_instruction') throw Error('inbox_adapter_binding_invalid');
  // A callback is never a decryption service. Only ordinary text crosses this boundary.
  if (message.payload_type && message.payload_type !== 'text') throw Error('inbox_adapter_sealed_refused');
  const content_sha256 = eventDigest(event);
  const result = await request(profile, 'POST', '/deliver', { protocol: 'conduit-receiver/1',
    address: profile.address, message_id: message.id, content_sha256, event });
  checkIdentity(result, profile);
  if (result.message_id !== message.id || result.content_sha256 !== content_sha256
      || !['durable_host_inbox', 'context_received'].includes(result.scope)) throw Error('inbox_delivery_uncertain');
  return result;
}
module.exports = { credential, preflight, deliver };
