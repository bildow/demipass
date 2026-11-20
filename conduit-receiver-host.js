'use strict';
// Embeddable receiver for an agent or web UI backend. onMessage receives peer
// DATA, not a shell command or a user prompt. The host supplies its own policy.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const { readPrivate, writePrivate, digest, eventDigest } = require('./conduit-receiver-profile');
const { credential } = require('./conduit-http-adapter');
function createReceiverHost({ address, wallet, policySha256, credentialFile, directory, onMessage, callbackTimeoutMs = 5000 }) {
  const dir = fs.lstatSync(directory);
  if (!dir.isDirectory() || dir.uid !== process.getuid() || (dir.mode & 0o077)) throw Error('receiver_private_directory_required');
  if (!address || !wallet || !/^[0-9a-f]{64}$/.test(policySha256 || '') || typeof onMessage !== 'function') throw Error('receiver_host_config_invalid');
  if (!Number.isInteger(callbackTimeoutMs) || callbackTimeoutMs < 1 || callbackTimeoutMs > 5000) throw Error('receiver_callback_bound_invalid');
  const identity = { protocol: 'conduit-receiver/1', address, wallet, policy_sha256: policySha256,
    input_authority: 'peer_data', durable_idempotency: true, sealed: false };
  let serial = Promise.resolve();
  const send = (res, status, data) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(data)); };
  return async (req, res) => {
    // Browser cross-origin requests are not accepted by this backend-to-backend API.
    if (req.headers.origin) return send(res, 403, { error: 'origin_refused' });
    let token; try { token = credential(credentialFile); } catch { return send(res, 503, { error: 'credential_unavailable' }); }
    const got = /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization || '')?.[1] || '';
    if (!crypto.timingSafeEqual(crypto.createHash('sha256').update(got).digest(), crypto.createHash('sha256').update(token).digest())) return send(res, 401, { error: 'unauthorized' });
    if (req.method === 'GET' && req.url === '/capabilities') return send(res, 200, identity);
    if (req.method !== 'POST' || req.url !== '/deliver') return send(res, 404, { error: 'not_found' });
    const chunks = []; let bytes = 0;
    try {
      for await (const b of req) { bytes += b.length; if (bytes > 262144) return send(res, 413, { error: 'oversize' }); chunks.push(b); }
      const value = JSON.parse(Buffer.concat(chunks)), m = value.event?.message;
      if (value.protocol !== identity.protocol || value.address !== address || !/^[a-zA-Z0-9_-]{1,128}$/.test(value.message_id || '')
          || m?.id !== value.message_id || value.event?.authority !== 'peer_message_not_operator_instruction'
          || typeof m.body !== 'string' || value.content_sha256 !== eventDigest(value.event)) return send(res, 400, { error: 'invalid_envelope' });
      if (m.payload_type && m.payload_type !== 'text') return send(res, 403, { error: 'sealed_refused' });
      // Serial admission plus exclusive create prevents two instances overwriting the same receipt.
      const work = async () => {
        const file = path.join(directory, digest([address, value.message_id]) + '.json');
        let record;
        try { record = readPrivate(file); }
        catch (e) {
          if (e.code !== 'ENOENT') throw e;
          // The relay retains message history. Host receipts need only bounded
          // identity/hash metadata; persisting the full event exceeded the private
          // receipt reader limit for legitimate large messages on restart.
          const initial = { protocol: identity.protocol, address, message_id: value.message_id,
            content_sha256: value.content_sha256, state: 'uncertain', admitted_at: new Date().toISOString() };
          let fd;
          try {
            fd = fs.openSync(file, 'wx', 0o600); fs.writeFileSync(fd, JSON.stringify(initial)); fs.fsyncSync(fd);
          } catch (e) {
            if (e.code === 'EEXIST') record = readPrivate(file); else throw e;
          } finally { if (fd !== undefined) fs.closeSync(fd); }
          if (!record) {
            const d = fs.openSync(directory, 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); }
            // Persist uncertainty BEFORE invoking a host. An interrupted delivery
            // is never automatically executed again on restart.
            let timer;
            let accepted;
            try { accepted = await Promise.race([Promise.resolve().then(() => onMessage(value.event)),
              new Promise((_, reject) => { timer = setTimeout(() => reject(Error('receiver_callback_timeout')), callbackTimeoutMs); })]); }
            finally { clearTimeout(timer); }
            if (accepted !== true) throw Error('receiver_consumer_did_not_confirm');
            record = { ...initial, state: 'context_received', received_at: new Date().toISOString() };
            writePrivate(file, record);
          }
        }
        if (record.content_sha256 !== value.content_sha256) return send(res, 409, { error: 'idempotency_conflict' });
        if (record.state !== 'context_received') return send(res, 409, { error: 'delivery_uncertain' });
        return send(res, 200, { ...identity, message_id: value.message_id, content_sha256: value.content_sha256,
          scope: 'context_received', received_at: record.received_at });
      };
      const result = serial.then(work); serial = result.catch(() => {}); await result;
    } catch { if (!res.headersSent) send(res, 503, { error: 'receiver_held' }); }
  };
}
module.exports = { createReceiverHost };
