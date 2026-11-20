'use strict';
const fs = require('fs'), path = require('path');
const profiles = require('./conduit-receiver-profile');
const { InboxListener } = require('./conduit-listener');
const codex = require('./conduit-codex-adapter');
const httpAdapter = require('./conduit-http-adapter');
async function validateRecipient(sdk, message, config, directory = () => sdk.conduitAgents()) {
  if (message.to === config.name) return true;
  // Inherited backlog is admitted only through authenticated route lineage,
  // never through message-supplied addressed_to or display names.
  if (!message.to || !sdk.conduitAgents) return false;
  const response = await directory();
  const rows = Array.isArray(response) ? response : response?.agents;
  if (!Array.isArray(rows)) return false;
  const row = rows.find(r => r.name === config.name);
  return row?.route?.current === config.name && Array.isArray(row.route.addresses)
    && row.route.addresses.includes(message.to);
}

// Retain admission uncertainty across MCP/daemon restarts. Only a known
// pre-submission failure is retryable; no restart blindly re-dispatches work.
async function durableDelivery(config, profile, notification, send) {
  const event = JSON.parse(notification.params.content), id = event.message.id;
  const dir = profiles.fileFor(config) + '.deliveries';
  try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o077)) throw Error('inbox_delivery_uncertain');
  const file = path.join(dir, profiles.digest([config.name, id]) + '.json');
  const hash = profiles.eventDigest(event);
  let existing;
  try { existing = profiles.readPrivate(file); } catch (e) { if (e.code !== 'ENOENT') throw Error('inbox_delivery_uncertain'); }
  if (existing) {
    if (existing.profile_sha256 !== profiles.digest(profile) || existing.content_sha256 !== hash) throw Error('inbox_delivery_uncertain');
    if (existing.state === 'accepted' || existing.state === 'refused') return existing.result;
    throw Error('inbox_delivery_uncertain');
  }
  // Exclusive creation acts as cross-process admission; an incomplete record
  // after a crash is unreadable and therefore holds.
  const refused = ['agent','goose','web-ui'].includes(profile.runtime)
    && event.message.payload_type && event.message.payload_type !== 'text';
  const refusal = { scope: 'refused_not_submitted', reason: 'sealed_content_not_supported', message_id: id };
  let fd;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify({ profile_sha256: profiles.digest(profile), state: refused ? 'refused' : 'uncertain',
      ...(refused ? { result: refusal } : {}), message_id: id, content_sha256: hash, at: new Date().toISOString() }));
    fs.fsyncSync(fd);
  } catch { throw Error('inbox_delivery_uncertain'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
  const d = fs.openSync(dir, 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); }
  if (refused) return refusal; // No host submission and no acknowledgment; later mail can proceed.
  try {
    const result = await send();
    profiles.writePrivate(file, { profile_sha256: profiles.digest(profile), state: 'accepted', message_id: id, content_sha256: hash, result, at: new Date().toISOString() });
    return result;
  } catch (e) {
    // Keep every failed admission held, including refusal. Reconciliation can
    // distinguish a retryable refusal without guessing after process death.
    throw Error('inbox_delivery_uncertain');
  }
}

function createRuntime({ sdk, profile, notifyClaude, onError = () => {} }) {
  const config = sdk.conduitConfig(); profiles.validate(profile, config);
  if (!profile.enabled) throw Error('receiver_disabled');
  if (profile.runtime === 'web-seat') throw Error('receiver_web_seat_has_no_push_contract');
  const pinned = profiles.digest(profile);
  let directoryPromise;
  const current = () => {
    const cfg = sdk.conduitConfig(), now = profiles.load(cfg);
    if (!now || profiles.digest(now) !== pinned) throw Error('inbox_binding_changed');
    return cfg;
  };
  const listener = new InboxListener({
    config: current,
    validateRecipient: (message, cfg) => validateRecipient(sdk, message, cfg,
      () => directoryPromise ||= sdk.conduitAgents()),
    beforePoll: async () => {
      directoryPromise = null;
      current();
      if (profile.runtime === 'claude') { if (!notifyClaude) throw Error('inbox_adapter_binding_invalid'); }
      else if (profile.runtime === 'codex') codex.validateCodexBinding({ socketPath: profile.socket, threadId: profile.thread_id, address: profile.address });
      else await httpAdapter.preflight(profile);
    },
    inbox: args => sdk.conduitInbox(args),
    notify: async notification => {
      const cfg = current();
      if (profile.runtime === 'claude') return notifyClaude(notification);
      return durableDelivery(cfg, profile, notification, async () => {
        current();
        return profile.runtime === 'codex'
          ? codex.deliverCodex({ socketPath: profile.socket, threadId: profile.thread_id, address: profile.address, notification })
          : httpAdapter.deliver(profile, notification);
      });
    }, onError,
  });
  return listener;
}
module.exports = { createRuntime, durableDelivery, validateRecipient };
