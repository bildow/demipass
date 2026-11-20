'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertPublicRoute } = require('./public-route');
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const KINDS = Object.freeze({
  claude: { transport: 'claude-channel', needs: 'Enable server:demipass as a Claude channel, then reconnect the reviewed MCP release.' },
  codex: { transport: 'codex-tool-output', needs: 'A running, private Codex daemon socket and the exact loaded thread.' },
  agent: { transport: 'receiver-http', needs: 'An authenticated receiver implementing Conduit receiver/v1 and a data-only inbound policy.' },
  goose: { transport: 'receiver-http', needs: 'A Goose host integration implementing receiver/v1. MCP tool installation alone does not wake Goose.' },
  'web-ui': { transport: 'receiver-http', needs: 'An authenticated backend implementing receiver/v1; the browser consumes data, never raw HTML or operator instructions.' },
  'web-seat': { transport: 'remote-mcp', needs: 'One public HTTPS connector and bearer credential per seat. Pull-only unless the host separately supports inbound events.' },
});
function digest(value) { return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
// Receipt fields may change after a read/ack. Bind every immutable message field,
// but never confuse changing delivery bookkeeping with a different message.
function eventDigest(event) {
  const message = { ...event.message };
  for (const k of ['state','read_at','acked_at','delivered_at','forwarded_to','buoy','refused_reason']) delete message[k];
  return digest({ source: event.source, authority: event.authority, message });
}
function fileFor(config) {
  if (!config.file_present || !config.name || !config.wallet || !config.pane_address || config.name !== config.pane_address)
    throw Error('receiver_pane_onboarding_required');
  return config.file + '.receiver.json';
}
function readPrivate(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o077) || st.size > 65536) throw Error('receiver_private_file_required');
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
}
function writePrivate(file, value) {
  const parent = path.dirname(file), st = fs.lstatSync(parent);
  if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o022)) throw Error('receiver_private_parent_required');
  const tmp = path.join(parent, '.receiver-' + crypto.randomBytes(12).toString('hex'));
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600); fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd); fs.closeSync(fd); fd = null;
    fs.renameSync(tmp, file);
    const dir = fs.openSync(parent, 'r'); try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally { if (fd !== null && fd !== undefined) fs.closeSync(fd); try { fs.unlinkSync(tmp); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
}
function validate(profile, config) {
  if (!profile || profile.version !== 1 || !KINDS[profile.runtime] || profile.address !== config.name
      || profile.wallet !== config.wallet || profile.relay !== config.url) throw Error('receiver_profile_binding_invalid');
  const fields = new Set(['version','runtime','address','wallet','relay','thread_id','socket','endpoint','credential_file','policy_sha256','public_endpoint','enabled','created_at','driver']);
  if (Object.keys(profile).some(k => !fields.has(k))) throw Error('receiver_profile_field_invalid');
  assertPublicRoute(profile.relay);
  const driver = profile.driver || (profile.runtime === 'claude' ? 'mcp' : 'standalone');
  if (!['mcp','standalone'].includes(driver) || profile.runtime === 'claude' && driver !== 'mcp') throw Error('receiver_driver_invalid');
  if (profile.enabled !== true && profile.enabled !== false) throw Error('receiver_profile_enabled_invalid');
  if (profile.runtime === 'codex') {
    if (!UUID.test(profile.thread_id || '') || !profile.address.endsWith('-' + profile.thread_id)
        || !path.isAbsolute(profile.socket || '')) throw Error('receiver_codex_binding_invalid');
  }
  if (['agent', 'goose', 'web-ui'].includes(profile.runtime)) {
    const u = assertPublicRoute(profile.endpoint);
    if (u.hash || u.search || !path.isAbsolute(profile.credential_file || '') || !/^[0-9a-f]{64}$/.test(profile.policy_sha256 || ''))
      throw Error('receiver_http_binding_invalid');
  }
  if (profile.runtime === 'web-seat') {
    const u = assertPublicRoute(profile.public_endpoint);
    if (u.protocol !== 'https:' || require('./public-route').privateAddress(u.hostname) || u.hostname === 'localhost'
        || u.hash || u.search || !path.isAbsolute(profile.credential_file || '')) throw Error('receiver_web_binding_invalid');
    if (profile.enabled) throw Error('receiver_web_seat_has_no_push_contract');
  }
  return profile;
}
function load(config) {
  const file = fileFor(config);
  try { return validate(readPrivate(file), config); }
  catch (e) { if (e.code === 'ENOENT') return null; throw Error('receiver_profile_unreadable_or_invalid'); }
}
function provision(config, options) {
  const file = fileFor(config);
  const allowed = new Set(['runtime','thread_id','socket','endpoint','credential_file','policy_sha256','public_endpoint','enabled','driver']);
  if (!options || Object.keys(options).some(k => !allowed.has(k))) throw Error('receiver_provision_options_invalid');
  options = { ...options };
  if (['agent','goose','web-ui','web-seat'].includes(options.runtime) && !options.credential_file) {
    options.credential_file = file + '.credential.json';
  }
  const profile = validate({ ...options, version: 1, address: config.name, wallet: config.wallet, relay: config.url,
    enabled: options.enabled === true, created_at: new Date().toISOString() }, config);
  if (profile.credential_file) {
    try { require('./conduit-http-adapter').credential(profile.credential_file); }
    catch (e) {
      if (e.code !== 'ENOENT' || options.credential_file !== file + '.credential.json') throw e;
      const fd = fs.openSync(profile.credential_file, 'wx', 0o600);
      try { fs.writeFileSync(fd, JSON.stringify({ bearer: crypto.randomBytes(32).toString('base64url') }) + '\n'); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
    }
  }
  let prior; try { prior = readPrivate(file); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (prior) {
    const a = { ...prior }, b = { ...profile }; delete a.created_at; delete b.created_at;
    if (digest(a) === digest(b)) return status(config);
  }
  writePrivate(file, profile);
  return status(config);
}
function status(config) {
  let profile;
  try { profile = load(config); }
  catch { return { state: 'held', reason: 'receiver_profile_unreadable_or_unbound', reception_verified: false }; }
  if (!profile) return { state: 'not_configured', reception_verified: false, supported_runtimes: Object.keys(KINDS) };
  return { state: profile.enabled ? 'configured_not_verified' : 'disabled', runtime: profile.runtime,
    transport: KINDS[profile.runtime].transport, driver: profile.driver || (profile.runtime === 'claude' ? 'mcp' : 'standalone'), profile_file: fileFor(config), profile_sha256: digest(profile),
    reception_verified: false, next: KINDS[profile.runtime].needs,
    ...(profile.credential_file ? { credential_file: profile.credential_file } : {}),
    ...(profile.runtime === 'web-seat' ? { automatic_reception: false, content_class: 'unsealed_only' } : {}) };
}
module.exports = { KINDS, digest, eventDigest, fileFor, readPrivate, writePrivate, validate, load, provision, status };
