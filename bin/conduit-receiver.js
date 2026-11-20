#!/usr/bin/env node
'use strict';
// Operator-side provisioning. No shell interpolation, token output or automatic
// provider process creation. Reuses the pane's already-approved Conduit identity.
const fs = require('fs');
const path = require('path');
const profiles = require('../conduit-receiver-profile');
async function main(argv) {
  const [command, ...rest] = argv;
  const args = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!/^--[a-z-]+$/.test(rest[i]) || !rest[i + 1] || rest[i + 1].startsWith('--')) throw Error('receiver_arguments_invalid');
    args[rest[i].slice(2).replace(/-/g, '_')] = rest[i + 1];
  }
  const allowed = new Set(['family','session','config','runtime','socket','thread_id','endpoint','credential_file','policy_sha256','public_endpoint','enabled','listen_port','recipients_file','driver']);
  if (Object.keys(args).some(k => !allowed.has(k))) throw Error('receiver_arguments_invalid');
  // These discovery commands must work before onboarding: never load SDK,
  // credentials, profiles, or a host process, and never authorize activation.
  if (command === 'catalog') {
    if (Object.keys(args).length) throw Error('receiver_arguments_invalid');
    return require('../conduit-runtime-catalog').catalog();
  }
  if (command === 'plan') {
    if (Object.keys(args).some(k => k !== 'runtime')) throw Error('receiver_arguments_invalid');
    return require('../conduit-runtime-catalog').plan(args.runtime);
  }
  if (!args.family || !args.session) throw Error('receiver_family_and_full_session_required');
  process.env.CONDUIT_MODEL_FAMILY = args.family; process.env.CONDUIT_SESSION_ID = args.session;
  process.env.CONDUIT_REQUIRE_PANE = '1';
  delete process.env.CONDUIT_AUTOBIND; delete process.env.CONDUIT_SESSION_NAME; delete process.env.CONDUIT_SESSION_NAME_SOURCE;
  if (args.config) process.env.CONDUIT_CONFIG = path.resolve(args.config);
  const sdk = require('../index');
  const bearerToken = require('../onboard').sessionToken();
  sdk.configure({ baseUrl: process.env.DEMIPASS_URL || 'https://api.dustforge.com', bearerToken });
  const config = sdk.conduitConfig();
  if (command === 'status') return profiles.status(config);
  if (command === 'serve-seat') {
    const profile = profiles.load(config), port = Number(args.listen_port);
    if (!Number.isInteger(port) || port < 1024 || port > 65535 || !args.recipients_file) throw Error('seat_listen_config_required');
    const peers = profiles.readPrivate(path.resolve(args.recipients_file));
    const handler = require('../conduit-seat-server').createSeatHandler({ sdk, profile, recipients: peers.recipients });
    const server = require('http').createServer(handler); server.requestTimeout = 10000; server.headersTimeout = 10000;
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
    console.log(JSON.stringify({ state: 'seat_tools_listening', bind: '127.0.0.1', port, public_endpoint: profile.public_endpoint,
      address: profile.address, automatic_push: false, public_reachability_verified: false }));
    return null;
  }
  if (command === 'configure') {
    const options = {};
    for (const k of ['runtime','socket','thread_id','endpoint','credential_file','policy_sha256','public_endpoint','driver']) if (args[k]) options[k] = args[k];
    if (args.enabled && !['true','false'].includes(args.enabled)) throw Error('receiver_enabled_must_be_boolean');
    options.enabled = args.enabled === 'true';
    if (options.runtime === 'codex') options.thread_id = options.thread_id || args.session;
    return profiles.provision(config, options);
  }
  if (command === 'unit') {
    const profile = profiles.load(config);
    if (!profile?.enabled || profile.runtime === 'claude' || profile.runtime === 'web-seat' || profile.driver === 'mcp') throw Error('receiver_requires_standalone_profile');
    const q = value => { if (/[\r\n\0]/.test(String(value))) throw Error('receiver_unit_argument_invalid'); return '"' + String(value).replace(/\$/g, '$$$$').replace(/%/g, '%%').replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; };
    const command = [process.execPath, __filename, 'run', '--family', args.family, '--session', args.session, ...(args.config ? ['--config', path.resolve(args.config)] : [])];
    return { unit_name: 'conduit-receiver-' + profiles.digest(config.name).slice(0,16) + '.service',
      unit: '[Unit]\nDescription=Conduit pane receiver\n[Service]\nType=simple\nExecStart=' + command.map(q).join(' ') + '\nRestart=on-failure\nRestartSec=30\nTimeoutStopSec=10\nUMask=0077\nNoNewPrivileges=true\n[Install]\nWantedBy=default.target\n', installed: false };
  }
  if (command === 'run' || command === 'once') {
    const profile = profiles.load(config);
    if (!profile || profile.driver === 'mcp' || profile.runtime === 'claude' || profile.runtime === 'web-seat') throw Error('receiver_requires_its_host_transport');
    const listener = require('../conduit-receiver-runtime').createRuntime({ sdk, profile,
      onError: code => process.stderr.write(JSON.stringify({ receiver_error: code, at: new Date().toISOString() }) + '\n') });
    if (command === 'once') { await listener.poll(); return listener.status(); }
    for (const signal of ['SIGTERM','SIGINT']) process.once(signal, () => { listener.stop(); process.exit(0); });
    listener.start();
    process.stdout.write(JSON.stringify({ state: 'listening', address: config.name, runtime: profile.runtime, reception_verified: false }) + '\n');
    return null;
  }
  throw Error('usage: conduit-receiver catalog | plan --runtime NAME | configure|status|run|once|unit|serve-seat --family FAMILY --session UUID [receiver options]');
}
if (require.main === module) main(process.argv.slice(2)).then(value => { if (value) console.log(JSON.stringify(value, null, 2)); }).catch(() => {
  // Private JSON parsing and SDK failures can contain credentials: emit a fixed error.
  console.error('Receiver operation refused; check the pane identity, private receiver profile and host prerequisite.'); process.exitCode = 1;
});
module.exports = { main };
