'use strict';
// Local owner opt-in, not a tool argument or peer-message capability.
const path = require('path'), os = require('os');
const profiles = require('./conduit-receiver-profile');
function policy(home = os.homedir()) {
  let p;
  try { p = profiles.readPrivate(path.join(home, '.config/demipass/conduit-startup.json')); }
  catch (e) { if (e.code === 'ENOENT') return { version: 1, claude_channels: false }; throw e; }
  if (!p || p.version !== 1 || typeof p.claude_channels !== 'boolean'
      || Object.keys(p).some(k => !['version','claude_channels'].includes(k))) throw Error('startup_policy_invalid');
  return p;
}
function claudeArgs(args, enabled) {
  if (!enabled || args.some(a => ['-p','--print','--help','-h','--version','-v'].includes(a))
      || ['auth','mcp','plugin','update','install','doctor','setup-token','agents'].includes(args[0])) return [...args];
  const flag = '--dangerously-load-development-channels';
  const equal = args.findIndex(a => a.startsWith(flag + '='));
  if (equal >= 0) args = [...args.slice(0,equal),flag,args[equal].slice(flag.length+1),...args.slice(equal+1)];
  const i = args.indexOf(flag);
  if (i >= 0) {
    let end = i + 1; while (end < args.length && !args[end].startsWith('-')) end++;
    if (args.slice(i + 1, end).includes('server:demipass')) return [...args];
    return [...args.slice(0, i + 1), 'server:demipass', ...args.slice(i + 1)];
  }
  // The channel option is variadic: a following positional prompt would become
  // another channel. Append after ordinary arguments, or before explicit `--`.
  const boundary=args.indexOf('--');
  return boundary < 0 ? [...args,flag,'server:demipass']
    : [...args.slice(0,boundary),flag,'server:demipass',...args.slice(boundary)];
}
function provisionClaude(config, home = os.homedir()) {
  if (!policy(home).claude_channels) return false;
  // Never re-enable a profile the owner explicitly disabled, replace another
  // runtime, or rewrite stable-address/Brain server policy.
  if (profiles.load(config)) return false;
  profiles.provision(config, { runtime: 'claude', enabled: true, driver: 'mcp' });
  return true;
}
module.exports = { policy, claudeArgs, provisionClaude };
