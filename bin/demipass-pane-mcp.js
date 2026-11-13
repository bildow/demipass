#!/usr/bin/env node
'use strict';
// demipass-pane-mcp: the local launcher for the DemiPass (and Buoy) MCP server of one agent pane.
// Installed to ~/.local/bin by bin/install-pane-launcher.sh <release-sha>, which pins RELEASE below; it then loads
// ~/.local/share/demipass/releases/<sha>/mcp-server.js (or buoy-mcp.js with --buoy). Docs: docs/pane-launcher.md.
//
// - The credential is read from ~/.mcp.json and placed in this process's env; it is never copied into other configs,
//   never printed, never written to the receipt.
// - Conduit is enabled only when ~/.config/demipass/conduit.json belongs to the same wallet as that credential. A
//   missing or unreadable Conduit setup disables Conduit only, never the vault/ssh//use tools (review 2026-11-12 M6).
//   Errors name the file, never quote its content.
// - Pane identity: walk up the parent chain to the NEAREST agent runtime (claude / codex). If that process (pid and
//   start time) has an explicit entry in ~/.config/demipass/pane-bindings.json, its model_family/session_id are used.
//   Otherwise, if it is Claude Code, CONDUIT_AUTOBIND=claude is set and the SDK derives the family from this session's
//   transcript at the first Conduit call; the launcher never guesses a family. Any other runtime (Codex: no session id
//   at MCP spawn) stays unbound. The walk stops at the nearest agent, so a nested agent never takes its parent pane's
//   address (review 2026-11-12 M5), and inherited CONDUIT_* identity variables are discarded. A stable session role
//   (CONDUIT_SESSION_NAME) is set only from an explicit binding's session_name, never for an autobound pane.
// - CONDUIT_REQUIRE_PANE=1 always: with no pane identity, Conduit messaging fails closed (never the shared legacy name).
const fs = require('fs'), path = require('path'), os = require('os');

const RELEASE = '@@DEMIPASS_RELEASE_SHA@@';   // replaced by bin/install-pane-launcher.sh
if (!/^[0-9a-f]{40}$/.test(RELEASE)) throw new Error('demipass-pane-mcp is not pinned to a release: install it with bin/install-pane-launcher.sh <release-sha>');

const home = os.homedir();
const role = process.argv[2] === '--buoy' ? 'buoy' : 'demipass';
const key = role === 'buoy' ? 'BUOY_TOKEN' : 'DEMIPASS_TOKEN';
const urlKey = role === 'buoy' ? 'BUOY_URL' : 'DEMIPASS_URL';
// A malformed ~/.mcp.json is reported without quoting it: JSON.parse errors can echo the text, i.e. the credential.
const fail = (msg) => { process.stderr.write('demipass-pane-mcp: ' + msg + '\n'); process.exit(1); };
let config;
{ let raw; try { raw = fs.readFileSync(path.join(home, '.mcp.json'), 'utf8'); } catch { fail('~/.mcp.json is missing or unreadable'); }
  try { config = JSON.parse(raw); } catch { fail('~/.mcp.json is not valid JSON'); } }
const env = (config && config.mcpServers && config.mcpServers[role] && config.mcpServers[role].env) || {};
if (!env[key]) fail('Missing configured ' + role + ' credential');
const claims = (t) => { try { return JSON.parse(Buffer.from(String(t).split('.')[1], 'base64url')); } catch { return {}; } };
const readJson = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };

let conduitOk = role === 'demipass';
if (conduitOk) {
  const shared = readJson(path.join(home, '.config/demipass/conduit.json'));
  const expected = shared && (shared.wallet || claims(shared.token || '').sub);
  if (!expected || claims(env[key]).sub !== expected) {
    conduitOk = false;
    process.stderr.write('demipass-pane-mcp: Conduit disabled: conduit.json missing, unreadable, or for another wallet\n');
  }
}
process.env[key] = env[key];
if (env[urlKey]) process.env[urlKey] = env[urlKey];

// The nearest agent runtime above this MCP: 'claude', 'codex' or null.
const agentKind = (pid) => {
  let argv; try { argv = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0'); } catch { return null; }
  if (argv.some((a) => /(^|\/)claude(\.js)?$/.test(a) || /\/@anthropic-ai\/claude-code\/cli\.js$/.test(a))) return 'claude';
  if (argv.some((a) => /(^|\/)codex(\.js)?$/.test(a) || /\/\.codex\/packages\//.test(a))) return 'codex';
  return null;
};
// The value of one variable in a process's own (initial) environment, or undefined; null when unreadable.
const procEnv = (pid, name) => {
  let raw; try { raw = fs.readFileSync(`/proc/${pid}/environ`, 'utf8'); } catch { return null; }
  const hit = raw.split('\0').find((e) => e.startsWith(name + '='));
  return hit === undefined ? undefined : hit.slice(name.length + 1);
};

let source = 'unbound', runtime = null, unbound = null;
if (role === 'demipass') {
  for (const k of ['CONDUIT_MODEL_FAMILY', 'CONDUIT_SESSION_ID', 'CONDUIT_SESSION_NAME', 'CONDUIT_AUTOBIND']) delete process.env[k];
  process.env.CONDUIT_REQUIRE_PANE = '1';   // with Conduit disabled this keeps Conduit calls failing closed, nothing else
  const b = conduitOk ? readJson(path.join(home, '.config/demipass/pane-bindings.json')) : null;
  const bindings = (b && Array.isArray(b.bindings)) ? b.bindings : [];
  if (!conduitOk) unbound = 'conduit_disabled';
  else {
    let pid = process.ppid;
    for (let hops = 0; pid > 1 && hops < 24; hops++) {
      let fields; try { const s = fs.readFileSync(`/proc/${pid}/stat`, 'utf8'); fields = s.slice(s.lastIndexOf(') ') + 2).trim().split(/\s+/); } catch { break; }
      const match = bindings.find((x) => x.pid === pid && String(x.start_ticks) === fields[19]);
      if (match) {
        process.env.CONDUIT_MODEL_FAMILY = match.model_family;
        process.env.CONDUIT_SESSION_ID = match.session_id;
        // A stable role (#21) comes only from an explicit binding; the SDK migrates such a pane to it on first use.
        if (typeof match.session_name === 'string' && match.session_name) process.env.CONDUIT_SESSION_NAME = match.session_name;
        source = 'pane-binding-process-start-checked';
        break;
      }
      runtime = agentKind(pid);
      if (runtime) {   // an agent runtime with no explicit binding: this MCP gets no address from further up
        const sid = process.env.CLAUDE_CODE_SESSION_ID || '';
        // A session id the agent process itself inherited (a claude started from inside another pane that did not set
        // its own) belongs to the outer session: never autobind to it. Unreadable environ = not proven, refuse.
        const own = runtime === 'claude' && sid ? procEnv(pid, 'CLAUDE_CODE_SESSION_ID') : undefined;
        if (runtime !== 'claude') unbound = runtime + '_no_session_id';
        else if (!sid) unbound = 'claude_no_session_id';
        else if (own === null) unbound = 'claude_environ_unreadable';
        else if (own === sid) unbound = 'claude_session_id_inherited';
        else { process.env.CONDUIT_AUTOBIND = 'claude'; source = 'autobind-claude-session'; }
        break;
      }
      pid = Number(fields[1]);
    }
    if (source === 'unbound' && !unbound) unbound = b ? 'no_agent_runtime_found' : 'pane_bindings_missing';
    if (!b && source === 'unbound') process.stderr.write('demipass-pane-mcp: pane-bindings.json missing or unreadable and no automatic address: no pane address\n');
  }
}

// Non-secret local startup receipt: which identity the actual MCP child loaded (0600, in a 0700 directory).
const runtimeDir = path.join(home, '.config/demipass/runtime');
fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(runtimeDir, `pid-${process.pid}.json`), JSON.stringify({ pid: process.pid, parent: process.ppid, role,
  model_family: process.env.CONDUIT_MODEL_FAMILY || null, session_id: process.env.CONDUIT_SESSION_ID || null,
  session_name: process.env.CONDUIT_SESSION_NAME || null,
  autobind: process.env.CONDUIT_AUTOBIND || null, runtime, unbound_reason: unbound, source, release: RELEASE,
  at: new Date().toISOString() }) + '\n', { mode: 0o600 });
require(path.join(home, '.local/share/demipass/releases', RELEASE, role === 'buoy' ? 'buoy-mcp.js' : 'mcp-server.js'));
