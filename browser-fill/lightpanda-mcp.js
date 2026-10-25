#!/usr/bin/env node
'use strict';
/**
 * demipass-lightpanda-mcp — Lightpanda's own MCP server, plus DemiPass browser fill, in one stdio MCP server.
 *
 * Why a wrapper: when goose drives Lightpanda through `lightpanda mcp` (stdio), the page lives in that process's
 * MCP session and nothing else can reach it. `lightpanda mcp --cdp-port` starts a CDP server, but every CDP
 * connection gets its own Browser (own V8 isolate) — Target.getTargets from a second client lists nothing — and
 * `lightpanda serve` likewise gives each connection its own browser. So the fill tool sits in front of the MCP
 * session itself: this process spawns `lightpanda mcp`, passes every message through unchanged, adds two tools, and
 * fills by calling Lightpanda's own `fill` tool internally. Those internal calls and their results never reach the
 * agent.
 *
 * Added tools:
 *   demipass_browser_fill_candidates {origin?}   logins this agent may fill on the current page (no values)
 *   demipass_browser_fill {ref, username_selector?, password_selector?, submit?, request_id?, wait_seconds?}
 *       → {filled: true, chars, origin, ...}
 *
 * After a fill, every result Lightpanda sends back (evaluate output, console logs, a GET form's URL, html with a
 * value attribute) and its stderr are scrubbed of the filled value and its URL/form/HTML encodings. That catches
 * accidents, not intent — see docs/agent-browser-fill.md.
 *
 * goose config (replaces the lightpanda extension's cmd/args):
 *   cmd: /usr/local/bin/demipass-lightpanda-mcp
 *   args: [--lightpanda, /usr/local/bin/lightpanda]          # anything after `--` goes to `lightpanda mcp`
 *   env:  DEMIPASS_FILL_TOKEN_FILE=/etc/agent/demipass-fill.token (or DEMIPASS_FILL_TOKEN / DEMIPASS_TOKEN), DEMIPASS_URL
 */

const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const { fillTokenFromEnv, FillError, normalizeOrigin, obtainFill, listCandidates, Redactor, failureResult, REDACTED } = require('./fill-core');
const { pageExpression } = require('./page-script');

const TOOL_FILL = 'demipass_browser_fill';
const TOOL_CANDIDATES = 'demipass_browser_fill_candidates';
const INTERNAL_PREFIX = 'demipass-internal-';

const FILL_TOOLS = [
  {
    name: TOOL_CANDIDATES,
    description: 'DemiPass: list the stored logins this agent may fill into the page that is open now (or into `origin`). Returns ref, name, username — never a password. Use a ref with demipass_browser_fill.',
    inputSchema: { type: 'object', properties: { origin: { type: 'string', description: 'Origin to look up (https://host[:port]). Default: the current page.' } } },
  },
  {
    name: TOOL_FILL,
    description: 'DemiPass: fill a stored login into the login form on the page that is open now. The password goes from the DemiPass vault straight into the page and never into this conversation; you get back {filled, chars, origin}. The page origin must be bound to the secret. Navigate to the login page first. With submit=true the form is submitted. Do not read the password field back afterwards — results are scrubbed, but reading it is still pointless.',
    inputSchema: {
      type: 'object',
      properties: {
        ref: { type: 'string', description: 'DemiPass ref code, e.g. DP-PWD-example-1a2b3c4d (see demipass_browser_fill_candidates).' },
        username_selector: { type: 'string', description: 'CSS selector of the username/email field. Default: detected.' },
        password_selector: { type: 'string', description: 'CSS selector of the password field. Default: the one visible password field.' },
        submit: { type: 'boolean', description: 'Submit the form after filling. Default false.' },
        request_id: { type: 'string', description: 'Resume an earlier request that was waiting for approval.' },
        wait_seconds: { type: 'integer', description: 'How long to wait for a person to approve on the DemiPass wallet (carbon tokens). Default 0 — silicon grants are approved at once.' },
      },
      required: ['ref'],
    },
  },
];

const INSTRUCTIONS_NOTE = `\n\nDemiPass logins:\n- Never ask for, type or read back a password. To log in, open the login page, call \`${TOOL_CANDIDATES}\`, then \`${TOOL_FILL} {ref, submit: true}\`. The value goes from the vault into the page directly; results say {filled, chars, origin}.\n- Filled values are replaced by ${REDACTED} in every later result.\n`;

function parseArgs(argv) {
  const out = { lightpanda: process.env.LIGHTPANDA_BIN || '/usr/local/bin/lightpanda', extra: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--') { out.extra = argv.slice(i + 1); break; }
    if (argv[i] === '--lightpanda') { out.lightpanda = argv[++i]; continue; }
    if (argv[i] === '--help' || argv[i] === '-h') { out.help = true; continue; }
    out.extra.push(argv[i]); // unknown flags go to lightpanda mcp
  }
  return out;
}

/**
 * The proxy. `io` = { stdin, stdout, stderr } (process streams by default); `api` = SDK-shaped fill API.
 * Exported for tests; `main()` wires it to the process.
 */
function createProxy({ lightpanda, extra = [], api, token, env = process.env, io = process, clientLabel }) {
  const redactor = new Redactor();
  const childEnv = { ...env, LIGHTPANDA_DISABLE_TELEMETRY: env.LIGHTPANDA_DISABLE_TELEMETRY || 'true' };
  // The DemiPass token is ours, not the browser's.
  for (const k of Object.keys(childEnv)) if (k.startsWith('DEMIPASS_')) delete childEnv[k];
  const child = spawn(lightpanda, ['mcp', ...extra], { stdio: ['pipe', 'pipe', 'pipe'], env: childEnv });

  let internalSeq = 0;
  const internal = new Map();     // internal id → resolve
  let fillBusy = false;
  const held = [];                // agent messages held while a fill runs (keeps the page still)

  const write = (stream, obj) => stream.write(JSON.stringify(obj) + '\n');
  const toAgent = (obj) => write(io.stdout, redactor.scrubDeep(obj));
  const toChild = (obj) => { try { write(child.stdin, obj); } catch (_) { /* child gone */ } };

  // ── child → us ──
  let cbuf = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    cbuf += chunk;
    let i;
    while ((i = cbuf.indexOf('\n')) >= 0) {
      const line = cbuf.slice(0, i); cbuf = cbuf.slice(i + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (_) { continue; } // never forward an unparseable (unscrubbable) line
      if (typeof msg.id === 'string' && internal.has(msg.id)) { const r = internal.get(msg.id); internal.delete(msg.id); r(msg); continue; }
      if (msg.id !== undefined && pendingInit.has(msg.id) && msg.result) {
        pendingInit.delete(msg.id);
        msg.result.instructions = String(msg.result.instructions || '') + INSTRUCTIONS_NOTE;
      }
      if (msg.id !== undefined && pendingList.has(msg.id) && msg.result && Array.isArray(msg.result.tools)) {
        pendingList.delete(msg.id);
        msg.result.tools = [...msg.result.tools.filter((t) => !t.name.startsWith('demipass_')), ...FILL_TOOLS];
      }
      toAgent(msg);
    }
  });
  let ebuf = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    ebuf += chunk;
    let i;
    while ((i = ebuf.indexOf('\n')) >= 0) { const line = ebuf.slice(0, i + 1); ebuf = ebuf.slice(i + 1); io.stderr.write(redactor.scrub(line)); }
  });

  function callChild(name, args, timeoutMs = 30000) {
    const id = INTERNAL_PREFIX + (++internalSeq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { internal.delete(id); reject(new FillError('browser_timeout', `browser ${name} timed out`)); }, timeoutMs);
      internal.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
      toChild({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
    });
  }
  function textOf(msg) {
    if (msg.error) return null;
    const c = msg.result && Array.isArray(msg.result.content) ? msg.result.content.find((x) => x.type === 'text') : null;
    return c ? c.text : '';
  }
  async function currentOrigin() {
    const m = await callChild('getUrl', {});
    const url = textOf(m);
    if (url === null || (m.result && m.result.isError)) throw new FillError('no_page', 'no page is open — navigate to the login page first');
    return { origin: normalizeOrigin(url.trim()), raw: url.trim() };
  }
  async function evalPage(args) {
    const m = await callChild('evaluate', { script: `JSON.stringify(${pageExpression(args)})` });
    const t = textOf(m);
    if (t === null || (m.result && m.result.isError)) throw new FillError('page_script_failed', 'the fill script failed in the page');
    try { return JSON.parse(t); } catch (_) { throw new FillError('page_script_failed', 'the fill script returned something unexpected'); }
  }

  async function doCandidates(args) {
    let origin = args.origin;
    if (!origin) {
      const cur = await currentOrigin();
      if (!cur.origin) throw new FillError('origin_not_fillable', 'the current page is not fillable (https only; http only on localhost)', { origin: safeOrigin(cur.raw) });
      origin = cur.origin;
    }
    return { ok: true, ...(await listCandidates(api, { origin, token })) };
  }

  async function doFill(args) {
    const mark = crypto.randomBytes(8).toString('hex');
    const sel = (k) => `[data-demipass-fill="${mark}:${k}"]`;
    const cur = await currentOrigin();
    if (!cur.origin) throw new FillError('origin_not_fillable', 'the current page is not fillable (https only; http only on localhost)', { origin: safeOrigin(cur.raw) });
    // Find and tag the fields first (no value involved). The tags bind the fill to this document: if the page
    // navigates before the fill, the selectors match nothing and the fill fails closed.
    const found = await evalPage({
      mode: 'find', mark, expectedOrigin: cur.origin,
      usernameSelector: args.username_selector || null, passwordSelector: args.password_selector || null,
    });
    if (!found.ok) throw findFailure(found, cur.origin);

    let secret;
    try {
      secret = await obtainFill(api, { ref: args.ref, origin: cur.origin, clientLabel, waitSeconds: args.wait_seconds, requestId: args.request_id, token });
      redactor.add(secret.value);
      // Lightpanda resolves `$LP_NAME` in tool string arguments from its environment. A value that contains such a
      // reference would be altered (and the variable's value typed instead) — refuse rather than guess.
      const lpRefs = (secret.value.match(/\$LP_[A-Za-z0-9_]+/g) || []).filter((r) => childEnv[r.slice(1)] !== undefined);
      if (lpRefs.length) throw new FillError('value_needs_escape', 'the stored value contains a $LP_ reference that Lightpanda would substitute; unset that LP_ variable for this agent');

      const again = await currentOrigin();
      if (again.origin !== secret.origin) throw new FillError('origin_changed', 'the page navigated away before the fill — nothing was filled', { origin: again.origin });

      let usernameFilled = false;
      if (found.username_field && secret.username) {
        const r = await callChild('fill', { selector: sel('u'), value: secret.username });
        if (r.error || (r.result && r.result.isError)) throw new FillError('fill_failed', 'the username field could not be filled (the page may have changed)');
        usernameFilled = true;
      }
      const r = await callChild('fill', { selector: sel('p'), value: secret.value });
      if (r.error || (r.result && r.result.isError)) throw new FillError('fill_failed', 'the password field could not be filled (the page may have changed)');
      const chars = secret.value.length;

      let submitted = false, submitError;
      if (args.submit) {
        let s;
        if (found.has_submit) s = await callChild('click', { selector: sel('s') });
        else s = await callChild('press', { key: 'Enter', selector: sel('p') });
        submitted = !(s.error || (s.result && s.result.isError));
        if (!submitted) submitError = 'submit_failed';
      } else {
        await evalPage({ mode: 'unmark', mark }).catch(() => {});
      }
      const after = submitted ? await currentOrigin().catch(() => ({})) : null;
      return {
        filled: true, chars, origin: secret.origin, ref: secret.ref,
        username_filled: usernameFilled, password_filled: true, submitted,
        ...(submitError ? { submit_error: submitError } : {}),
        ...(after && after.origin !== undefined ? { origin_after_submit: after.origin || safeOrigin(after.raw) } : {}),
      };
    } finally {
      if (secret) secret.value = null;
    }
  }

  async function runTool(msg) {
    const { id, params } = msg;
    const name = params && params.name;
    const args = (params && params.arguments) || {};
    fillBusy = true;
    let result;
    try {
      const out = name === TOOL_FILL ? await doFill(args) : await doCandidates(args);
      result = { content: [{ type: 'text', text: JSON.stringify(redactor.scrubDeep(out), null, 2) }] };
    } catch (err) {
      result = { content: [{ type: 'text', text: JSON.stringify(failureResult(err, redactor), null, 2) }], isError: true };
    } finally {
      fillBusy = false;
    }
    toAgent({ jsonrpc: '2.0', id, result });
    while (held.length && !fillBusy) onAgentMessage(held.shift());
  }

  // ── agent → us ──
  const pendingInit = new Set();
  const pendingList = new Set();
  function onAgentMessage(msg) {
    if (fillBusy && msg.method) { held.push(msg); return; }
    if (msg.method === 'tools/call' && msg.params && (msg.params.name === TOOL_FILL || msg.params.name === TOOL_CANDIDATES)) {
      runTool(msg);
      return;
    }
    if (msg.method === 'initialize' && msg.id !== undefined) pendingInit.add(msg.id);
    if (msg.method === 'tools/list' && msg.id !== undefined) pendingList.add(msg.id);
    toChild(msg);
  }
  let abuf = '';
  io.stdin.setEncoding('utf8');
  io.stdin.on('data', (chunk) => {
    abuf += chunk;
    let i;
    while ((i = abuf.indexOf('\n')) >= 0) {
      const line = abuf.slice(0, i); abuf = abuf.slice(i + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (_) { toAgent({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); continue; }
      onAgentMessage(msg);
    }
  });
  io.stdin.on('end', () => { try { child.stdin.end(); } catch (_) {} });
  child.on('exit', (code) => { if (io === process) process.exit(code == null ? 1 : code); });
  child.on('error', (e) => { io.stderr.write(`demipass-lightpanda-mcp: cannot start ${path.basename(String(lightpanda))}: ${e.code || 'error'}\n`); if (io === process) process.exit(1); });

  return { child, redactor };
}

function findFailure(v, origin) {
  const msgs = {
    origin_changed: 'the page is no longer on the origin it was a moment ago',
    no_password_field: 'no visible password field on this page — pass password_selector',
    ambiguous_password_field: 'several password fields on this page — pass password_selector',
    selector_not_found: `no element matches the ${v.field}_selector`,
    bad_selector: `the ${v.field}_selector is not valid CSS`,
    field_not_usable: `the ${v.field} field is hidden, disabled or read-only`,
  };
  return new FillError(v.code || 'page_script_failed', msgs[v.code] || 'the login form could not be located', { origin, ...(v.count ? { count: v.count } : {}) });
}
function safeOrigin(url) { try { return new URL(url).origin; } catch (_) { return null; } }

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write('usage: demipass-lightpanda-mcp [--lightpanda PATH] [-- lightpanda mcp args]\n');
    return;
  }
  try { require('dotenv').config(); } catch {}
  const demipass = require('../index.js');
  demipass.configure({ baseUrl: process.env.DEMIPASS_URL || 'https://api.dustforge.com' });
  // A dedicated silicon token wins; otherwise the usual DemiPass bearer (credentials file, then DEMIPASS_TOKEN).
  const fillToken = fillTokenFromEnv(process.env) || '';
  if (!fillToken) demipass.loadBearerFromEnvironment();
  createProxy({
    lightpanda: opts.lightpanda, extra: opts.extra, api: demipass, token: fillToken || undefined,
    clientLabel: `lightpanda-mcp@${require('os').hostname()}`.slice(0, 80),
  });
  process.stdout.on('error', () => process.exit(0));
}

if (require.main === module) main();

module.exports = { createProxy, parseArgs, FILL_TOOLS };
