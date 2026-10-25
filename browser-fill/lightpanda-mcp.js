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
 * value attribute) and its stderr are scrubbed, best-effort, of the filled value as echoed verbatim or in the
 * URL / form / HTML / markdown / JSON encodings listed in fill-core.js. That catches accidents, not intent, and
 * not a value transformed any other way — see docs/agent-browser-fill.md.
 *
 * goose config (replaces the lightpanda extension's cmd/args):
 *   cmd: /usr/local/bin/demipass-lightpanda-mcp
 *   args: [--lightpanda, /usr/local/bin/lightpanda]          # anything after `--` goes to `lightpanda mcp`
 *   env:  DEMIPASS_FILL_TOKEN_FILE=/etc/agent-fill/demipass-fill.token (or DEMIPASS_FILL_TOKEN), DEMIPASS_URL
 *         A fill token variable that is set but unusable (file absent until provisioning, blank) makes the fill tools
 *         answer no_fill_identity; the Lightpanda tools keep working. Neither set → DEMIPASS_TOKEN / credentials file.
 *   No dotenv and no npm dependencies: runtime requires are ../index.js, ./fill-core.js, ./page-script.js + Node core.
 */

const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const { resolveFillToken, fillIdentityConfigured, FillError, normalizeOrigin, obtainFill, listCandidates, Redactor, failureResult, REDACTED } = require('./fill-core');
const { pageExpression } = require('./page-script');

const TOOL_FILL = 'demipass_browser_fill';
const TOOL_CANDIDATES = 'demipass_browser_fill_candidates';

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

const INSTRUCTIONS_NOTE = `\n\nDemiPass logins:\n- Never ask for, type or read back a password. To log in, open the login page, call \`${TOOL_CANDIDATES}\`, then \`${TOOL_FILL} {ref, submit: true}\`. The value goes from the vault into the page directly; results say {filled, chars, origin}.\n- Best-effort scrubbing: where a later result echoes a filled value as-is or in a common encoding (URL, form, HTML, markdown, JSON), that text is replaced by ${REDACTED}. A value the page or a script transforms any other way is not caught, so do not read login fields back.\n`;

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
 * Split a utf8 stream into lines in linear time (a chunk is scanned once; a long line is joined once).
 */
function lineSplitter(onLine) {
  let parts = [];
  return (chunk) => {
    let start = 0;
    let i;
    while ((i = chunk.indexOf('\n', start)) >= 0) {
      parts.push(chunk.slice(start, i));
      const line = parts.length === 1 ? parts[0] : parts.join('');
      parts = [];
      start = i + 1;
      onLine(line);
    }
    if (start < chunk.length) parts.push(chunk.slice(start));
  };
}

/**
 * The proxy. `io` = { stdin, stdout, stderr } (process streams by default); `api` = SDK-shaped fill API.
 * `getToken()` supplies the fill token per call (may throw FillError('no_fill_identity')); `token` is the static
 * shorthand. Exported for tests; `main()` wires it to the process.
 *
 * JSON-RPC ids: every request the child sees carries an id this proxy minted. Agent ids are rewritten on the way in
 * and restored on the way out, internal calls (the fill's getUrl / evaluate / fill / click) use ids from the same
 * counter, and a child reply whose id we did not mint for the agent is never forwarded. So no agent id can be taken
 * for an internal reply, and no internal reply (Lightpanda's `fill` result echoes the value) can reach the agent.
 *
 * Holding: while a fill tool runs, and until every internal call has been answered (a call that timed out keeps its
 * id registered until Lightpanda answers or exits), agent requests are held, so the page stays still. A timed-out
 * call that is still unanswered `hardKillMs` later means Lightpanda is stuck (a page in `while (true)`): the child is
 * killed, and every held request is answered "the browser exited".
 */
function createProxy({ lightpanda, extra = [], api, token, getToken, env = process.env, io = process, clientLabel, internalTimeoutMs = 30000, hardKillMs = 60000 }) {
  const tokenFor = typeof getToken === 'function' ? getToken : () => token;
  const redactor = new Redactor();
  const childEnv = { ...env, LIGHTPANDA_DISABLE_TELEMETRY: env.LIGHTPANDA_DISABLE_TELEMETRY || 'true' };
  // The DemiPass token is ours, not the browser's.
  for (const k of Object.keys(childEnv)) if (k.startsWith('DEMIPASS_')) delete childEnv[k];
  const child = spawn(lightpanda, ['mcp', ...extra], { stdio: ['pipe', 'pipe', 'pipe'], env: childEnv });

  let seq = 0;                    // the only id space the child sees
  const internal = new Map();     // child id → { done(msg) }   (our own calls)
  const forAgent = new Map();     // child id → { id: the agent's id, kind, firstPage }
  let running = false;            // a fill tool is running
  let childGone = false;
  let exitCode;                   // set when the child exited while a fill tool was running (its reply goes out first)
  const killTimers = new Set();
  const held = [];                // agent requests held while busy (keeps the page still)
  const busy = () => running || internal.size > 0;

  const write = (stream, obj) => { try { stream.write(JSON.stringify(obj) + '\n'); } catch (_) { /* stream gone */ } };
  const toAgent = (obj) => write(io.stdout, redactor.scrubDeep(obj));
  const toChild = (obj) => { if (!childGone) write(child.stdin, obj); };
  const agentError = (id, message, code = -32603) => toAgent({ jsonrpc: '2.0', id, error: { code, message } });

  // ── child → us ──
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', lineSplitter((line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch (_) { return; } // never forward an unparseable (unscrubbable) line
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return; // we never send batches
    const isReply = msg.method === undefined && ('result' in msg || 'error' in msg);
    if (!isReply) { toAgent(msg); return; } // the child's own requests / notifications (its id space)
    if (msg.id === null || msg.id === undefined) { toAgent(msg); return; } // id-less error (parse error)
    const mine = internal.get(msg.id);
    if (mine) { internal.delete(msg.id); mine.done(msg); drain(); return; }
    const a = forAgent.get(msg.id);
    if (!a) return; // a reply to nothing we sent for the agent: swallow
    forAgent.delete(msg.id);
    msg.id = a.id;
    if (a.kind === 'initialize' && msg.result && typeof msg.result === 'object') {
      msg.result.instructions = String(msg.result.instructions || '') + INSTRUCTIONS_NOTE;
    }
    if (a.kind === 'tools/list' && msg.result && Array.isArray(msg.result.tools)) {
      const theirs = msg.result.tools.filter((t) => !(t && typeof t.name === 'string' && t.name.startsWith('demipass_')));
      msg.result.tools = a.firstPage ? [...theirs, ...FILL_TOOLS] : theirs;
    }
    toAgent(msg);
  }));
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', lineSplitter((line) => { try { io.stderr.write(redactor.scrub(line) + '\n'); } catch (_) {} }));

  function callChild(name, args) {
    if (childGone) return Promise.reject(new FillError('browser_gone', 'the browser exited'));
    const id = ++seq;
    return new Promise((resolve, reject) => {
      const entry = { done: (m) => { clearTimeout(timer); resolve(m); } };
      // On timeout the fill fails, but the id stays registered: Lightpanda may still be acting on the page, so agent
      // requests stay held, and the late reply is swallowed when it comes.
      const timer = setTimeout(() => {
        const kill = setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} }, hardKillMs);
        killTimers.add(kill);
        entry.done = () => { clearTimeout(kill); killTimers.delete(kill); };
        reject(new FillError('browser_timeout', `browser ${name} timed out`));
      }, internalTimeoutMs);
      internal.set(id, entry);
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
  const failed = (r) => Boolean(r.error || (r.result && r.result.isError));

  async function doCandidates(args) {
    const tok = tokenFor();
    let origin = args.origin;
    if (!origin) {
      const cur = await currentOrigin();
      if (!cur.origin) throw new FillError('origin_not_fillable', 'the current page is not fillable (https only; http only on localhost)', { origin: safeOrigin(cur.raw) });
      origin = cur.origin;
    }
    return { ok: true, ...(await listCandidates(api, { origin, token: tok })) };
  }

  async function doFill(args) {
    const tok = tokenFor(); // no fill identity → refuse before touching the page
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
      secret = await obtainFill(api, { ref: args.ref, origin: cur.origin, clientLabel, waitSeconds: args.wait_seconds, requestId: args.request_id, token: tok });
      redactor.add(secret.value);
      // Lightpanda resolves `$LP_NAME` in tool string arguments from its environment. A value that contains such a
      // reference would be altered (and the variable's value typed instead) — refuse rather than guess.
      const lpRefs = (secret.value.match(/\$LP_[A-Za-z0-9_]+/g) || []).filter((r) => childEnv[r.slice(1)] !== undefined);
      if (lpRefs.length) throw new FillError('value_needs_escape', 'the stored value contains a $LP_ reference that Lightpanda would substitute; unset that LP_ variable for this agent');

      const again = await currentOrigin();
      if (again.origin !== secret.origin) throw new FillError('origin_changed', 'the page navigated away before the fill — nothing was filled', { origin: again.origin });

      let usernameTried = false;
      if (found.username_field && secret.username) {
        const r = await callChild('fill', { selector: sel('u'), value: secret.username });
        if (failed(r)) throw new FillError('fill_failed', 'the username field could not be filled (the page may have changed)');
        usernameTried = true;
      }
      const r = await callChild('fill', { selector: sel('p'), value: secret.value });
      if (failed(r)) throw new FillError('fill_failed', 'the password field could not be filled (the page may have changed)');
      // Verify what the field holds (length only), like the CDP path: maxlength handling or a page script can change it.
      const chk = await evalPage({ mode: 'check', mark, expectedOrigin: secret.origin });
      if (!chk.ok) throw new FillError(chk.code === 'origin_changed' ? 'origin_changed' : 'fill_failed', 'the password field is gone after the fill (the page changed)', { origin: secret.origin });
      if (chk.password_chars !== secret.value.length) await refuseAndClear(sel, mark, secret.origin);
      const usernameFilled = usernameTried && chk.username_chars === secret.username.length;
      const chars = chk.password_chars;

      let submitted = false, submitError;
      if (args.submit) {
        let s;
        if (found.has_submit) s = await callChild('click', { selector: sel('s') });
        else s = await callChild('press', { key: 'Enter', selector: sel('p') });
        submitted = !failed(s);
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

  // The field holds something other than the value (a length guard, a page script). Whatever it holds derives from the
  // value, so it joins the Redactor (page JS may keep a copy and echo it later); then the field is emptied — as a
  // user would, then, if the page refills it, with no events — and the emptying is verified.
  async function refuseAndClear(sel, mark, origin) {
    const learn = async () => {
      const r = await evalPage({ mode: 'residue', mark }).catch(() => null);
      if (r && r.ok && typeof r.value === 'string') redactor.add(r.value);
    };
    const empty = async () => { const c = await evalPage({ mode: 'check', mark }).catch(() => null); return Boolean(c && c.ok && c.password_chars === 0); };
    await learn();
    await callChild('fill', { selector: sel('p'), value: '' }).catch(() => null);
    let ok = await empty();
    if (!ok) { await evalPage({ mode: 'clear', mark }).catch(() => null); ok = await empty(); }
    if (!ok) {
      await learn();
      throw new FillError('clear_failed', 'the password field did not accept the value, and the page would not let it be emptied: part of the value may still be in the field (what it holds is redacted from later results, unless under 4 characters)', { origin });
    }
    throw new FillError('value_not_accepted', 'the password field did not accept the value; the field was cleared', { origin });
  }

  async function runTool(msg) {
    const { id, params } = msg;
    const name = params && params.name;
    const args = (params && params.arguments) || {};
    running = true;
    let result;
    try {
      const out = name === TOOL_FILL ? await doFill(args) : await doCandidates(args);
      result = { content: [{ type: 'text', text: JSON.stringify(redactor.scrubDeep(out), null, 2) }] };
    } catch (err) {
      const e = childGone ? new FillError('browser_gone', 'the browser exited during the fill') : err;
      result = { content: [{ type: 'text', text: JSON.stringify(failureResult(e, redactor), null, 2) }], isError: true };
    } finally {
      running = false;
    }
    if (id !== undefined) toAgent({ jsonrpc: '2.0', id, result });
    if (exitCode !== undefined) { exitProcess(exitCode); return; }
    drain();
  }
  function exitProcess(code) { if (io === process) process.exit(code == null ? 1 : code); }
  function drain() { while (held.length && !busy()) onAgentMessage(held.shift()); }

  // ── agent → us ──
  function onAgentMessage(msg) {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      agentError(null, Array.isArray(msg) ? 'JSON-RPC batches are not supported' : 'Invalid Request', -32600);
      return;
    }
    if (msg.method === undefined) { toChild(msg); return; } // the agent's reply to a child request (child's ids)
    if (busy()) { held.push(msg); return; }
    if (msg.method === 'tools/call' && msg.params && (msg.params.name === TOOL_FILL || msg.params.name === TOOL_CANDIDATES)) {
      runTool(msg);
      return;
    }
    if (msg.id !== undefined && msg.id !== null) {
      if (childGone) { agentError(msg.id, 'the browser exited'); return; }
      const cid = ++seq;
      forAgent.set(cid, { id: msg.id, kind: msg.method, firstPage: !(msg.params && msg.params.cursor) });
      toChild({ ...msg, id: cid });
      return;
    }
    if (msg.method === 'notifications/cancelled' && msg.params && msg.params.requestId !== undefined) {
      for (const [cid, a] of forAgent) {
        if (a.id === msg.params.requestId) { toChild({ ...msg, params: { ...msg.params, requestId: cid } }); return; }
      }
      return; // nothing of the agent's with that id is at the child (an internal id is never the agent's to cancel)
    }
    toChild(msg);
  }
  io.stdin.setEncoding('utf8');
  io.stdin.on('data', lineSplitter((line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch (_) { agentError(null, 'Parse error', -32700); return; }
    onAgentMessage(msg);
  }));
  io.stdin.on('end', () => { try { child.stdin.end(); } catch (_) {} });
  child.stdin.on('error', () => { /* child gone; handled by 'exit' */ });
  child.on('exit', (code) => {
    childGone = true;
    for (const k of killTimers) clearTimeout(k);
    killTimers.clear();
    for (const e of internal.values()) e.done({ error: { code: -32603, message: 'browser exited' } });
    internal.clear();
    for (const a of forAgent.values()) agentError(a.id, 'the browser exited');
    forAgent.clear();
    while (held.length) { const m = held.shift(); if (m.id !== undefined && m.id !== null) agentError(m.id, 'the browser exited'); }
    // A fill tool still running answers first (its remaining steps fail at once now that the child is gone); a cap
    // keeps a fill stuck in an HTTP call from holding the process past its browser.
    if (running) { exitCode = code; setTimeout(() => exitProcess(code), 5000).unref(); return; }
    exitProcess(code);
  });
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
  // No dotenv: it would resolve a `dotenv` module (and read a .env) from paths the agent's uid can write, and run
  // that code inside the process that holds fill values. Configuration comes from the MCP client's env only.
  const demipass = require('../index.js');
  demipass.configure({ baseUrl: process.env.DEMIPASS_URL || 'https://api.dustforge.com' });
  // A configured fill identity (DEMIPASS_FILL_TOKEN / _FILE) is read per call and never falls back; with neither set,
  // the usual DemiPass bearer (credentials file, then DEMIPASS_TOKEN) is used.
  if (!fillIdentityConfigured(process.env)) demipass.loadBearerFromEnvironment();
  createProxy({
    lightpanda: opts.lightpanda, extra: opts.extra, api: demipass,
    getToken: () => resolveFillToken(process.env),
    clientLabel: `lightpanda-mcp@${require('os').hostname()}`.slice(0, 80),
  });
  process.stdout.on('error', () => process.exit(0));
}

if (require.main === module) main();

module.exports = { createProxy, parseArgs, lineSplitter, FILL_TOOLS, INSTRUCTIONS_NOTE };
