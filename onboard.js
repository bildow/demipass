#!/usr/bin/env node
'use strict';
/**
 * demipass-onboard — put an agent pane onto any DemiPass service (a "tenant": FLEETGATE, Conduit, …) in one step.
 *
 *   demipass-onboard <service> [--cap <DD per day>] [--mcp-config <path>] [--no-wait] [--approval <id>]
 *   demipass-onboard --list
 *
 * What it does, in order:
 *   1. Reads the service from DemiPass's registry (GET /api/services/<slug>): its name, prices, endpoint, and the MCP
 *      server agents attach with (`mcp_server`, "<npm package>#<bin>"). Nothing here hard-codes a service URL.
 *   2. Makes sure this wallet consents to pay it (services.ensureConsent). If not, the consent is filed as a request
 *      the person approves in the DemiPass app; the command waits for that tap (up to 15 min; --no-wait returns the
 *      approval id to pass back with --approval).
 *   3. Registers the service's MCP server in the MCP config (default ~/.mcp.json; one entry per service, idempotent,
 *      a .bak copy before any change). The entry reuses this machine's DemiPass session from the `demipass` entry
 *      (or DEMIPASS_TOKEN), copied file-to-file, never printed. Every pane started afterwards has the tools; a running
 *      pane picks them up with /mcp (reconnect).
 *   4. Service tokens are not minted here: the service's MCP server mints its own (aud svc:<slug>), in memory, on first
 *      use, and re-mints on expiry. A token therefore never sits in a config file.
 *
 * Also exported for the demipass MCP tool `demipass_onboard_service`.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { services } = require('./services.js');

const API = (process.env.DEMIPASS_URL || 'https://api.dustforge.com').replace(/\/$/, '');
const DEFAULT_MCP_CONFIG = path.join(os.homedir(), '.mcp.json');
const SLUG_RE = /^[a-z][a-z0-9-]{1,30}$/;

// This machine's DemiPass session: DEMIPASS_TOKEN, else the `demipass` entry of the MCP config, else the SDK login.
function sessionToken(mcpConfig = DEFAULT_MCP_CONFIG) {
  if (process.env.DEMIPASS_TOKEN) return process.env.DEMIPASS_TOKEN.trim();
  try { const c = JSON.parse(fs.readFileSync(mcpConfig, 'utf8')); const t = c.mcpServers && c.mcpServers.demipass && c.mcpServers.demipass.env && c.mcpServers.demipass.env.DEMIPASS_TOKEN; if (t) return t; } catch (_) {}
  try { const c = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.config', 'demipass', 'credentials.json'), 'utf8')); if (c && c.token) return c.token; } catch (_) {}
  return '';
}

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(15000) });
  const d = await r.json().catch(() => null);
  if (!r.ok) throw Object.assign(new Error(`${url}: HTTP ${r.status} ${(d && d.error) || ''}`.trim()), { status: r.status });
  return d;
}

// "<package>#<bin>" → the local file to run. Only packages resolvable on this machine (this checkout counts as
// `demipass`); never installs anything.
function resolveMcpServer(spec) {
  const m = /^((?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)#([a-z0-9][a-z0-9._-]*)$/.exec(String(spec || ''));
  if (!m) return null;
  const [, pkg, bin] = m;
  let dir = null;
  try { const own = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')); if (own.name === pkg) dir = __dirname; } catch (_) {}
  if (!dir) { try { dir = path.dirname(require.resolve(pkg + '/package.json')); } catch (_) { return { error: `${pkg} is not installed here (npm i ${pkg})` }; } }
  const pj = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const rel = pj.bin && (typeof pj.bin === 'string' ? (bin === pj.name ? pj.bin : null) : pj.bin[bin]);
  if (!rel) return { error: `${pkg} has no bin "${bin}"` };
  const file = path.resolve(dir, rel);
  if (!fs.existsSync(file)) return { error: `${file} is missing` };
  return { file };
}

// Adds (or confirms) the MCP server entry for a service. The session token is copied from the demipass entry (or the
// env) into the new entry's env without passing through any output.
function registerMcp({ slug, file, mcpConfig = DEFAULT_MCP_CONFIG, token }) {
  let cfg = { mcpServers: {} };
  const exists = fs.existsSync(mcpConfig);
  if (exists) cfg = JSON.parse(fs.readFileSync(mcpConfig, 'utf8'));
  cfg.mcpServers = cfg.mcpServers || {};
  // Already attached under any name (the same file): nothing to do. Conduit's tools, for one, live in the demipass server.
  for (const [name, e] of Object.entries(cfg.mcpServers)) {
    if (e && Array.isArray(e.args) && e.args.some(a => path.resolve(String(a)) === file)) return { changed: false, name };
  }
  const env = { DEMIPASS_URL: API };
  if (token) env.DEMIPASS_TOKEN = token;
  cfg.mcpServers[slug] = { command: process.execPath, args: [file], env };
  if (exists) fs.copyFileSync(mcpConfig, mcpConfig + '.bak');
  const tmp = mcpConfig + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, mcpConfig);
  return { changed: true, name: slug };
}

async function onboardService({ service, capDd, approvalId, wait = true, waitMs = 15 * 60 * 1000, mcpConfig = DEFAULT_MCP_CONFIG, register = true, log = () => {} } = {}) {
  const slug = String(service || '').toLowerCase();
  if (!SLUG_RE.test(slug)) return { ok: false, error: 'service: a registered service slug (demipass-onboard --list)' };
  let t;
  try { t = await getJson(`${API}/api/services/${slug}`); }
  catch (e) { return { ok: false, error: e.status === 404 ? `no service "${slug}" (demipass-onboard --list)` : e.message }; }
  const token = sessionToken(mcpConfig);
  if (!token) return { ok: false, error: 'no DemiPass session on this machine: sign in first (demipass_login, or set DEMIPASS_TOKEN)' };
  const dp = services({ token, baseUrl: API });

  // One submission/call must fit the daily consent: default to 5 of the dearest action, at least 300 DD.
  const dearest = Math.max(0, ...(t.actions || []).filter(a => a.open).map(a => a.max_price_dd || a.price_dd || 0));
  const cap = capDd || Math.max(300, dearest * 5);
  let c = await dp.ensureConsent({ service: slug, dailyCapDd: cap, approvalId });
  if (c.pending && wait) {
    log(`Approve "let a wallet pay ${slug}" (${cap} DD/day) in the DemiPass app — waiting (approval ${c.pending.approval_id})…`);
    const id = c.pending.approval_id, until = Date.now() + waitMs;
    while (c.pending && Date.now() < until) {
      await new Promise(ok => setTimeout(ok, 5000));
      try { c = await dp.ensureConsent({ service: slug, dailyCapDd: cap, approvalId: id }); }
      catch (e) { if (e.status === 410 || e.status === 403) return { ok: false, error: `approval ${id}: ${e.message}` }; throw e; }
    }
  }
  if (c.pending) return { ok: false, status: 'approval_pending', service: slug, approval_id: c.pending.approval_id, daily_cap_dd: cap,
    next: `Approve it in the DemiPass app, then: demipass-onboard ${slug} --cap ${cap} --approval ${c.pending.approval_id}` };
  const low = dearest && c.consent.daily_cap_dd < dearest;

  let mcp = { attached: false, reason: 'the service names no MCP server yet (its owner sets mcp_server)' };
  if (t.mcp_server && register) {
    const r = resolveMcpServer(t.mcp_server);
    if (!r || r.error) mcp = { attached: false, reason: r ? r.error : `bad mcp_server "${t.mcp_server}"` };
    else { const g = registerMcp({ slug, file: r.file, mcpConfig, token }); mcp = { attached: true, config: mcpConfig, entry: g.name, changed: g.changed }; }
  }
  return { ok: true, service: slug, name: t.name, endpoint: t.endpoint || null,
    consent: { id: c.consent.id, daily_cap_dd: c.consent.daily_cap_dd, existing: Boolean(c.existing) }, mcp,
    ...(low ? { warning: `the daily consent (${c.consent.daily_cap_dd} DD) is below one ${slug} call (${dearest} DD); re-run with --cap` } : {}),
    next: mcp.attached ? (mcp.changed ? 'New panes have the tools. In a running pane: /mcp → reconnect.' : 'Already attached; nothing to restart.') : 'Consent is in place.' };
}

async function listServices() {
  const d = await getJson(`${API}/api/services`);
  return d.tenants.map(t => ({ service: t.slug, name: t.name, endpoint: t.endpoint || null, mcp_server: t.mcp_server || null,
    prices: Object.fromEntries((t.actions || []).filter(a => a.open).map(a => [a.action, a.price_dd])) }));
}

module.exports = { onboardService, listServices, resolveMcpServer, registerMcp };

if (require.main === module) {
  const a = process.argv.slice(2);
  const opt = (n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };
  (async () => {
    if (a[0] === '--list' || !a[0]) { console.log(JSON.stringify(await listServices(), null, 2)); return; }
    const r = await onboardService({ service: a[0], capDd: opt('--cap') ? Number(opt('--cap')) : undefined, approvalId: opt('--approval') ? Number(opt('--approval')) : undefined,
      wait: !a.includes('--no-wait'), mcpConfig: opt('--mcp-config') || DEFAULT_MCP_CONFIG, log: m => console.error(m) });
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : (r.status === 'approval_pending' ? 3 : 1));
  })().catch(e => { console.error('demipass-onboard:', e.message); process.exit(1); });
}
